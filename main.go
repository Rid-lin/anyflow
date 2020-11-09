package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"

	"github.com/Rid-lin/anyflow/proto/netflow"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Packet struct {
	Raw   []byte
	Saddr *net.UDPAddr
	Proto string
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "List of strings"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type Config struct {
	SubNets             arrayFlags `yaml:"SubNets" toml:"subnets" env:"SUBNETS"`
	IgnorList           arrayFlags `yaml:"IgnorList" toml:"ignorlist" env:"IGNORLIST"`
	LogLevel            string     `yaml:"LogLevel" toml:"loglevel" env:"LOG_LEVEL"`
	ProcessingDirection string     `yaml:"ProcessingDirection" toml:"direct" env:"DIRECT" env-default:"both"`
	FlowAddr            string     `yaml:"FlowAddr" toml:"flowaddr" env:"FLOW_ADDR"`
	FlowPort            int        `yaml:"FlowPort" toml:"flowport" env:"FLOW_PORT" env-default:"2055"`
	NameFileToLog       string     `yaml:"FileToLog" toml:"log" env:"FLOW_LOG"`
	FlowPrometheusPort  int        `yaml:"FlowPrometheusPort" toml:"flowprometheusport" env:"FLOW__PROM_PORT" env-default:":8080"`
}

var (
	cfg                Config
	SubNets, IgnorList arrayFlags
	writer             *bufio.Writer
	FileToLog          *os.File
	err                error
)

func CheckError(err error) {
	if err != nil {
		log.Fatalf("Error:%v", err)
		os.Exit(0)
	}
}

func Parse(b []byte, addr *net.UDPAddr) (*Packet, error) {
	p := new(Packet)
	// parse for flow netflowcol
	switch b[1] {
	case 9:
		*p = Packet{Raw: b, Saddr: addr, Proto: "nf9"}
	default:
		return p, errors.New("No flow packet")
	}
	return p, nil
}

func receivePackets(c *net.UDPConn) {
	buf := make([]byte, 9000)

	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("Error:%v", err)
			continue
		}

		packetSourceIP := addr.IP.String()
		packetsTotal.WithLabelValues(packetSourceIP).Inc()
		log.Infof("Packet source:%v", packetSourceIP)

		p, err := Parse(buf[:n], addr)
		if err != nil {
			log.Errorf("Error parsing packet:%v", err)
			continue
		}

		switch p.Proto {
		case "nf9":
			nf, err := netflow.New(p.Raw, p.Saddr)
			if err != nil {
				log.Errorf("Error parsing netflow nf9 packet:%v", err)
				continue
			}

			if !nf.HasFlows() {
				log.Debug("No flows in nf9 packet")
				continue
			}

			records, err := nf.GetFlows()
			if err != nil {
				log.Errorf("Error getting flows from packet:%v", err)
				continue
			}

			log.Infof("Number of flow packet records:%v", len(records))

			for i, r := range records {
				fmt.Fprintf(writer, "Flow record:%d", i)
				for _, v := range r.Values {
					fmt.Fprintf(writer, " %v:%v", v.GetType(), v.GetValue())
				}
				fmt.Fprintf(writer, "\n")
			}
		}
	}
}

func init() {
	flag.StringVar(&cfg.FlowAddr, "addr", "", "NetFlow/IPFIX listening address")
	flag.IntVar(&cfg.FlowPort, "port", 2055, "NetFlow/IPFIX listening port")
	flag.IntVar(&cfg.FlowPrometheusPort, "hport", 8080, "Http (prometheus) listening port")
	flag.StringVar(&cfg.LogLevel, "loglevel", "info", "Log level")
	flag.Var(&cfg.SubNets, "subnet", "List of internal subnets")
	flag.Var(&cfg.IgnorList, "ignorlist", "List of ignored words/parameters per string")
	flag.StringVar(&cfg.ProcessingDirection, "direct", "both", "")
	flag.StringVar(&cfg.NameFileToLog, "log", "", "The file where logs will be written in the format of squid logs")
	flag.Parse()
	var config_source string
	if SubNets == nil && IgnorList == nil {
		// err := cleanenv.ReadConfig("anyflow.toml", &cfg)
		err := cleanenv.ReadConfig("/etc/anyflow/anyflow.toml", &cfg)
		if err != nil {
			log.Warningf("No .env file found: %v", err)
		}
		lvl, err2 := log.ParseLevel(cfg.LogLevel)
		if err2 != nil {
			log.Errorf("Error in determining the level of logs (%v). Installed by default = Info", cfg.LogLevel)
			lvl, _ = log.ParseLevel("info")
		}
		log.SetLevel(lvl)
		config_source = "ENV/CFG"
	} else {
		config_source = "CLI"
	}
	log.Debugf("Config read from %s: IgnorList=(%v), SubNets=(%v), FlowAddr=(%v), FlowPort=(%v), cfg.FlowPrometheusPort=(%v), LogLevel=(%v), ProcessingDirection=(%v)",
		config_source,
		cfg.IgnorList,
		cfg.SubNets,
		cfg.FlowAddr,
		cfg.FlowPort,
		cfg.FlowPrometheusPort,
		cfg.LogLevel,
		cfg.ProcessingDirection)

	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	// log.SetLevel(log.DebugLevel)

	prometheus.MustRegister(packetsTotal)
}

func main() {

	if cfg.NameFileToLog == "" {
		writer = bufio.NewWriter(os.Stdout)
		log.Debug("Output in os.Stdout")
	} else {
		FileToLog, err = os.OpenFile(cfg.NameFileToLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		// FileToLog, err = os.Create(cfg.NameFileToLog)
		if err != nil {
			log.Errorf("Error, the '%v' file could not be created (there are not enough premissions or it is busy with another program): %v", cfg.NameFileToLog, err)
			writer = bufio.NewWriter(os.Stdout)
			FileToLog.Close()
			log.Debug("The output will be done in os.Stdout because the log file could not be opened.")
		} else {
			defer FileToLog.Close()
			writer = bufio.NewWriter(FileToLog)
			log.Debugf("Output in file (%v)(%v)", cfg.NameFileToLog, FileToLog)
		}
	}

	httpListenAddress := fmt.Sprintf("%v:%v", cfg.FlowAddr, cfg.FlowPrometheusPort)
	flowListenAddress := fmt.Sprintf("%v:%v", cfg.FlowAddr, cfg.FlowPort)

	log.Infof("Flow listening on %s", flowListenAddress)
	ServerAddr, err := net.ResolveUDPAddr("udp", flowListenAddress)
	CheckError(err)

	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	CheckError(err)

	defer ServerConn.Close()

	go receivePackets(ServerConn)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`<html>
            <head><title>Anyflow Metrics Server</title></head>
            <body>
            <h1>Anyflow Metrics Server</h1>
            <p><a href="/metrics">Metrics</a></p>
            </body>
            </html>`)); err != nil {
			log.Errorf("Error parsing template HTML:%v", err)
		}
	})

	log.Infof("HTTP listening on %s", httpListenAddress)
	if err := http.ListenAndServe(httpListenAddress, nil); err != nil {
		panic(fmt.Errorf("Error starting HTTP server: %s", err))
	}
}
