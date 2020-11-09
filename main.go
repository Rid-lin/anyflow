package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"

	"github.com/Rid-lin/anyflow/proto/netflow"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Packet struct {
	Raw   []byte
	Saddr *net.UDPAddr
	Proto string
}

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
				fmt.Printf("Flow record:%d", i)
				for _, v := range r.Values {
					fmt.Printf(" %v:%v", v.GetType(), v.GetValue())
				}
				fmt.Printf("\n")
			}
		}
	}
}

func init() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	prometheus.MustRegister(packetsTotal)
}

func main() {
	httpListenAddress := ":8080"
	flowListenAddress := ":10001"

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
