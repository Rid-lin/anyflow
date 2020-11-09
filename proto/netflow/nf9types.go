package netflow

type Nf9type struct {
	Type        string
	Stringify   func(b []byte) string
	Length      uint16
	Description string
}

var Nf9FieldMap = map[uint16]Nf9type{
	1:   {Type: "IN_BYTES", Stringify: BytesToNumber},
	2:   {Type: "IN_PKTS", Stringify: BytesToNumber},
	3:   {Type: "FLOWS", Stringify: BytesToNumber},
	4:   {Type: "PROTOCOL", Stringify: BytesToNumber},
	5:   {Type: "SRC_TOS", Stringify: BytesToNumber},
	6:   {Type: "TCP_FLAGS", Stringify: BytesToNumber},
	7:   {Type: "L4_SRC_PORT", Stringify: BytesToNumber},
	8:   {Type: "IPV4_SRC_ADDR", Stringify: BytesToIpv4},
	9:   {Type: "SRC_MASK", Stringify: BytesToNumber},
	10:  {Type: "INPUT_SNMP", Stringify: BytesToNumber},
	11:  {Type: "L4_DST_PORT", Stringify: BytesToNumber},
	12:  {Type: "IPV4_DST_ADDR", Stringify: BytesToIpv4},
	13:  {Type: "DST_MASK", Stringify: BytesToNumber},
	14:  {Type: "OUTPUT_SNMP", Stringify: BytesToNumber},
	15:  {Type: "IPV4_NEXT_HOP", Stringify: BytesToIpv4},
	16:  {Type: "SRC_AS", Stringify: BytesToNumber},
	17:  {Type: "DST_AS", Stringify: BytesToNumber},
	18:  {Type: "BGP_IPV4_NEXT_HOP", Stringify: BytesToIpv4},
	19:  {Type: "MUL_DST_PKTS", Stringify: BytesToNumber},
	20:  {Type: "MUL_DST_BYTES", Stringify: BytesToNumber},
	21:  {Type: "LAST_SWITCHED", Stringify: BytesToNumber},
	22:  {Type: "FIRST_SWITCHED", Stringify: BytesToNumber},
	23:  {Type: "OUT_BYTES", Stringify: BytesToNumber},
	24:  {Type: "OUT_PKTS", Stringify: BytesToNumber},
	25:  {Type: "MIN_PKT_LNGTH", Stringify: BytesToNumber},
	26:  {Type: "MAX_PKT_LNGTH", Stringify: BytesToNumber},
	27:  {Type: "IPV6_SRC_ADDR", Stringify: BytesToIpv6},
	28:  {Type: "IPV6_DST_ADDR", Stringify: BytesToIpv6},
	29:  {Type: "IPV6_SRC_MASK", Stringify: BytesToIpv6},
	30:  {Type: "IPV6_DST_MASK", Stringify: BytesToIpv6},
	31:  {Type: "IPV6_FLOW_LABEL", Stringify: BytesToNumber},
	32:  {Type: "ICMP_TYPE", Stringify: BytesToNumber},
	33:  {Type: "MUL_IGMP_TYPE", Stringify: BytesToNumber},
	34:  {Type: "SAMPLING_INTERVAL", Stringify: BytesToNumber},
	35:  {Type: "SAMPLING_ALGORITHM", Stringify: BytesToNumber},
	36:  {Type: "FLOW_ACTIVE_TIMEOUT", Stringify: BytesToNumber},
	37:  {Type: "FLOW_INACTIVE_TIMEOUT", Stringify: BytesToNumber},
	38:  {Type: "ENGINE_TYPE", Stringify: BytesToNumber},
	39:  {Type: "ENGINE_ID", Stringify: BytesToNumber},
	40:  {Type: "TOTAL_BYTES_EXP", Stringify: BytesToNumber},
	41:  {Type: "TOTAL_PKTS_EXP", Stringify: BytesToNumber},
	42:  {Type: "TOTAL_FLOWS_EXP", Stringify: BytesToNumber},
	44:  {Type: "IPV4_SRC_PREFIX", Stringify: BytesToIpv4},
	45:  {Type: "IPV4_DST_PREFIX", Stringify: BytesToIpv4},
	46:  {Type: "MPLS_TOP_LABEL_TYPE", Stringify: BytesToNumber},
	47:  {Type: "MPLS_TOP_LABEL_IP_ADDR", Stringify: BytesToIpv4},
	48:  {Type: "FLOW_SAMPLER_ID", Stringify: BytesToNumber},
	49:  {Type: "FLOW_SAMPLER_MODE", Stringify: BytesToNumber},
	50:  {Type: "FLOW_SAMPLER_RANDOM_INTERVAL", Stringify: BytesToNumber},
	52:  {Type: "MIN_TTL", Stringify: BytesToNumber},
	53:  {Type: "MAX_TTL", Stringify: BytesToNumber},
	54:  {Type: "IPV4_IDENT", Stringify: BytesToIpv4},
	55:  {Type: "DST_TOS", Stringify: BytesToNumber},
	56:  {Type: "IN_SRC_MAC", Stringify: BytesToMac},
	57:  {Type: "OUT_DST_MAC", Stringify: BytesToMac},
	58:  {Type: "SRC_VLAN", Stringify: BytesToNumber},
	59:  {Type: "DST_VLAN", Stringify: BytesToNumber},
	60:  {Type: "IP_PROTOCOL_VERSION", Stringify: BytesToNumber},
	61:  {Type: "DIRECTION", Stringify: BytesToNumber},
	62:  {Type: "IPV6_NEXT_HOP", Stringify: BytesToIpv4},
	63:  {Type: "BPG_IPV6_NEXT_HOP", Stringify: BytesToIpv6},
	64:  {Type: "IPV6_OPTION_HEADERS", Stringify: BytesToNumber},
	70:  {Type: "MPLS_LABEL_1", Stringify: BytesToNumber},
	71:  {Type: "MPLS_LABEL_2", Stringify: BytesToNumber},
	72:  {Type: "MPLS_LABEL_3", Stringify: BytesToNumber},
	73:  {Type: "MPLS_LABEL_4", Stringify: BytesToNumber},
	74:  {Type: "MPLS_LABEL_5", Stringify: BytesToNumber},
	75:  {Type: "MPLS_LABEL_6", Stringify: BytesToNumber},
	76:  {Type: "MPLS_LABEL_7", Stringify: BytesToNumber},
	77:  {Type: "MPLS_LABEL_8", Stringify: BytesToNumber},
	78:  {Type: "MPLS_LABEL_9", Stringify: BytesToNumber},
	79:  {Type: "MPLS_LABEL_10", Stringify: BytesToNumber},
	80:  {Type: "IN_DST_MAC", Stringify: BytesToMac},
	81:  {Type: "OUT_SRC_MAC", Stringify: BytesToMac},
	82:  {Type: "IF_NAME", Stringify: BytesToString},
	83:  {Type: "IF_DESC", Stringify: BytesToString},
	84:  {Type: "SAMPLER_NAME", Stringify: BytesToNumber},
	85:  {Type: "IN_PERMANENT_BYTES", Stringify: BytesToNumber},
	86:  {Type: "IN_PERMANENT_PKTS", Stringify: BytesToNumber},
	88:  {Type: "FRAGMENT_OFFSET", Stringify: BytesToNumber},
	89:  {Type: "FORWARDING_STATUS", Stringify: BytesToNumber},
	90:  {Type: "MPLS_PAL_RD", Stringify: BytesToNumber},
	91:  {Type: "MPLS_PREFIX_LEN", Stringify: BytesToNumber},
	92:  {Type: "SRC_TRAFFIC_INDEX", Stringify: BytesToNumber},
	93:  {Type: "DST_TRAFFIC_INDEX", Stringify: BytesToNumber},
	102: {Type: "layer2packetSectionOffset", Stringify: BytesToNumber},
	103: {Type: "layer2packetSectionSize", Stringify: BytesToNumber},
	104: {Type: "layer2packetSectionData", Stringify: BytesToNumber},
	128: {Type: "BGP_ADJ_NEXT_AS", Stringify: BytesToNumber},
	129: {Type: "BGP_ADJ_PREV_AS", Stringify: BytesToNumber},
	148: {Type: "CONN_ID", Stringify: BytesToNumber},
	152: {Type: "FLOW_CREATE_TIME_MSEC", Stringify: BytesToNumber},
	153: {Type: "FLOW_END_TIME_MSEC", Stringify: BytesToNumber},
	231: {Type: "FWD_FLOW_DELTA_BYTES", Stringify: BytesToNumber},
	232: {Type: "REV_FLOW_DELTA_BYTES", Stringify: BytesToNumber},
	323: {Type: "EVENT_TIME_MSEC", Stringify: BytesToNumber},
	225: {Type: "XLATE_SRC_ADDR_IPV4", Stringify: BytesToIpv4},
	226: {Type: "XLATE_DST_ADDR_IPV4", Stringify: BytesToIpv4},
	227: {Type: "XLATE_SRC_PORT", Stringify: BytesToNumber},
	228: {Type: "XLATE_DST_PORT", Stringify: BytesToNumber},
	281: {Type: "XLATE_SRC_ADDR_IPV6", Stringify: BytesToIpv6},
	282: {Type: "XLATE_DST_ADDR_IPV6", Stringify: BytesToIpv6},
	233: {Type: "FW_EVENT", Stringify: BytesToNumber},
	230: {Type: "NAT_EVENT", Stringify: BytesToNumber},
	234: {Type: "INGRESS_VRFID", Stringify: BytesToNumber},
	235: {Type: "EGRESS_VRFID", Stringify: BytesToNumber},
	361: {Type: "XLATE_PORT_BLOCK_START", Stringify: BytesToNumber},
	362: {Type: "XLATE_PORT_BLOCK_END", Stringify: BytesToNumber},
	363: {Type: "XLATE_PORT_BLOCK_STEP", Stringify: BytesToNumber},
	364: {Type: "XLATE_PORT_BLOCK_SIZE", Stringify: BytesToNumber},
}

type Netflow struct {
	Version   uint16
	Count     uint16
	SysUptime uint32
	UnixSecs  uint32
	Sequence  uint32
	SourceId  uint32
	FlowSet   []FlowSet
}
type FlowSet struct {
	Id       uint16
	Length   uint16
	Template []Template
	Data     []Record
	Padding  []byte
}
type Record struct {
	Values []Value
}
type Value struct {
	Value       []byte
	Type        uint16
	Length      uint16
	Description string
}
type Template struct {
	Id           uint16
	FieldCount   uint16
	Fields       []Field
	ScopeLength  uint16
	OptionLength uint16
}
type Field struct {
	Type   uint16
	Length uint16
}

var TemplateTable = make(map[string]map[uint16]*Template)
