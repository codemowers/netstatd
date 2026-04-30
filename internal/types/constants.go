package types

// Protocol constants
const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

const (
	ConnEventTCPState      = 1
	ConnEventListenSyscall = 2
	ConnEventTCPAccept     = 3
	ConnEventUDPSend       = 4
	ConnEventUDPRecv       = 5
)

// Protocol names - returns empty string for unknown protocols
var ProtocolNames = map[uint8]string{
	ProtocolTCP: "TCP",
	ProtocolUDP: "UDP",
}

// Address family constants
const (
	FamilyIPv4 = 2  // AF_INET
	FamilyIPv6 = 10 // AF_INET6
)

// Address family names
var FamilyNames = map[uint16]string{
	FamilyIPv4: "AF_INET",
	FamilyIPv6: "AF_INET6",
}

// TCP state constants (from Linux kernel)
const (
	TCPEstablished = 1
	TCPSynSent     = 2
	TCPSynRecv     = 3
	TCPFinWait1    = 4
	TCPFinWait2    = 5
	TCPTimeWait    = 6
	TCPClose       = 7
	TCPCloseWait   = 8
	TCPLastAck     = 9
	TCPListen      = 10
	TCPClosing     = 11
)

// TCP state names
var TCPStateNames = map[uint32]string{
	TCPEstablished: "ESTABLISHED",
	TCPSynSent:     "SYN_SENT",
	TCPSynRecv:     "SYN_RECV",
	TCPFinWait1:    "FIN_WAIT1",
	TCPFinWait2:    "FIN_WAIT2",
	TCPTimeWait:    "TIME_WAIT",
	TCPClose:       "CLOSE",
	TCPCloseWait:   "CLOSE_WAIT",
	TCPLastAck:     "LAST_ACK",
	TCPListen:      "LISTEN",
	TCPClosing:     "CLOSING",
}
