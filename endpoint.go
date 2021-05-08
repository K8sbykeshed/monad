package monad

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Format specifies the format to represent the endpoint
type Format string

const (
	dummyFmt Format = ""
	// IPTables points to a iptables representation of an endpoint
	IPTables Format = "iptables"

	unSupported string = "not supported"
)

// Endpoint is an abstraction of a network entity that is managed in the
// rule-based packet processing pipeline such as iptables.
type Endpoint interface {
	// Contains returns true if the target endpoint is fully containned by
	// the current endpoint
	Contains(Endpoint) bool
	// String returns the string representation of the endpoint with respect
	// to the target format
	String(Format) (string, error)
}

type dummyEndpoint struct{}

func (d *dummyEndpoint) Contains(ep Endpoint) bool {
	return false
}

func (d *dummyEndpoint) String(Format) (string, error) {
	return "", fmt.Errorf(unSupported)
}

// IPEndpoint represents an IP endpoint
// The information for an IP endpoint is not strictly L3, it could also store
// L4 information such as port.
type IPEndpoint struct {
	// Addr is the address of the endpoint
	Addr net.IP
	// CIDR is effectively a range of contiguous IP addresses
	CIDR *net.IPNet
	// Ports is a range of contiguous ports
	Ports *[2]uint64
	// Iface is the interface of the endpoint
	Iface *string
}

// NewIPEndpoint builds an IP endpoint
func NewIPEndpoint(addr, iface, ports *string) (Endpoint, error) {
	ep := &IPEndpoint{Iface: iface}
	if addr != nil {
		ip, cidr, err := net.ParseCIDR(*addr)
		if err != nil {
			newAddr := *addr
			ip = net.ParseIP(newAddr)
		}
		if len(ip) == 0 {
			return nil, fmt.Errorf("cannot parse address '%s'", *addr)
		}
		ep.Addr, ep.CIDR = ip, cidr
	}
	if ports != nil {
		ports, err := parsePortRange(*ports)
		if err != nil {
			return nil, err
		}
		ep.Ports = ports
	}
	return ep, nil
}

func portValid(port uint64) bool {
	return port < 65535
}

func parsePortRange(ports string) (*[2]uint64, error) {
	portStrs := strings.Split(ports, ",")
	switch len(portStrs) {
	case 1:
		port, err := strconv.ParseUint(portStrs[0], 0, 0)
		if err != nil || !portValid(port) {
			break
		}
		return &[2]uint64{port, port}, nil
	case 2:
		port0, err := strconv.ParseUint(portStrs[0], 0, 0)
		if err != nil || !portValid(port0) {
			break
		}
		port1, err := strconv.ParseUint(portStrs[1], 0, 0)
		if err != nil || !portValid(port1) {
			break
		}
		if port1 < port0 {
			port0, port1 = port1, port0
		}
		return &[2]uint64{port0, port1}, nil
	}
	return nil, fmt.Errorf("port (range) '%s' is invalid", ports)
}

func (self *IPEndpoint) Contains(ep Endpoint) bool {
	target, ok := ep.(*IPEndpoint)
	if !ok {
		return false
	}

	if self.Iface != nil {
		if target.Iface == nil || (*self.Iface) != (*target.Iface) {
			return false
		}
	}
	if self.CIDR != nil {
		if !self.CIDR.Contains(target.Addr) {
			return false
		}
		if target.CIDR != nil {
			size1, _ := self.CIDR.Mask.Size()
			size2, _ := target.CIDR.Mask.Size()
			if size1 < size2 {
				return false
			}
		}
	}
	if self.Ports != nil {
		if target.Ports == nil {
			return false
		}
		if self.Ports[0] > target.Ports[0] || self.Ports[1] < target.Ports[1] {
			return false
		}
	}

	return true
}

func (ip *IPEndpoint) String(format Format) (string, error) {
	switch format {
	case IPTables:
		return ip.marshalIPEndpointIPTables()
	default:
		return "", fmt.Errorf(unSupported)
	}
}

// TODO: parse the IP endpoint in iptables format
func (ip *IPEndpoint) marshalIPEndpointIPTables() (string, error) {
	return "", nil
}
