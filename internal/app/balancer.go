package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"github.com/cilium/ebpf"
)

var (
	errInvalidIp     = errors.New("invalid ipv4 address")
	errInvalidMac    = errors.New("invalid Mac address")
	errInvalidIndex  = errors.New("invalid Index number")
	errInterfaceDown = errors.New("err interface down")
	errLoopback      = errors.New("err interface is loopback")
)

const (
	LB_SIZE_BYTES     = 14
	EGRESS_SIZE_BYTES = 14
)

type LoadBalancer struct {
	Config Config
	IP     net.IP
	Mac    net.HardwareAddr
	Index  int
	Arp    *Arp
}

type Egress struct {
	IP    net.IP
	Mac   net.HardwareAddr
	Index int
}

func (e *Egress) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	b.Grow(EGRESS_SIZE_BYTES)

	ip := e.IP.To4()
	if ip == nil {
		return nil, errInvalidIp
	}

	if err := binary.Write(b, binary.BigEndian, &ip); err != nil {
		return nil, err
	}

	if len(e.Mac) != 6 {
		return nil, errInvalidMac
	}

	if err := binary.Write(b, binary.BigEndian, &e.Mac); err != nil {
		return nil, err
	}

	if e.Index < 1 {
		return nil, errInvalidIndex
	}

	idx := uint32(e.Index)
	if err := binary.Write(b, binary.LittleEndian, &idx); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func NewEgress(ifName string) (*Egress, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}

	if iface.Flags&net.FlagUp == 0 {
		return nil, errInterfaceDown
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return nil, errLoopback
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	e := new(Egress)
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP.To4()
		case *net.IPAddr:
			ip = v.IP.To4()
		}

		if ip == nil {
			continue
		}

		if !ip.IsGlobalUnicast() || ip.IsLoopback() {
			continue
		}

		e.IP = ip
	}

	if e.IP == nil {
		return nil, errInvalidIp
	}

	e.Index = iface.Index
	e.Mac = iface.HardwareAddr

	return e, nil
}

func (lb *LoadBalancer) MarshalBinary() ([]byte, error) {
	b := new(bytes.Buffer)
	b.Grow(LB_SIZE_BYTES)

	ip := lb.IP.To4()
	if ip == nil {
		return nil, errInvalidIp
	}

	if err := binary.Write(b, binary.BigEndian, &ip); err != nil {
		return nil, err
	}

	if len(lb.Mac) != 6 {
		return nil, errInvalidMac
	}

	if err := binary.Write(b, binary.BigEndian, &lb.Mac); err != nil {
		return nil, err
	}

	if lb.Index < 1 {
		return nil, errInvalidIndex
	}

	idx := uint32(lb.Index)
	if err := binary.Write(b, binary.BigEndian, &idx); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// AddressByInterface retrieves the IP and Mac addresses of a given
// interface.
func balancerFromInterface(lb *LoadBalancer, iface *net.Interface) error {
	if iface.Flags&net.FlagUp == 0 {
		return errInterfaceDown
	}

	if iface.Flags&net.FlagLoopback != 0 {
		return errLoopback
	}

	lb.Index = iface.Index
	lb.Mac = iface.HardwareAddr

	arp := &Arp{
		table: make(arpTable),
	}

	if err := arp.Refresh(); err != nil {
		return err
	}

	lb.Arp = arp

	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP.To4()
		case *net.IPAddr:
			ip = v.IP.To4()
		}

		if ip == nil {
			continue
		}

		if !ip.IsGlobalUnicast() || ip.IsLoopback() {
			continue
		}

		lb.IP = ip
	}

	if lb.IP == nil {
		return errInvalidIp
	}
	return nil
}

func NewLoadBalancer(ifName string, config string, arp string) (*LoadBalancer, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}

	if arp != "" {
		arpPath = arp
	}

	lb := &LoadBalancer{}
	if err := balancerFromInterface(lb, iface); err != nil {
		return nil, err
	}

	if err := lb.Config.ReadYaml(config); err != nil {
		return nil, err
	}

	return lb, nil
}

// WriteToMap writes the load balancer's addresses into the
// LbMetadata map.
func (lb *LoadBalancer) WriteToMap(lbMap *ebpf.Map) error {
	var key uint32 = 0

	if err := lbMap.Put(&key, lb); err != nil {
		return err
	}

	return nil
}

func (e *Egress) WriteToMap(egressMap *ebpf.Map) error {
	var key uint32 = 0

	if err := egressMap.Put(&key, e); err != nil {
		return err
	}

	return nil
}
