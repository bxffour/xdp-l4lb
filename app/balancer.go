package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"github.com/cilium/ebpf"
)

const (
	LB_SIZE_BYTES = 14
)

type LoadBalancer struct {
	Config Config
	IP     net.IP
	Mac    net.HardwareAddr
	Index  int
	Arp    *Arp
}

var (
	errInvalidIp     = errors.New("invalid ipv4 address")
	errInvalidMac    = errors.New("invalid Mac address")
	errInvalidIndex  = errors.New("invalid Index number")
	errInterfaceDown = errors.New("err interface down")
	errLoopback      = errors.New("err interface is loopback")
)

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
func (lb *LoadBalancer) BalancerFromInterface(iface *net.Interface) error {
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

// WriteToMap writes the load balancer's addresses into the
// LbMetadata map.
func (lb *LoadBalancer) WriteToMap(lbMap *ebpf.Map) error {
	var key uint32 = 0

	if err := lbMap.Put(&key, lb); err != nil {
		return err
	}

	return nil
}
