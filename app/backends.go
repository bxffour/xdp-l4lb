package app

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

const BACKEND_SIZE_BYTES = 10

type Backend struct {
	IP  net.IP
	Mac net.HardwareAddr
}

func (b *Backend) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(BACKEND_SIZE_BYTES)

	ip := b.IP.To4()
	if ip == nil {
		return nil, errInvalidIp
	}

	if err := binary.Write(buf, binary.BigEndian, &ip); err != nil {
		return nil, err
	}

	if len(b.Mac) != 6 {
		return nil, errInvalidMac
	}

	if err := binary.Write(buf, binary.BigEndian, &b.Mac); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil

}

func (lb *LoadBalancer) parseBackends() ([]Backend, error) {
	var backends []Backend

	for _, bb := range lb.Config.Backends {
		var b Backend

		socket := strings.Split(bb, ":")
		ipStr := socket[0]

		ip, err := parseIP(ipStr)
		if err != nil {
			return nil, err
		}

		b.IP = ip

		macStr, err := lb.Arp.Search(ipStr)
		if err != nil {
			continue
		}

		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, err
		}

		b.Mac = mac

		backends = append(backends, b)
	}

	return backends, nil
}

func parseIP(ip string) (net.IP, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return nil, errInvalidIp
	}

	ipAddr = ipAddr.To4()
	if ipAddr == nil {
		return nil, errInvalidIp
	}

	return ipAddr, nil
}

func (lb *LoadBalancer) WriteBackends(m *ebpf.Map) error {
	backends, err := lb.parseBackends()
	if err != nil {
		return err
	}

	for i, backend := range backends {
		key := uint32(i)

		if err := m.Put(&key, &backend); err != nil {
			return err
		}
	}

	return nil
}
