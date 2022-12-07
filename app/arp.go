package app

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"sync"
)

const (
	IPADDR  int = 0
	MACADDR int = 3
	// TODO:
	// Make loadbalancer capable of redirecting traffic
	// through other interfaces.
	IFNAME int = 5
)

type arpTable map[string]string

func readSysArp() (arpTable, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}

	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan()

	table := make(arpTable)

	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		ipAddr := fields[IPADDR]
		macAddr := fields[MACADDR]

		table[ipAddr] = macAddr
	}

	return table, nil
}

type Arp struct {
	mu    sync.RWMutex
	table arpTable
}

func (a *Arp) Refresh() (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	table, err := readSysArp()
	if err != nil {
		return err
	}

	a.table = table
	return nil
}

func (a *Arp) Search(ipaddr string) (mac string, err error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	mac, ok := a.table[ipaddr]

	if !ok {
		a.mu.RUnlock()
		a.Refresh()
		a.mu.RLock()

		mac, ok = a.table[ipaddr]
		if !ok {
			return "", errors.New("ip address has no entry in arp cache")
		}
	}

	return mac, nil
}
