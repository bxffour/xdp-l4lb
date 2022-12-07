package app

import (
	"bytes"
	"encoding/binary"
	"net"
	"os/exec"
	"testing"
)

var (
	normal = "normal"
	down   = "ifdown"
)

func TestBalancerFromInterface(t *testing.T) {
	if err := interfaceSetup("setup"); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(ifCleanup)

	var tests = []struct {
		name   string
		ifName string
		expect error
	}{
		{name: "normal interface", ifName: normal, expect: nil},
		{name: "test interface down", ifName: down, expect: errInterfaceDown},
		{name: "test loopback interface", ifName: "lo", expect: errLoopback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, err := net.InterfaceByName(tt.ifName)
			if err != nil {
				t.Fatal(err)
			}

			lb := &LoadBalancer{}
			err = lb.BalancerFromInterface(iface)
			if tt.expect != nil && err == nil {
				t.Fatal("expected an error but got nil")
			}

			if err != tt.expect {
				t.Fatalf("expected: %s, got: %s", tt.expect.Error(), err.Error())
			}

		})
	}

}

func TestMarshalBinary(t *testing.T) {
	var tests = []struct {
		name   string
		input  *LoadBalancer
		expect error
	}{
		{
			name:   "no errors",
			input:  newMockLoadBalancer(t, "8.8.4.4", "00:00:5e:00:53:01", 5),
			expect: nil,
		},
		{
			name:   "test ipv6 address",
			input:  newMockLoadBalancer(t, "fc00:dead:cafe:1::1", "00:00:5e:00:53:01", 5),
			expect: errInvalidIp,
		},
		{
			name:   "test 0 index",
			input:  newMockLoadBalancer(t, "8.8.8.8", "00:00:5e:00:53:01", 0),
			expect: errInvalidIndex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.input.MarshalBinary()
			if tt.expect != nil && err == nil {
				t.Fatal("expected an error but got nil")
			}
			if err != tt.expect {
				t.Errorf("expected %s, got %s", tt.expect, err.Error())
			}

			if tt.expect == nil {
				if len(b) != LB_SIZE_BYTES {
					t.Fatalf("expected %d bytes, got %d bytes", LB_SIZE_BYTES, len(b))
				}

				buf := bytes.NewBuffer(b)

				var ip [4]byte
				if err := binary.Read(buf, binary.BigEndian, &ip); err != nil {
					t.Fatal(err)
				}

				ipnet := net.IPv4(ip[0], ip[1], ip[2], ip[3])
				if !tt.input.IP.Equal(ipnet) {
					t.Fatal("ip address mismatch")
				}

				var mac [6]byte
				if err := binary.Read(buf, binary.BigEndian, &mac); err != nil {
					t.Fatal(err)
				}

				for i, byte := range tt.input.Mac {
					if mac[i] != byte {
						t.Fatalf("expected: %+v, got: %+v", tt.input.Mac, mac)
					}
				}

				var idx uint32
				if err := binary.Read(buf, binary.BigEndian, &idx); err != nil {
					t.Fatalf("expected: %d, got: %d", tt.input.Index, idx)
				}
			}
		})
	}
}

func newMockLoadBalancer(t *testing.T, ip string, mac string, index int) *LoadBalancer {
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}

	ipAddr := net.ParseIP(ip)

	return &LoadBalancer{
		IP:    ipAddr,
		Mac:   macAddr,
		Index: index,
	}

}

func interfaceSetup(arg string) error {
	setupNormalInterface := exec.Command(
		"/home/sxntana/github_projects/xdp-l4lb/bin/utils/testenv/setup.sh",
		arg,
	)
	if setupNormalInterface.Err != nil {
		return setupNormalInterface.Err
	}

	if err := setupNormalInterface.Run(); err != nil {
		return err
	}

	return nil
}

func ifCleanup() {
	interfaceSetup("teardown")
}
