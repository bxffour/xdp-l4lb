package stats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

type datarec struct {
	rxPackets uint64
	rxBytes   uint64
}

func (d *datarec) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	err := binary.Read(r, binary.LittleEndian, &d.rxPackets)
	if err != nil {
		return err
	}

	err = binary.Read(r, binary.LittleEndian, &d.rxBytes)
	if err != nil {
		return err
	}

	return nil
}

type record struct {
	timestamp time.Time
	total     datarec
}

type StatsRecord struct {
	Record [5]record
}

func (s *StatsRecord) CollectStats(sMap *ebpf.Map) error {
	var key uint32

	for key = 0; key < 5; key++ {
		if err := getMapVal(key, sMap, s /* Stats record */); err != nil {
			return err
		}
	}

	return nil
}

func getMapVal(key uint32, m *ebpf.Map, stat *StatsRecord) error {
	var (
		percpuVals []datarec
		summedVals datarec
	)

	stat.Record[key].timestamp = time.Now()

	err := m.Lookup(&key, &percpuVals)
	if err != nil {
		return err
	}

	for _, d := range percpuVals {
		summedVals.rxPackets += d.rxPackets
		summedVals.rxBytes += d.rxBytes
	}

	stat.Record[key].total.rxBytes = summedVals.rxBytes
	stat.Record[key].total.rxPackets = summedVals.rxPackets

	return nil
}

func Action2str(act uint) string {
	switch act {
	case 0:
		return "XDP_ABORT"
	case 1:
		return "XDP_DROP"
	case 2:
		return "XDP_PASS"
	case 3:
		return "XDP_TX\t"
	case 4:
		return "XDP_REDIRECT"
	default:
		log.Panic("invalid input")
	}

	return ""
}

func PrintStats(prev StatsRecord, recv StatsRecord) {
	var (
		bps float64
		pps float64
		sb  strings.Builder
	)

	for i := 0; i < 5; i++ {
		rec := recv.Record[i]
		prev := prev.Record[i]

		period := rec.timestamp.Sub(prev.timestamp).Seconds()

		pps = float64(rec.total.rxPackets-prev.total.rxPackets) / period

		bytes := float64(rec.total.rxBytes - prev.total.rxBytes)
		bps = (bytes * 8) / period / 1000000

		sb.WriteString(fmt.Sprintf("%s\t %d pkts (%10.0f pps) %11.0f Kbytes (%6.0f Mbits/s) period: %f\n",
			Action2str(uint(i)), rec.total.rxPackets, pps, float64(rec.total.rxBytes)/1000, bps, period))
	}

	fmt.Println(sb.String())
}
