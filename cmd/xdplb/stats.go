package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"time"

	"github.com/bxffour/xdp-l4lb/internal/stats"
	"github.com/cilium/ebpf"
	"github.com/urfave/cli/v2"
)

var statsCommand = cli.Command{
	Name: "stats",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Usage:   "print extra information",
			Aliases: []string{"v"},
		},
		&cli.StringFlag{
			Name:        "pinpath",
			DefaultText: "/sys/fs/bpf/lb",
			Usage:       "path to pin ebpf maps",
			Aliases:     []string{"p"},
			Value:       "/sys/fs/bpf/lb",
		},
	},
	Action: func(ctx *cli.Context) error {
		pinPath := ctx.String("pinpath")
		mapPath := path.Join(pinPath, statsMap)

		log.Printf("Loading pinned map at %s\n\n", mapPath)
		statsMap, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})

		if err != nil {
			return fmt.Errorf("error loading pinned map at %s: %w", mapPath, err)
		}

		defer statsMap.Close()

		info, err := statsMap.Info()
		if err != nil {
			return fmt.Errorf("error getting map info: %w", err)
		}

		ctrlC := make(chan os.Signal, 1)
		signal.Notify(ctrlC, os.Interrupt)

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		id, ok := info.ID()
		if !ok {
			log.Println("map ID field not available")
		}

		verbose := ctx.Bool("verbose")

		fmt.Println("Collecting stats from BPF map")

		if verbose {
			fmt.Printf(" - BPF map (bpf_map_type: %d) id: %d name: %s ", info.Type, id, info.Name)
			fmt.Printf("key_size: %d value_size: %d max entries: %d\n\n", info.KeySize, info.ValueSize, info.MaxEntries)
		}

		for {
			var (
				recv stats.StatsRecord
				prev stats.StatsRecord
			)

			if err := recv.CollectStats(statsMap); err != nil {
				return fmt.Errorf("error collecting stats: %w", err)
			}

			select {
			case <-ticker.C:
				copy(prev.Record[:], recv.Record[:])

				if err := recv.CollectStats(statsMap); err != nil {
					return fmt.Errorf("error collecting stats: %w", err)
				}

				stats.PrintStats(prev, recv)

			case <-ctrlC:
				log.Println("cleaning up resources...")
				return nil
			}
		}
	},
}
