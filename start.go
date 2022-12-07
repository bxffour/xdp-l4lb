package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/bxffour/xdp-l4lb/app"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/urfave/cli/v2"
)

var pinPath = "/sys/fs/bpf/lb/"
var statsMap = "xdp_stats_map"

var startCommand = cli.Command{
	Name: "start",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "dev",
			Required: true,
			Usage:    "<ifname> of interface to attach program to",
		},
		&cli.StringFlag{
			Name:        "config",
			DefaultText: "./hosts.yml",
			Usage:       "path to hosts.yml configuration file",
			Aliases:     []string{"c"},
			Value:       "./hosts.yml",
		},
		&cli.StringFlag{
			Name:        "section",
			Usage:       "program to load into the kernel (xdp.pass|xdp.abort|xdp.drop|xdp.print)",
			Aliases:     []string{"sec"},
			DefaultText: "xdp.print",
			Value:       "xdp.print",
		},
	},

	Before: func(ctx *cli.Context) error {
		if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create bpffs subpath at: %+v", pinPath)
		}
		return nil
	},

	Action: func(ctx *cli.Context) error {
		lb := &app.LoadBalancer{}

		ifaceName := ctx.String("dev")
		configPath := ctx.String("config")

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}

		if err := lb.BalancerFromInterface(iface); err != nil {
			return err
		}

		if err := lb.Config.ReadYaml(configPath); err != nil {
			return err
		}

		var objs bpfObjects
		if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: pinPath,
			},
		}); err != nil {
			return fmt.Errorf("failed to load bof objects: %w", err)
		}
		defer objs.Close()

		if err := lb.WriteToMap(objs.LbMetadata); err != nil {
			return fmt.Errorf("failed to write to lb_metadata map: %w", err)
		}

		if err := lb.WriteBackends(objs.BackendMap); err != nil {
			return fmt.Errorf("failed to write to backend map: %w", err)
		}

		section := ctx.String("section")
		prog := string2Sec(section, objs)

		log.Printf("attaching progsec %s to interface %d\n", section, lb.Index)
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: lb.Index,
			Flags:     link.XDPDriverMode,
		})

		if err != nil {
			return fmt.Errorf("link.AttachXDP: %w", err)
		}

		defer l.Close()

		log.Printf("Attached XDP program to iface %q (index %d)", ifaceName, iface.Index)
		log.Printf("Press CTRL-C to exit the program")

		ctrlC := make(chan os.Signal, 1)
		signal.Notify(ctrlC, os.Interrupt, syscall.SIGTERM)

		<-ctrlC
		return nil
	},
}

func string2Sec(sec string, objs bpfObjects) *ebpf.Program {
	switch sec {
	case "xdp.compare":
		return objs.XdpCompare
	case "xdp.pass":
		return objs.XdpPass
	case "xdp.drop":
		return objs.XdpDrop
	case "xdp.abort":
		return objs.XdpAbort
	case "xdp.loadbalancer":
		return objs.XdpLoadbalancer
	default:
		log.Fatal("invalid input")
	}

	return nil
}
