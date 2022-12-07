package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./xdp/lb_kern.c

func main() {
	app := cli.NewApp()
	app.Name = "xdplb"
	app.Commands = []*cli.Command{
		&startCommand,
		&statsCommand,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
