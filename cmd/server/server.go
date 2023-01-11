package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func pingServer(ctx context.Context, addr string) (net.Addr, error) {
	s, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		go func() {
			<-ctx.Done()
			_ = s.Close()
		}()

		buf := make([]byte, 1024)

		for {
			_, client, err := s.ReadFrom(buf)
			if err != nil {
				return
			}

			log.Printf("[%s] connected to the server", client)

			_, err = s.WriteTo([]byte("pong\n"), client)
			if err != nil {
				log.Printf("[%s] write: %v", client, err)
				return
			}

		}
	}()

	return s.LocalAddr(), nil
}

var (
	address = flag.String("a", "0.0.0.0:7000", "address to run the server on")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	server, err := pingServer(ctx, *address)
	if err != nil {
		log.Fatal(err)
	}
	defer cancel()

	log.Printf("server listening on %s", server)

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

	<-exitChan
	log.Println("bye")
}
