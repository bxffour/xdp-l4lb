package app

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Backends []string `yaml:"backends"`
	Pinpath  string   `yaml:"pinpath"`
}

func (cfg *Config) ReadYaml(filepath string) error {
	config, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(config, cfg); err != nil {
		return err
	}

	err = validateBackends(cfg.Backends)
	if err != nil {
		return err
	}

	return nil
}

func validateBackends(backends []string) error {
	for _, backend := range backends {
		addr := strings.Split(backend, ":")

		if net.ParseIP(addr[0]) == nil {
			return fmt.Errorf("err invalid addr: %s", addr[0])
		}
	}

	return nil
}
