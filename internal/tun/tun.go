package tun

import (
	"log"
	"os/exec"

	"github.com/songgao/water"
)

type TunDevice struct {
	Interface *water.Interface
}

func CreateTun() (*TunDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	log.Printf("TUN interface created: %s\n", iface.Name())

	return &TunDevice{Interface: iface}, nil
}

// Platform-specific: configure IP address (Linux example)
func (t *TunDevice) Configure(address string, cidr string) error {
	cmd := exec.Command("ip", "addr", "add", address+"/"+cidr, "dev", t.Interface.Name())
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("ip", "link", "set", "dev", t.Interface.Name(), "up")
	return cmd.Run()
}
