package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/linuxkit/virtsock/pkg/vsock"
)

var (
	tapIface string
	debug    bool
)

const (
	defaultTapDevice   = "eth1"
	defaultMacAddr     = "5a:94:ef:e4:0c:ee"
	defaultMTU         = 4000
	SeedPhrase         = "github.com/rancher-sandbox/rancher-desktop-networking"
	vsockHandshakePort = 6669
	vsockDialPort      = 6655
)

func main() {
	flag.BoolVar(&debug, "debug", false, "enable debug flag")
	flag.StringVar(&tapIface, "tap-interface", defaultTapDevice, "tap interface name")
	flag.Parse()

	go listenForHandshake()
	// equivalent to: `ip link show`
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("vmSwitch getting link devices failed: %v", err)
	}

	for _, link := range links {
		if link.Attrs().Name == defaultTapDevice {
			log.Fatalf("%s interface already exist, exiting now...", defaultTapDevice)
		}
	}

	for {
		if err := run(); err != nil {
			logrus.Error(err)
		}
		time.Sleep(time.Second)
	}
}

func run() error {
	conn, err := vsock.Dial(vsock.CIDHost, vsockDialPort)
	if err != nil {
		return errors.Wrap(err, "cannot connect to host")
	}
	defer conn.Close()

	// figure out if this is necessary
	req, err := http.NewRequest("POST", "/connect", nil)
	if err != nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}

	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: tapIface,
		},
	})
	if err != nil {
		return errors.Wrapf(err, "cannot create %v tap device", tapIface)
	}
	defer tap.Close()
	if err := linkUp(tapIface, defaultMacAddr); err != nil {
		return errors.Wrapf(err, "cannot set mac address [%s] for %s tap device", defaultMacAddr, tapIface)
	}

	errCh := make(chan error, 1)
	go tx(conn, tap, errCh, defaultMTU)
	go rx(conn, tap, errCh, defaultMTU)
	go func() {
		if err := dhcp(tapIface); err != nil {
			errCh <- errors.Wrap(err, "dhcp error")
		}
	}()

	return <-errCh
}

func linkUp(iface string, mac string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	if mac == "" {
		return netlink.LinkSetUp(link)
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetHardwareAddr(link, hw); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func dhcp(iface string) error {
	if _, err := exec.LookPath("udhcpc"); err == nil { // busybox dhcp client
		cmd := exec.Command("udhcpc", "-f", "-q", "-i", iface, "-v")
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		return cmd.Run()
	}
	cmd := exec.Command("dhclient", "-4", "-d", "-v", iface)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func listenForHandshake() {
	l, err := vsock.Listen(vsock.CIDAny, vsockHandshakePort)
	if err != nil {
		logrus.Fatalf("listenForHandshake listen failed: %v", err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Errorf("listenForHandshake connection accept: %v", err)
			continue
		}
		_, err = conn.Write([]byte(SeedPhrase))
		if err != nil {
			logrus.Errorf("listenForHandshake writing CIDHost: %v\n", err)
		}
		conn.Close()
		logrus.Info("successful handshake with host switch")
	}

}

func rx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	logrus.Info("waiting for packets...")
	var frame ethernet.Frame
	for {
		frame.Resize(mtu)
		n, err := tap.Read([]byte(frame))
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read packet from tap")
			return
		}
		frame = frame[:n]

		if debug {
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			logrus.Info(packet.String())
		}

		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, uint16(n))

		if _, err := conn.Write(size); err != nil {
			errCh <- errors.Wrap(err, "cannot write size to socket")
			return
		}
		if _, err := conn.Write(frame); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to socket")
			return
		}
	}
}

func tx(conn net.Conn, tap *water.Interface, errCh chan error, mtu int) {
	sizeBuf := make([]byte, 2)
	buf := make([]byte, defaultMTU+header.EthernetMinimumSize)

	for {
		n, err := io.ReadFull(conn, sizeBuf)
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read size from socket")
			return
		}
		if n != 2 {
			errCh <- fmt.Errorf("unexpected size %d", n)
			return
		}
		size := int(binary.LittleEndian.Uint16(sizeBuf[0:2]))

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			logrus.Info(packet.String())
		}

		if _, err := tap.Write(buf[:size]); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}
	}
}
