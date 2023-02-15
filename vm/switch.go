package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

/*
#cgo CFLAGS: -Wall
extern void nsenter();
void __attribute__((constructor)) init(void) {
	nsenter();
}
*/
import "C"

var (
	debug    bool
	tapIface string
)

const (
	defaultNameSpace = "rd1"
	defaultTapDevice = "eth0"
	defaultMacAddr   = "5a:94:ef:e4:0c:ee"
	defaultMTU       = 4000
	pipePath =  "/run/netns/rd-pipe"
)

type syncer interface {
	Sync() error
}

func main() {
	signal.Ignore(syscall.SIGHUP)

	flag.BoolVar(&debug, "debug", true, "enable debug flag")
	flag.StringVar(&tapIface, "tap-interface", defaultTapDevice, "tap interface name")
	flag.Parse()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	connFile, err := os.OpenFile(pipePath, os.O_RDWR, 0o600 | os.ModeNamedPipe)
	if err != nil {
		logrus.Fatalf("could not open named pipe")
	}
	defer connFile.Close()

	logrus.Infof("Got connection: %v", connFile)

	// this should never happend
	if err := checkForExsitingIf(defaultTapDevice); err != nil {
		logrus.Fatal(err)
	}

	for {
		if err := run(connFile); err != nil {
			logrus.Error(err)
		}
		time.Sleep(time.Second)
	}

}

func run(connFile *os.File) error {
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

	logrus.Debugf("Created tap device %s: %v", tapIface, tap)
	defer logrus.Debug("Closing tap device")

	if err := linkUp(tapIface, defaultMacAddr); err != nil {
		return errors.Wrapf(err, "cannot set mac address [%s] for %s tap device", defaultMacAddr, tapIface)
	}
	if err := loopbackUp(); err != nil {
		return errors.Wrap(err, "failed enable loop back")
	}

	logrus.Debugf("Setup complete for tap interface %s(%s) + loopback", tapIface, defaultMacAddr)

	errCh := make(chan error, 1)
	go tx(connFile, tap, errCh, defaultMTU)
	go rx(connFile, tap, errCh, defaultMTU)
	go func() {
		if err := dhcp(tapIface); err != nil {
			errCh <- errors.Wrap(err, "dhcp error")
		}
	}()

	return <-errCh
}

func loopbackUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}

	return netlink.LinkSetUp(lo)
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

	logrus.Debugf("successful link setup %+v\n", link)
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

func rx(conn io.Writer, tap *water.Interface, errCh chan error, mtu int) {
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

		if s, ok := conn.(syncer); ok {
			if err := s.Sync(); err != nil {
				logrus.Errorf("failed to sync vm->host: %v", err)
			}
		}

		if debug {
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			logrus.Infof("wrote packet (vm -> host %d): %s", size, packet.String())
		}
	}
}

func tx(conn io.Reader, tap *water.Interface, errCh chan error, mtu int) {
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

		if cap(buf) < size {
			buf = make([]byte, size)
		}

		n, err = io.ReadFull(conn, buf[:size])
		if err != nil {
			errCh <- errors.Wrap(err, "cannot read payload from socket")
			return
		}
		if n == 0 || n != size {
			errCh <- fmt.Errorf("unexpected size %d != %d", n, size)
			return
		}

		if _, err := tap.Write(buf[:size]); err != nil {
			errCh <- errors.Wrap(err, "cannot write packet to tap")
			return
		}

		if debug {
			packet := gopacket.NewPacket(buf[:size], layers.LayerTypeEthernet, gopacket.Default)
			logrus.Infof("Read packet (host -> vm %d): %s", size, packet.String())
		}
	}
}

func checkForExsitingIf(ifName string) error {
	// equivalent to: `ip link show`
	links, err := netlink.LinkList()
	if err != nil {
		return errors.Wrapf(err, "getting link devices failed")
	}

	for _, link := range links {
		if link.Attrs().Name == ifName {
			return errors.Errorf("%s interface already exist, exiting now...", ifName)
		}
	}
	return nil
}
