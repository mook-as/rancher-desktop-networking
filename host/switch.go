package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/pkg/errors"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/vmsock"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows/registry"
)

var (
	exitCode int
	debug    bool
)

const (
	defaultHostSwitchMTU = 1500
	gatewayIP            = "192.168.127.1"
	sshGuestPort         = 2222
	sshHostPort          = "192.168.127.2:22"
	vsockPort            = 6655
	vsockHandshakePort   = 6669
	SeedPhrase           = "github.com/rancher-sandbox/rancher-desktop-networking"
	timeoutSeconds       = 10 * 60
)

func main() {
	flag.BoolVar(&debug, "debug", false, "enable debug flag")
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	groupErrs, ctx := errgroup.WithContext(ctx)
	defer os.Exit(exitCode)

	// catch user issued signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	config := types.Configuration{
		Debug:             debug,
		CaptureFile:       "capture.pcap",
		MTU:               defaultHostSwitchMTU,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         gatewayIP,
		GatewayMacAddress: "5a:94:ef:e4:0c:dd",
		DHCPStaticLeases: map[string]string{
			"192.168.127.2": "5a:94:ef:e4:0c:ee",
		},
		DNS: []types.Zone{
			{
				Name: "rancher-desktop.internal.",
				Records: []types.Record{
					{
						Name: "gateway",
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.254"),
					},
				},
			},
			{
				Name: "docker.internal.",
				Records: []types.Record{
					{
						Name: "gateway",
						IP:   net.ParseIP(gatewayIP),
					},
					{
						Name: "host",
						IP:   net.ParseIP("192.168.127.254"),
					},
				},
			},
		},
		DNSSearchDomains: searchDomains(),
		Forwards: map[string]string{
			fmt.Sprintf("127.0.0.1:%d", sshGuestPort): sshHostPort,
		},
		NAT: map[string]string{
			"192.168.127.254": "127.0.0.1",
		},
		GatewayVirtualIPs: []string{"192.168.127.254"},
		VpnKitUUIDMacAddresses: map[string]string{
			"c3d68012-0208-11ea-9fd7-f2189899ab08": "5a:94:ef:e4:0c:ee",
		},
	}

	ln, err := vsockListener(vsockPort)
	if err != nil {
		logrus.Fatalf("creating vsock listener for hostSwitch failed: %v", err)
	}
	groupErrs.Go(func() error {
		return run(ctx, groupErrs, &config, ln)
	})

	// Wait for something to happen
	groupErrs.Go(func() error {
		select {
		// Catch signals so exits are graceful and defers can run
		case <-sigChan:
			cancel()
			return errors.New("signal caught")
		case <-ctx.Done():
			return nil
		}
	})
	// Wait for all of the go funcs to finish up
	if err := groupErrs.Wait(); err != nil {
		logrus.Error(err)
		exitCode = 1
	}
}

type loggingListener struct {
	l net.Listener
}

func (l *loggingListener) Accept() (net.Conn, error) {
	logrus.Debugf("vnet accept()")
	return l.l.Accept()
}

func (l *loggingListener) Addr() net.Addr {
	logrus.Debugf("vnet addr()")
	return l.l.Addr()
}

func (l *loggingListener) Close() error {
	logrus.Debugf("vnet close()")
	return l.l.Close()
}


// Pipe bidirectionally between two streams.
func Pipe(c1, c2 io.ReadWriteCloser) error {
	copy := func(reader io.Reader, writer io.Writer, info string) <-chan error {
		ch := make(chan error)
		go func() {
			for {
				n, err := io.Copy(writer, reader)
				if n > 0 || err != nil {
					logrus.Infof("copied %d bytes (%s): %v", n, info, err)
				}
				if err != nil {
					ch <- err
				}
			}
		}()
		return ch
	}

	ch1 := copy(c1, c2, "file->vsock")
	ch2 := copy(c2, c1, "vsock->file")
	select {
	case err := <-ch1:
		c1.Close()
		c2.Close()
		<-ch2
		if err != io.EOF {
			return err
		}
	case err := <-ch2:
		c1.Close()
		c2.Close()
		<-ch1
		if err != io.EOF {
			return err
		}
	}

	logrus.Infof("Finished copying!")
	return nil
}

func run(ctx context.Context, g *errgroup.Group, config *types.Configuration, ln net.Listener) error {
	vn, err := virtualnetwork.New(config)
	if err != nil {
		return err
	}
	logrus.Info("waiting for clients...")
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				logrus.Errorf("failed to accept pipe: %v", err)
			}
			err = vn.AcceptQemu(ctx, conn)
			if err != nil {
				logrus.Errorf("pipe closed: %v", err)
			} else {
				logrus.Infof("Accepted connection: ctx=%+v conn=%+v", ctx, conn)
			}
		}
	}()

	vnLn, err := vn.Listen("tcp", fmt.Sprintf("%s:80", gatewayIP))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, &loggingListener{vnLn}, mux)

	g.Go(func() error {
	debugLog:
		for {
			select {
			case <-time.After(5 * time.Second):
				logrus.Debugf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
			case <-ctx.Done():
				break debugLog
			}
		}
		return nil
	})

	return nil
}

func httpServe(ctx context.Context, g *errgroup.Group, ln net.Listener, mux http.Handler) {
	g.Go(func() error {
		<-ctx.Done()
		return ln.Close()
	})
	g.Go(func() error {
		s := &http.Server{
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		err := s.Serve(ln)
		if err != nil {
			if err != http.ErrServerClosed {
				return err
			}
			return err
		}
		return nil
	})
}

func withProfiler(vn *virtualnetwork.VirtualNetwork) http.Handler {
	mux := vn.Mux()
	if debug {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	}
	return mux
}

func searchDomains() []string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		f, err := os.Open("/etc/resolv.conf")
		if err != nil {
			logrus.Errorf("open file error: %v", err)
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		searchPrefix := "search "
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), searchPrefix) {
				searchDomains := strings.Split(strings.TrimPrefix(sc.Text(), searchPrefix), " ")
				logrus.Debugf("Using search domains: %v", searchDomains)
				return searchDomains
			}
		}
		if err := sc.Err(); err != nil {
			logrus.Errorf("scan file error: %v", err)
			return nil
		}
	}
	return nil
}

func vsockListener(vsockPort uint32) (net.Listener, error) {
	// make a PR to change the hadcoded handshake port
	vmGUID, err := GetVMGUID()
	if err != nil {
		return nil, errors.Wrap(err, "trying to find WSL GUID faild")
	}
	logrus.Info("successfull handshake")

	return vmsock.Listen(vmGUID, vsockPort)
}

// GetVMGUID retrieves the GUID for a correct hyper-v VM (most likely WSL).
// It performs a handshake with a running vsock-peer in the WSL distro
// to make sure we establish the AF_VSOCK connection with a right VM.
func GetVMGUID() (hvsock.GUID, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostComputeService\VolatileStore\ComputeSystem`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return hvsock.GUIDZero, fmt.Errorf("could not open registry key, is WSL VM running? %v", err)
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(0)
	if err != nil {
		return hvsock.GUIDZero, fmt.Errorf("machine IDs can not be read in registry: %v", err)
	}
	if len(names) == 0 {
		return hvsock.GUIDZero, errors.New("no running WSL VM found")
	}

	found := make(chan hvsock.GUID, len(names))
	done := make(chan bool, len(names))
	defer close(done)

	for _, name := range names {
		vmGUID, err := hvsock.GUIDFromString(name)
		if err != nil {
			logrus.Errorf("invalid VM name: [%s], err: %v", name, err)
			continue
		}
		go handshake(vmGUID, vsockHandshakePort, found, done)
	}
	return tryFindGUID(found)
}

// handshake attempts to perform a handshake by verifying the seed with a running
// af_vsock peer in WSL distro, it attempts once per second
func handshake(vmGUID hvsock.GUID, peerHandshakePort uint32, found chan<- hvsock.GUID, done <-chan bool) {
	svcPort, err := hvsock.GUIDFromString(winio.VsockServiceID(peerHandshakePort).String())
	if err != nil {
		logrus.Errorf("hostHandshake parsing svc port: %v", err)
	}
	addr := hvsock.Addr{
		VMID:      vmGUID,
		ServiceID: svcPort,
	}

	attempInterval := time.NewTicker(time.Second * 1)
	attempt := 1
	for {
		select {
		case <-done:
			logrus.Infof("attempt to handshake with [%s], goroutine is terminated", vmGUID.String())
			return
		case <-attempInterval.C:
			// Spawn a goroutine here to ensure we don't get stuck on a timeout
			go func() {
				conn, err := hvsock.Dial(addr)
				select {
				case <-done:
					// If we're already connected, no need to print more things.
					return
				default:
				}
				if err != nil {
					attempt++
					logrus.Debugf("handshake attempt[%v] to dial into VM [%s], looking for vsock-peer", attempt, vmGUID.String())
					return
				}
				seed, err := readSeed(conn)
				if err != nil {
					logrus.Errorf("hosthandshake attempt to read the seed: %v", err)
				}
				if err := conn.Close(); err != nil {
					logrus.Errorf("hosthandshake closing connection: %v", err)
				}
				if seed == SeedPhrase {
					logrus.Infof("successfully estabilished a handshake with a peer: %s", vmGUID.String())
					found <- vmGUID
					return
				}
				logrus.Infof("hosthandshake failed to match the seed phrase with a peer running in: %s", vmGUID.String())
			}()
		}
	}
}

// tryFindGuid waits on a found chanel to receive a GUID until
// deadline of 10s is reached
func tryFindGUID(found chan hvsock.GUID) (hvsock.GUID, error) {
	bailOut := time.After(time.Second * timeoutSeconds)
	for {
		select {
		case vmGUID := <-found:
			return vmGUID, nil
		case <-bailOut:
			return hvsock.GUIDZero, errors.New("could not find vsock-peer process on any hyper-v VM(s)")
		}
	}
}

func readSeed(conn net.Conn) (string, error) {
	seed := make([]byte, len(SeedPhrase))
	if _, err := io.ReadFull(conn, seed); err != nil {
		return "", err
	}
	return string(seed), nil
}
