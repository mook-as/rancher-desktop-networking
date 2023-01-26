package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/dustin/go-humanize"
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/vmsock"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var exitCode int

const(
	defaultHostSwitchMTU = 1500
	gatewayIP   = "192.168.127.1"
	sshGuestPort = 2222
	sshHostPort = "192.168.127.2:22"
	vsockPort = 6655
)

func main(){
	ctx, cancel := context.WithCancel(context.Background())
	groupErrs, ctx := errgroup.WithContext(ctx)
	defer os.Exit(exitCode)

		// catch user issued signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

		// TODO: DEBUG only
		logrus.SetLevel(logrus.DebugLevel)


		config := types.Configuration{
			Debug:             true,
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
		if err != nil{
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

func run(ctx context.Context, g *errgroup.Group, config *types.Configuration, ln net.Listener) error{
	vn, err := virtualnetwork.New(config)
	if err != nil{
		return err
	}
	logrus.Info("waiting for clients...")
	httpServe(ctx, g, ln, withProfiler(vn))

	vnLn, err := vn.Listen("tcp", fmt.Sprintf("%s:80", gatewayIP))
	if err != nil{
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/services/forwarder/all", vn.Mux())
	mux.Handle("/services/forwarder/expose", vn.Mux())
	mux.Handle("/services/forwarder/unexpose", vn.Mux())
	httpServe(ctx, g, vnLn, mux)

	g.Go(func() error {
		debugLog:
			for {
				select {
				case <-time.After(5 * time.Second):
					fmt.Printf("%v sent to the VM, %v received from the VM\n", humanize.Bytes(vn.BytesSent()), humanize.Bytes(vn.BytesReceived()))
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
	//TODO: DEBUG only
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	/////////////////
	return mux
}

func vsockListener(vsockPort uint32)(net.Listener, error){
	// make a PR to change the hadcoded handshake port
	vmGUID, err := vmsock.GetVMGUID()
	if err != nil{
		return nil, errors.Wrap(err, "trying to find WSL GUID faild")
	}
	logrus.Info("successfull handshake")

	return vmsock.Listen(vmGUID, vsockPort)
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