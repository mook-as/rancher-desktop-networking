package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"time"

	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
)

var (
	debug      bool
	childPath  string
	unshareArg string
)

const (
	vsockHandshakePort = 6669
	vsockDialPort      = 6655
	SeedPhrase         = "github.com/rancher-sandbox/rancher-desktop-networking"
	pipePath = "/run/netns/rd-pipe"
)


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

func main() {
	flag.BoolVar(&debug, "debug", false, "enable debug flag")
	flag.StringVar(&childPath, "child-path", "", "the path to the child sub process that will run in a new namespace")
	flag.StringVar(&unshareArg, "unshare-arg", "", "the arg for unshare program")
	flag.Parse()

	if childPath == "" {
		logrus.Fatal("path to the child sub process must be provided")
	}

	if unshareArg == "" {
		logrus.Fatal("unshare program arg must be provided")
	}

	logrus.Info("Starting handhsake...")

	done := make(chan struct{})
	go listenForHandshake(done)
	<-done

	// figure out a better way to do this
	time.Sleep(time.Second * 5)

	conn, err := vsock.Dial(vsock.CIDHost, vsockDialPort)
	if err != nil {
		logrus.Fatalf("cannot connect to host: %v", err)
	}
	logrus.Debugf("dialed host %v:%d: %+v", vsock.CIDHost, vsockDialPort, conn)

	if err = os.Remove(pipePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		logrus.Fatalf("failed to delete existing pipe: %v", err)
	}
	if err = os.MkdirAll(path.Dir(pipePath), 0o755); err != nil {
		logrus.Fatalf("failed to create pipe directory %s: %v", path.Dir(pipePath), err)
	}
	if err = syscall.Mkfifo(pipePath, 0600); err != nil {
		logrus.Fatalf("failed to create fifo: %v", err)
	}
	pipe, err := os.OpenFile(pipePath, os.O_RDWR | os.O_CREATE, 0o600 | os.ModeNamedPipe)
	if err != nil {
		logrus.Fatalf("could not open named pipe")
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error {
		err := Pipe(pipe, conn)
		if err != nil {
			return fmt.Errorf("failed to pipe connection: %w", err)
		}
		return nil
	})

	// setup network namespace
	_, err = configureNamespace("rd1")
	if err != nil {
		logrus.Fatal(err)
	}

	// exec /usr/bin/unshare --net=/run/netns/rd1 --pid --mount-proc --fork --propagation slave  "${0}"
	unshareCmd := exec.Command("/usr/bin/nsenter", "-n/run/netns/rd1", "-F",  "/usr/bin/unshare", "--pid", "--mount-proc", "--fork", "--propagation", "slave", "/usr/bin/nohup", unshareArg)
	unshareCmd.Stdin = os.Stdin
	unshareCmd.Stdout = os.Stdout
	unshareCmd.Stderr = os.Stderr
	if err := unshareCmd.Start(); err != nil {
		logrus.Fatalf("could not start the unshare process: %v", err)
	}

	// /run/wsl-init.pid
	unsharePID := strconv.Itoa(unshareCmd.Process.Pid)

	err = os.WriteFile("/run/wsl-init.pid", []byte(unsharePID), 0644)
	if err != nil{
		logrus.Fatal(err)
	}
	logrus.Infof("unshare pid is: %v", unsharePID)
	logrus.Infof("unshare arg is: %s", unshareArg)

	// start the child process
	// the child process will run in the new namespace the reason behind this subprocess
	// is to avoid swithcing back and forth between namespaces,
	// this is due to the limitaion in the golang's runtime
	// all the sub process could potentiall start in the original
	// namespace
	subProcess := exec.Command("/usr/local/bin/vm-switch", "-debug")
	logFile, err := os.Create("/mnt/c/Users/Mark/AppData/Local/rancher-desktop/logs/vm-switch.log")
	if err != nil {
		logrus.Errorf("failed to create log file for vm-switch: %v", err)
	} else {
		subProcess.Stdout = logFile
		subProcess.Stderr = logFile
	}
	if err := subProcess.Start(); err != nil {
		logrus.Fatalf("could not start the child process: %v", err)
	}
	logFile.Close()

	logrus.Infof("successfully started the child process vm-switch running with a PID: %v", subProcess.Process.Pid)

	errGroup.Go(func() error { 
		if err := subProcess.Wait(); err != nil {
			return fmt.Errorf("vm-switch exited with error: %w", err)
		}
		return nil
	})

	if err = errGroup.Wait(); err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("handshake process done")
}

func listenForHandshake(done chan<- struct{}) {
	l, err := vsock.Listen(vsock.CIDAny, vsockHandshakePort)
	if err != nil {
		logrus.Fatalf("listenForHandshake listen failed: %v", err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		go func(conn net.Conn) {
			defer conn.Close()
			if err != nil {
				logrus.Errorf("listenForHandshake connection accept: %v", err)
				return
			}
			_, err = conn.Write([]byte(SeedPhrase))
			if err != nil {
				logrus.Errorf("listenForHandshake writing CIDHost: %v\n", err)
				return
			}
			logrus.Info("successful handshake with host switch")
			done <- struct{}{}
		}(conn)
	}

}

func configureNamespace(ns string) (netns.NsHandle, error) {
	// intentionally ignoring this error
	_ = netns.DeleteNamed(ns)

	rdNs, err := netns.NewNamed(ns)
	if err != nil {
		return netns.None(), errors.Wrap(err, "creating new namespace failed")
	}

	logrus.Infof("created a new namespace %v %v", ns, rdNs.String())
	return rdNs, nil
}
