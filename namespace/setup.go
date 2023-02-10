package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

var (
	debug     bool
	namespace string
	remove    bool
)

const defaultNamespace = "rd1"

func main() {
	flag.BoolVar(&debug, "debug", false, "enable debug flag")
	flag.StringVar(&namespace, "namespace", defaultNamespace, "name of the namespace to create")
	flag.BoolVar(&remove, "remove", false, "removes a given namespace")
	flag.Parse()

	if remove {
		if err := netns.DeleteNamed(namespace); err != nil {
			logAndExit(err)
		}
		logAndExit(fmt.Sprintf("removed namespace %v", namespace))
	}

	rdNs, err := configureNamespace(namespace)
	if err != nil {
		log.Fatal(err)
	}
	rdNs.Close()

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

func logAndExit(args ...interface{}){
	logrus.Info(args)
	os.Exit(0)
}

