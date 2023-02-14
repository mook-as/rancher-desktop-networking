LDFLAGS = -ldflags '-s -w'

.PHONY: build
build: host-switch vm-switch namespace-setup handshake

.PHONY: host-switch
host-switch:
			GOOS=windows go build $(LDFLAGS) -o bin/host-switch.exe host/switch.go

.PHONY: vm-switch
vm-switch:
			GOOS=linux CGO_ENABLED=0 go build $(LDFLAGS) -o bin/vm-switch vm/switch.go

.PHONY: namespace-setup
namespace-setup:
			GOOS=linux CGO_ENABLED=0 go build $(LDFLAGS) -o bin/namespace-setup namespace/setup.go

.PHONY: handshake
handshake:
			GOOS=linux CGO_ENABLED=0 go build $(LDFLAGS) -o bin/handshake handshake/run.go

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor