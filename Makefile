GO_DIR  = ./cmd
BPF_SRC = ./xdp
TESTENV = /home/sxntana/Documents/studies/xdp/xdp-tutorial/testenv/testenv.sh

LOADBAL        = xdplb
BACKEND		   = server
BUILD_DIR_GO   = ./bin/go
GO_BIN         = $(BUILD_DIR_GO)/$(TARGET)
CONFIG		   = config.yml

VAGRANT_DIR = ./testenv/vagrant
PING_SRC    = $(GO_DIR)/$(BACKEND)
LB_SRC	    = $(GO_DIR)/$(LOADBAL)
PING        = $(BUILD_DIR_GO)/$(BACKEND)
LB          = $(BUILD_DIR_GO)/$(LOADBAL)

.PHONY: all
all: audit $(LOADBAL) $(BACKEND)

#=====================================================================#
# AUDIT
#=====================================================================#

# audit: tidy dependencies and format, vet and test all code
.PHONY: audit
audit:
	@echo 'Tidying and verifying module dependencies...'
	go mod tidy
	go mod verify
	@echo 'Formatting code...'
	go fmt ./...
	@echo 'Vetting code ...'
	go vet ./...
	staticcheck ./...
	#@echo 'Running tests...'
	#go test -race -vet=off ./...

cleanup:
	sudo rm -rf /sys/fs/bpf/lb/*
#=====================================================================#
# BUILD
#=====================================================================#

.PHONY: generate
generate: $(LB_SRC)/main.go
	go generate ./...

$(LOADBAL): generate
	CGO_ENABLED=0 go build -o $(LB) $(LB_SRC)

$(BACKEND):
	CGO_ENABLED=0 go build -o $(PING) $(PING_SRC) 

.PHONY: trace
trace:
	sudo cat /sys/kernel/tracing/trace_pipe

.PHONY: ping
ping:
	sudo $(TESTENV) ping -n test --legacy

SECTION ?= "xdp.pass"
.PHONY: attach
attach: generate $(TARGET)
	sudo ./$(LB) start --dev test --egress test -c $(CONFIG) --sec $(SECTION)

.PHONY:
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > xdp/libs/vmlinux.h

xdp_stats:
	sudo ./$(LB) stats 
	
.PHONY: deploy
deploy: $(TARGET)
	cp $(LB) $(DOCKER_BIN)/lb
	 
#============================================================================#
# DEBUG
#============================================================================#

$(TARGET)_opt:
	go build -gcflags="all=-N -l" -o $(BUILD_DIR_GO)/$@ $(GO_DIR)/*.go

dlv-exec: $(TARGET)_opt
	sudo dlv-root exec $(BUILD_DIR_GO)/$< start -- --dev test --config $(CONFIG)

perf-record:
	sudo perf record -a \
		-e xdp:xdp_redirect_err \
		-e xdp:xdp_exception \
		-e xdp:xdp_bulk_tx \
		-e xdp:xdp_cpumap_enqueue
		
perf-script:
	sudo perf script
	
#============================================================================#
# TESTENV
#============================================================================#

xdp-interface:
	sudo $(TESTENV) setup -n test --legacy
	
backends:
	sudo $(TESTENV) setup -n be1 --legacy
	sudo $(TESTENV) setup -n be2 --legacy


#============================================================================#
# TESTENV
#============================================================================#

VAGRANT_DIR=./testenv/vagrant

vagrant_deploy: $(LOADBAL) $(BACKEND)
	cp $(LB) $(VAGRANT_DIR)/loadbalancer
	cp $(PING) $(VAGRANT_DIR)/backend