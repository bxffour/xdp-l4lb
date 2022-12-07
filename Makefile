CC = clang


GO_DIR  = .
BPF_SRC = ./xdp
TESTENV = /home/sxntana/Documents/studies/xdp/xdp-tutorial/testenv/testenv.sh

TARGET         = xdplb
BPF_TARGET     = ${TARGET:=_kern}
BPF_C          = $(BPF_SRC)/${BPF_TARGET:=.c}
BPF_OBJ        = ${BPF_TARGET:=.o}
LIBBPF_HEADERS = libbpf/src
LIBBPF_OBJ     = libbpf/src/libbpf.a
BUILD_DIR_BPF  = bin/objs
BUILD_DIR_GO   = bin/go
DOCKER_BIN	   = testenv/app
GO_BIN         = $(BUILD_DIR_GO)/$(TARGET)
CONFIG		   = config.yml

CFLAGS = -target bpf \
			-g \
			-D __BPF_TRACING__ \
			-I $(LIBBPF_HEADERS) \
			-Wall \
			-Wno-unused-value \
			-Wno-pointer-sign \
			-Wno-compare-distinct-pointer-types \
			-Werror

.PHONY: all
all: audit generate $(TARGET)

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
generate: $(GO_DIR)/main.go
	go generate ./...

.PHONY: trace
trace:
	sudo cat /sys/kernel/tracing/trace_pipe

.PHONY: ping
ping:
	sudo $(TESTENV) ping -n test --legacy

SECTION ?= "xdp.compare"
.PHONY: attach
attach: generate $(TARGET)
	sudo ./$(GO_BIN) start --dev test -c $(CONFIG) --sec $(SECTION)

.PHONY:
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > xdp/libs/vmlinux.h

xdp_stats:
	sudo ./$(GO_BIN) stats 

$(TARGET): generate
	go build -o $(BUILD_DIR_GO)/$@ $(GO_DIR)/*.go
	
.PHONY: deploy
deploy: $(TARGET)
	cp $(BUILD_DIR_GO)/$^ $(DOCKER_BIN)
	 
$(BPF_OBJ): $(BPF_C) ./src/kspace/xdp_l4lb_kern.h ./src/kspace/xdp_l4lb_pkt.h ./src/kspace/xdp_l4lb_stats.h
	$(CC) -S $(CFLAGS) \
		-O2 -emit-llvm -c -o $(BUILD_DIR_BPF)/${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $(BUILD_DIR_BPF)/$@ $(BUILD_DIR_BPF)/${@:.o=.ll}

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