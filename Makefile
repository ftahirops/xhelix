VERSION ?= 0.0.2
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w \
	-X github.com/xhelix/xhelix/pkg/version.Version=$(VERSION) \
	-X github.com/xhelix/xhelix/pkg/version.Commit=$(COMMIT)

BIN := xhelix
CTL := xhelixctl
VFY := xhelix-verify
HSH := xhelix-honeysh
SNK := xhelix-sinkhole
DNS := xhelix-dnspoison
WD  := xhelix-watchdog
DIST := dist

.PHONY: all build test vet clean tidy deb rpm static-check race docs-pdf ebpf vmlinux rules-lint

all: build

# Generate vmlinux.h from the running kernel's BTF.
# Re-run on the target host after kernel upgrades.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c \
	  > sensors/ebpf/progs/headers/vmlinux.h
	@echo "vmlinux.h: $$(wc -l < sensors/ebpf/progs/headers/vmlinux.h) lines"

# Compile the unified eBPF object. Requires clang and libbpf-dev.
ebpf:
	clang -O2 -g -Wall -target bpf \
	  -D__TARGET_ARCH_x86 \
	  -I sensors/ebpf/progs \
	  -c sensors/ebpf/progs/all.bpf.c \
	  -o sensors/ebpf/progs/xhelix-progs.o
	@file sensors/ebpf/progs/xhelix-progs.o

# Compile the Phase I BPF-LSM program. Separate object so kernels
# without BPF-LSM (or in dry-run / load-only mode) can use the main
# xhelix-progs.o without pulling in LSM bindings.
# Output: sensors/ebpf/progs/xhelix-lsm.o
# Deploy path: /usr/lib/xhelix/xhelix-lsm.o
ebpf-lsm:
	clang -O2 -g -Wall -target bpf \
	  -D__TARGET_ARCH_x86 \
	  -I sensors/ebpf/progs \
	  -c sensors/ebpf/progs/bpflsm.bpf.c \
	  -o sensors/ebpf/progs/xhelix-lsm.o
	@file sensors/ebpf/progs/xhelix-lsm.o

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/xhelix
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(CTL) ./cmd/xhelixctl
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(VFY) ./cmd/xhelix-verify
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(HSH) ./cmd/xhelix-honeysh
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(SNK) ./cmd/xhelix-sinkhole
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DNS) ./cmd/xhelix-dnspoison
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(WD)  ./cmd/xhelix-watchdog

race:
	go test -race -count=1 ./...

static-check: build
	@file ./$(BIN) | grep -q "statically linked" \
	  && echo "static binary OK" \
	  || (echo "FAIL: $(BIN) is not statically linked"; exit 1)
	@file ./$(VFY) | grep -q "statically linked" \
	  && echo "static verify binary OK" \
	  || (echo "FAIL: $(VFY) is not statically linked"; exit 1)
	@file ./$(HSH) | grep -q "statically linked" \
	  && echo "static honeysh binary OK" \
	  || (echo "FAIL: $(HSH) is not statically linked"; exit 1)
	@file ./$(SNK) | grep -q "statically linked" \
	  && echo "static sinkhole binary OK" \
	  || (echo "FAIL: $(SNK) is not statically linked"; exit 1)
	@file ./$(DNS) | grep -q "statically linked" \
	  && echo "static dnspoison binary OK" \
	  || (echo "FAIL: $(DNS) is not statically linked"; exit 1)

test:
	go test -race -count=1 ./...

# rules-lint compiles every shipped CEL rule. Catches bugs like
# `has(map[k])` that the engine accepts at parse time but rejects
# at compile time. Wired into deb so bad rules never ship.
rules-lint: build
	./$(CTL) rules lint ruleset/core
	./$(CTL) rules lint ruleset/dlcf || true   # dlcf has subdirs; tolerant

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN) $(CTL) $(VFY) $(HSH) $(SNK) $(DNS) $(WD)
	rm -rf $(DIST)

deb: build rules-lint
	mkdir -p packaging/deb/usr/local/bin
	cp $(BIN) $(CTL) $(VFY) packaging/deb/usr/local/bin/
	# Sync the live ruleset into the package so deployment never
	# drifts from what was lint-validated above. Wipe-and-replace
	# to clean out renamed/removed files.
	rm -rf packaging/deb/usr/share/xhelix/ruleset
	mkdir -p packaging/deb/usr/share/xhelix/ruleset
	cp -a ruleset/core packaging/deb/usr/share/xhelix/ruleset/
	cp -a ruleset/dlcf packaging/deb/usr/share/xhelix/ruleset/
	# Optional: include compiled eBPF programs if present.
	@if [ -f sensors/ebpf/progs/xhelix-progs.o ]; then \
	  mkdir -p packaging/deb/usr/lib/xhelix; \
	  cp sensors/ebpf/progs/xhelix-progs.o packaging/deb/usr/lib/xhelix/; \
	  echo "deb: bundled eBPF progs"; \
	else \
	  echo "deb: eBPF progs not built (run 'make ebpf' first to include)"; \
	fi
	mkdir -p $(DIST)
	dpkg-deb --build packaging/deb $(DIST)/xhelix_$(VERSION)_amd64.deb

rpm: build
	mkdir -p $(DIST)
	rpmbuild -bb \
	  --define "_topdir $(PWD)/.rpmbuild" \
	  --define "_rpmdir $(PWD)/$(DIST)" \
	  --define "_sourcedir $(PWD)" \
	  --define "_builddir $(PWD)/.rpmbuild/BUILD" \
	  --define "_specdir $(PWD)/packaging/rpm" \
	  --define "_srcrpmdir $(PWD)/$(DIST)" \
	  packaging/rpm/xhelix.spec || \
	  (echo "rpmbuild failed. Install with: sudo dnf install rpm-build"; exit 1)

docs-pdf:
	@which pandoc >/dev/null 2>&1 || (echo "pandoc required for PDF generation"; exit 1)
	@which wkhtmltopdf >/dev/null 2>&1 || (echo "wkhtmltopdf required for PDF generation"; exit 1)
	@echo "Generating comprehensive documentation PDF..."
	@sed '/github.com\/xhelix\/xhelix\/actions\/workflows/d' README.md > /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/INSTALL.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/ARCHITECTURE.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/USAGE.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/FEATURES.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/CONFIG.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/RULES.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat docs/SECURITY.md >> /tmp/xhelix-docs.md
	@echo -e "\n---\n\n" >> /tmp/xhelix-docs.md
	@cat AGENTS.md >> /tmp/xhelix-docs.md
	@cat CHANGELOG.md >> /tmp/xhelix-docs.md
	@sed 's/^!\[.*\](.*)$$//g' /tmp/xhelix-docs.md > /tmp/xhelix-docs-clean.md
	@pandoc /tmp/xhelix-docs-clean.md \
	  --pdf-engine=wkhtmltopdf \
	  --metadata title="xhelix Documentation" \
	  --metadata author="xhelix authors" \
	  --metadata date="$(shell date +%Y-%m-%d)" \
	  -V margin-top=2cm \
	  -V margin-bottom=2cm \
	  -V margin-left=2cm \
	  -V margin-right=2cm \
	  -o $(DIST)/xhelix-documentation.pdf
	@echo "PDF generated: $(DIST)/xhelix-documentation.pdf"
