VERSION ?= 0.0.2
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w \
	-X github.com/xhelix/xhelix/pkg/version.Version=$(VERSION) \
	-X github.com/xhelix/xhelix/pkg/version.Commit=$(COMMIT)

BIN := xhelix
CTL := xhelixctl
VFY := xhelix-verify
DIST := dist

.PHONY: all build test vet clean tidy deb rpm static-check race docs-pdf ebpf vmlinux

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

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/xhelix
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(CTL) ./cmd/xhelixctl
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(VFY) ./cmd/xhelix-verify

race:
	go test -race -count=1 ./...

static-check: build
	@file ./$(BIN) | grep -q "statically linked" \
	  && echo "static binary OK" \
	  || (echo "FAIL: $(BIN) is not statically linked"; exit 1)
	@file ./$(VFY) | grep -q "statically linked" \
	  && echo "static verify binary OK" \
	  || (echo "FAIL: $(VFY) is not statically linked"; exit 1)

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN) $(CTL) $(VFY)
	rm -rf $(DIST)

deb: build
	mkdir -p packaging/deb/usr/local/bin
	cp $(BIN) $(CTL) packaging/deb/usr/local/bin/
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
