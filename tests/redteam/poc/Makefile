# PoC binaries — exploit primitives xhelix should detect.
# Build:  make             (all PoCs)
#         make clean
#
# Run individually:  sudo -u www-data ./mmap_rwx
# Or via runner:     sudo bash ../run_attack_suite.sh
#
# Each PoC is single-source C, compiled with no protections so the
# primitive runs cleanly enough for xhelix to observe.

CC ?= gcc
# Disable PIE, stack canary, fortify — we WANT exploit primitives
# to surface to the kernel, not be stopped at libc.
CFLAGS  ?= -O0 -g -Wall -fno-stack-protector -no-pie -z execstack -U_FORTIFY_SOURCE
LDFLAGS ?=

# Memory-primitive PoCs
MEMORY := mmap_rwx mprotect_wx memfd_exec ptrace_attach \
          process_vm_readv_poc bpf_probe userfaultfd_poc

# Container-escape PoCs
ESCAPE := unshare_ns mount_attempt setns_attempt kexec_attempt module_load

# Buffer overflow / ASLR-bypass PoCs
BOF := stack_bof heap_bof format_string uaf_simple double_free

# Persistence / forbidden-write PoCs
PERSIST := write_cron write_authorized_keys write_ld_so_preload

# Network / exfil PoCs
NETWORK := connect_forbidden dns_known_bad

ALL := $(MEMORY) $(ESCAPE) $(BOF) $(PERSIST) $(NETWORK)

.PHONY: all clean memory escape bof persist network list

all: $(ALL)

memory:  $(MEMORY)
escape:  $(ESCAPE)
bof:     $(BOF)
persist: $(PERSIST)
network: $(NETWORK)

list:
	@echo "Memory primitives:   $(MEMORY)"
	@echo "Container escapes:   $(ESCAPE)"
	@echo "Buffer overflows:    $(BOF)"
	@echo "Persistence:         $(PERSIST)"
	@echo "Network / exfil:     $(NETWORK)"

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(ALL)
