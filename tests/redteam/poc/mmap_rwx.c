// mmap_rwx — anonymous RWX mapping (classic shellcode-stage primitive).
//
// xhelix expects: seccomp denies if installed (Ring 1), eBPF
// observes (mprotect_wx_pattern), planner emits SignalRWXMemory
// (Tier-1, weight 95) → tier ≥ Suspended.
//
// In MONITOR mode the syscall succeeds; xhelix LOGS the attempt
// and the planner shadow-fires.
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    void *p = mmap(NULL, 4096,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap RWX REFUSED");
        return 0;        // refusal is itself a successful detection
    }
    printf("mmap RWX allowed at %p (monitor mode)\n", p);
    munmap(p, 4096);
    return 0;
}
