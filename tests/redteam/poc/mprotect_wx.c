// mprotect_wx — allocate writable page, then promote to executable.
// Classic post-corruption "make my stack writable + executable"
// step many exploits use after a buffer overflow.
//
// xhelix expects: seccomp denies if installed; planner sees
// SignalRWXMemory.
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }

    if (mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect W->X REFUSED");
        munmap(p, 4096);
        return 0;
    }
    printf("mprotect W->X allowed at %p (monitor mode)\n", p);
    munmap(p, 4096);
    return 0;
}
