// process_vm_readv — cross-process memory read primitive.
// Lets an attacker scrape another process's address space
// without ptrace (less audited). xhelix added this to
// NeverLearnable in P-PS.15.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t target = argc > 1 ? atoi(argv[1]) : getppid();
    char buf[64] = {0};
    struct iovec local  = { .iov_base = buf, .iov_len = sizeof(buf) };
    // Read at an arbitrary location; we don't care if data is valid,
    // we want the syscall to be observed.
    struct iovec remote = { .iov_base = (void *)0x400000, .iov_len = sizeof(buf) };

    ssize_t n = process_vm_readv(target, &local, 1, &remote, 1, 0);
    if (n < 0) { perror("process_vm_readv REFUSED"); return 0; }
    printf("process_vm_readv read %zd bytes from pid %d (monitor mode)\n", n, target);
    return 0;
}
