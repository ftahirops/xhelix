// ptrace_attach — attach to another process, classic credential
// stealing / process injection primitive. xhelix never-learnable.
//
// Usage: ./ptrace_attach <target-pid>     (default 1 = init)
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>

int main(int argc, char **argv) {
    pid_t target = argc > 1 ? atoi(argv[1]) : 1;
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) {
        perror("ptrace ATTACH REFUSED");
        return 0;
    }
    printf("ptrace ATTACH allowed on pid %d (monitor mode)\n", target);
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
