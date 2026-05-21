// memfd_exec — create an in-memory file, write a tiny ELF stub
// or shell-redirect script to it, exec the fd via fexecve / /proc/
// self/fd/N.  Disk-less staging — never touches the filesystem.
//
// xhelix expects: NeverLearnableMemory MemMemfdExec flag; the
// exec attempt path goes via /proc/self/fd/N which AppArmor +
// pkg/protectpolicy can fingerprint.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>

int main(void) {
    int fd = syscall(SYS_memfd_create, "stage", 0);
    if (fd < 0) { perror("memfd_create REFUSED"); return 0; }

    // Tiny shell script — gets execve'd as a #!-script
    const char *script = "#!/bin/sh\necho memfd_exec stage ran as $$\n";
    if (write(fd, script, strlen(script)) < 0) { perror("write"); return 1; }

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char *const argv[] = { path, NULL };
    char *const envp[] = { NULL };
    execve(path, argv, envp);
    perror("execve via memfd REFUSED");
    return 0;
}
