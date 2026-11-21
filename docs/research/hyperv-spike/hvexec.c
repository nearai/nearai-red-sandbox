/* Spike guest agent: connect to the Hyper-V host over hvsocket (AF_VSOCK,
 * hv_sock transport), report the guest, then run each command line the host
 * sends through /bin/sh and stream back its output and exit status. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/vm_sockets.h>

static void put(int fd, const char *s) { size_t n = strlen(s); while (n) { ssize_t w = write(fd, s, n); if (w <= 0) exit(3); s += w; n -= (size_t)w; } }

int main(int argc, char **argv) {
    unsigned port = argc > 1 ? (unsigned)atoi(argv[1]) : 5000;
    int fd = -1;
    for (int i = 0; i < 60 && fd < 0; i++) {
        fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        struct sockaddr_vm a = { .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = port };
        if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0) break;
        perror("hvexec: connect"); if (fd >= 0) close(fd); fd = -1; sleep(1);
    }
    if (fd < 0) return 2;
    struct utsname u; uname(&u);
    char line[4096];
    snprintf(line, sizeof line, "HELLO %s %s %s\n", u.sysname, u.release, u.machine);
    put(fd, line);
    FILE *in = fdopen(dup(fd), "r");
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\n")] = 0;
        if (!strcmp(line, "EXIT")) break;
        FILE *p = popen(line, "r");
        if (!p) { put(fd, "ERR popen\n"); continue; }
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof buf - 1, p)) > 0) { buf[n] = 0; put(fd, buf); }
        int st = pclose(p);
        snprintf(buf, sizeof buf, "\nRTS_EXIT %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : 128);
        put(fd, buf);
    }
    put(fd, "BYE\n");
    return 0;
}
