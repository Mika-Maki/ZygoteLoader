// uid_filter.cpp —— 在目标 App 进程内按 HMA 的名单过滤"UID 可见性"
// 名单来源：HMA 服务写出的文件（每行一个 uid），路径由 main.cpp 传入。
//   getpriority(PRIO_USER, uid) 且 uid ∈ 名单          -> -EPERM
//   openat/openat2 路径含 /cgroup/.../uid_<N> 且 N ∈ 名单 -> -ENOENT
//   其余 syscall 一律放行
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 0x00000001
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
struct seccomp_notif {
    uint64_t id; uint32_t pid; uint32_t flags; struct seccomp_data data;
};
struct seccomp_notif_resp {
    uint64_t id; int64_t val; int32_t error; uint32_t flags;
};
#endif

#define MAX_HIDDEN 4096
static uint32_t g_hidden[MAX_HIDDEN];
static int g_hidden_count = 0;

static int uid_is_hidden(uint32_t uid) {
    for (int i = 0; i < g_hidden_count; i++) if (g_hidden[i] == uid) return 1;
    return 0;
}

static int path_hidden_uid(const char *path, uint32_t *out) {
    if (!path) return 0;
    const char *p = strstr(path, "uid_");
    if (!p) return 0;
    if (!strstr(path, "cgroup")) return 0;
    p += 4;
    if (*p < '0' || *p > '9') return 0;
    unsigned long v = strtoul(p, NULL, 10);
    if (v == 0 || v > 0xffffffUL) return 0;
    *out = (uint32_t) v;
    return 1;
}

static void *notify_loop(void *arg) {
    int fd = (int) (intptr_t) arg;
    for (;;) {
        struct seccomp_notif req;
        memset(&req, 0, sizeof(req));
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            break;
        }
        struct seccomp_notif_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.id = req.id;
        int nr = (int) req.data.nr;
        int deny = 0;

        if (nr == __NR_getpriority) {
            int which = (int) req.data.args[0];
            uint32_t uid = (uint32_t) req.data.args[1];
            if (which == 2 /* PRIO_USER */ && uid_is_hidden(uid)) deny = 1;
        } else if (nr == __NR_openat || nr == __NR_openat2) {
            char path[512];
            memset(path, 0, sizeof(path));
            struct iovec local = { path, sizeof(path) - 1 };
            struct iovec remote = { (void *) (uintptr_t) req.data.args[1], sizeof(path) - 1 };
            ssize_t got = process_vm_readv((pid_t) req.pid, &local, 1, &remote, 1, 0);
            if (got <= 0) got = 0;
            path[got] = 0;
            uint32_t hid = 0;
            if (path_hidden_uid(path, &hid) && uid_is_hidden(hid)) deny = 1;
        }

        if (deny) {
            resp.error = (nr == __NR_getpriority) ? EPERM : ENOENT;
        } else {
            resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT) break;
    }
    return NULL;
}

// 返回 0 = 已安装；-1 = 不支持（不安装，放行一切）
extern "C" int uid_filter_init(const uint32_t *uids, int count) {
    if (!uids || count <= 0) return -1;
    if (count > MAX_HIDDEN) count = MAX_HIDDEN;
    memcpy(g_hidden, uids, sizeof(uint32_t) * count);
    g_hidden_count = count;

    struct sock_filter insn[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0 /* seccomp_data.nr */),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(insn) / sizeof(insn[0])),
        .filter = insn,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    int fd = (int) syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) return -1;   // 不支持 user-notify 就不装（宁可不装也不越界过滤）
    pthread_t t;
    if (pthread_create(&t, NULL, notify_loop, (void *) (intptr_t) fd) != 0) {
        close(fd);
        return -1;
    }
    pthread_detach(t);
    return 0;
}
