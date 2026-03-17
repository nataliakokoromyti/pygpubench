// Copyright (c) 2026 Erik Schultheis
// SPDX-License-Identifier: Apache-2.0
//

#include <cstdint>
#include <fcntl.h>
#include <stddef.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/landlock.h>
#include <system_error>
#include <utility>

class Fd {

public:
    explicit Fd(int fd) : mFD(fd) {}
    ~Fd() { close(mFD); }

    int fd() { return mFD; }

    // non-copyable, movable
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : mFD(std::exchange(o.mFD, -1)) {}

private:
    int mFD;
};

struct LandlockFd : Fd {
    explicit LandlockFd(int fd) : Fd(fd) {}
};

static LandlockFd landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
    const int ret = syscall(__NR_landlock_create_ruleset, attr, size, flags);
    if (ret < 0)
        throw std::system_error(errno, std::system_category(),
                                "landlock_create_ruleset");
    return LandlockFd{ret};
}

static void landlock_add_rule(
    LandlockFd& ruleset, enum landlock_rule_type rule_type,
    const void *rule_attr, uint32_t flags) {
    if (syscall(__NR_landlock_add_rule, ruleset.fd(), rule_type, rule_attr, flags) < 0)
        throw std::system_error(errno, std::system_category(),
                                "landlock_add_rule");
}

static void landlock_restrict_self(LandlockFd& ruleset, uint32_t flags) {
    if (syscall(__NR_landlock_restrict_self, ruleset.fd(), flags) < 0)
        throw std::system_error(errno, std::system_category(),
                                "landlock_restrict_self");
}

static void allow_path(LandlockFd& ruleset, const char *path, uint64_t access) {
    int raw = open(path, O_PATH | O_CLOEXEC);
    if (raw < 0) {
        if (errno == ENOENT) return;
        throw std::system_error(errno, std::system_category(), path);
    }
    Fd fd(raw);

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd      = fd.fd(),
    };
    landlock_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
}

void install_landlock() {
    // === DEFENSE: Stub cuModuleLoadData to block custom PTX loading (ptx_injection) ===
    {
        void* cuda_lib = dlopen("libcuda.so.1", RTLD_NOW|RTLD_GLOBAL);
        if (!cuda_lib) cuda_lib = dlopen("libcuda.so", RTLD_NOW|RTLD_GLOBAL);
        const char* fns[] = {"cuModuleLoadData", "cuModuleLoadDataEx", NULL};
        for (int i = 0; fns[i]; i++) {
            void* fn = dlsym(RTLD_DEFAULT, fns[i]);
            if (!fn) continue;
            uintptr_t page = (uintptr_t)fn & ~4095UL;
            if (mprotect((void*)page, 8192, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) continue;
            unsigned char stub[] = {0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};
            memcpy(fn, stub, sizeof(stub));
            mprotect((void*)page, 8192, PROT_READ|PROT_EXEC);
        }
    }

    // Required for all seccomp filters below
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // === DEFENSE: Block SYS_ptrace via seccomp (ptrace exploit) ===
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            fprintf(stderr, "seccomp(block ptrace): %s\n", strerror(errno));
        }
    }


    // === DEFENSE: Block prctl(PR_SET_DUMPABLE, non-zero) via seccomp (ptrace exploit) ===
    // gVisor may not filter ptrace through seccomp, so block the prerequisite:
    // the exploit calls prctl(PR_SET_DUMPABLE, 1) to re-enable ptrace access.
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),              // load syscall nr
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 157, 0, 5),    // __NR_prctl?
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),             // load arg0 (option)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 3),      // PR_SET_DUMPABLE?
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 24),             // load arg1 (value)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),      // value==0? allow
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),   // DENY non-zero
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),       // ALLOW
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    }

    // === DEFENSE: Block pwrite64 via seccomp (proc_mem_write) ===
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 18, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            fprintf(stderr, "seccomp(block pwrite64): %s\n", strerror(errno));
        }
    }

    // === DEFENSE: Block mmap(MAP_FIXED | PROT_EXEC) via seccomp (mmap_shadow) ===
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9, 0, 7),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 32),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 4),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 0),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 40),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x10),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            fprintf(stderr, "seccomp(block mmap MAP_FIXED+EXEC): %s\n", strerror(errno));
        }
    }

    // === DEFENSE: Block mprotect(PROT_EXEC) via seccomp (function_detour + twostep_mprotect) ===
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { /* may already be set */ }
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 3),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 32),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x4),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x4, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            fprintf(stderr, "seccomp(block mprotect EXEC): %s\n", strerror(errno));
        }
    }

    // === DEFENSE: Block madvise(MADV_DONTNEED=4) via seccomp (backing_file) ===
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { /* may already be set */ }
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 28, 0, 3),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 32),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { .len = 6, .filter = filter };
        syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    }

    // === DEFENSE: Block mremap(MREMAP_FIXED) via seccomp (mremap_rwx) ===
    // Prevents replacing code pages via mremap with MREMAP_FIXED flag.
    // mremap syscall nr=25, flags=args[3] at offset 40, MREMAP_FIXED=0x2
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),             // load syscall nr
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 25, 0, 4),    // mremap(25)? no->allow
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 40),            // load flags (args[3])
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x2),          // AND MREMAP_FIXED(0x2)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x2, 0, 1),   // set? deny, else allow
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),      // ALLOW
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),  // DENY (EPERM)
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            fprintf(stderr, "seccomp(block mremap MREMAP_FIXED): %s\n", strerror(errno));
        }
    }

    // === DEFENSE: Block SYS_seccomp (317) - installed LAST (seccomp_trap) ===
    // Must be last so harness's own seccomp installs above are not blocked.
    {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 317, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };
        syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    }

    // Prevent ptrace and /proc/self/mem tampering
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // Landlock may not be available (gVisor) - non-fatal
    try {

    const std::uint64_t RO = LANDLOCK_ACCESS_FS_READ_FILE |
                     LANDLOCK_ACCESS_FS_READ_DIR;

    const std::uint64_t RW = RO                              |
                     LANDLOCK_ACCESS_FS_WRITE_FILE   |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE  |
                     LANDLOCK_ACCESS_FS_REMOVE_DIR   |
                     LANDLOCK_ACCESS_FS_MAKE_REG     |
                     LANDLOCK_ACCESS_FS_MAKE_DIR     |
                     LANDLOCK_ACCESS_FS_MAKE_SYM     |
                     #ifdef LANDLOCK_ACCESS_FS_TRUNCATE
                     LANDLOCK_ACCESS_FS_TRUNCATE     |
                     #endif
                     #ifdef LANDLOCK_ACCESS_FS_REFER
                     LANDLOCK_ACCESS_FS_REFER        |
                     #endif
                     0;

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = RW, // everything we handle; unlisted = unrestricted
    };

    LandlockFd ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

    // Read-only: entire filesystem
    allow_path(ruleset_fd, "/", RO);

    // Read-write: /tmp and /dev only
    allow_path(ruleset_fd, "/tmp", RW);
    allow_path(ruleset_fd, "/dev", RW); // needed for /dev/null etc, used e.g., by triton

    landlock_restrict_self(ruleset_fd, 0);

    } catch (const std::system_error&) {
        // landlock not available (gVisor) - seccomp filters still active
        fprintf(stderr, "landlock not available, continuing with seccomp only\n");
    }
}
