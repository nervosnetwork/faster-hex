#define _GNU_SOURCE
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ucontext.h>

static uintptr_t main_base;
static unsigned ticks[1024 * 256];
static unsigned elsewhere;

static int inspect_main(struct dl_phdr_info *info, size_t unused, void *data) {
    (void)unused; (void)data;
    if (!info->dlpi_name || !*info->dlpi_name) {
        main_base = info->dlpi_addr;
        return 1;
    }
    return 0;
}
static void sample(int sig, siginfo_t *info, void *context) {
    (void)sig; (void)info;
    ucontext_t *uc = context;
#if defined(__x86_64__)
    uintptr_t addr = uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    uintptr_t addr = uc->uc_mcontext.pc;
#else
#error Unsupported sampling target
#endif
    uintptr_t word = (addr - main_base) / 4;
    if (word < sizeof(ticks) / sizeof(ticks[0])) ++ticks[word];
    else ++elsewhere;
}
__attribute__((constructor)) static void start(void) {
    dl_iterate_phdr(inspect_main, NULL);
    struct sigaction sa = {0};
    sa.sa_sigaction = sample;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPROF, &sa, NULL);
    struct itimerval t = {{0,500},{0,500}};
    setitimer(ITIMER_PROF, &t, NULL);
}
__attribute__((destructor)) static void finish(void) {
    struct itimerval stop = {0};
    setitimer(ITIMER_PROF, &stop, NULL);
    FILE *f = fopen(getenv("COUNTS_FILE"), "w");
    if (f) {
        for (size_t i=0; i<sizeof(ticks)/sizeof(ticks[0]); ++i)
            if (ticks[i]) fprintf(f, "%zx %u\n", i*4, ticks[i]);
        fprintf(f, "outside %u\n", elsewhere);
        fclose(f);
    }
}
