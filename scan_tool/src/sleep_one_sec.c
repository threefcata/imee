#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <link.h>
#include <sched.h>
#include <linux/types.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "imee.h"
#include "util.h"

void* p1;
void* buffer;

struct arg_blk
{
    unsigned long cr3;
    unsigned long num_x_page;
    unsigned long num_w_page;
    unsigned long offset;
    unsigned long code_host;
    unsigned long data_host;
    unsigned long stack;
    unsigned long entry;
    unsigned long int_handler;
    unsigned long thunk;
    unsigned long got;
    unsigned long got_len;
    unsigned long gotplt;
    unsigned long gotplt_len;
};

struct arg_blk args;

static int go ();

int main()
{
    cpu_set_t cpuset;
    CPU_ZERO (&cpuset);
    CPU_SET (1, &cpuset);
    sched_setaffinity (0, sizeof (cpuset), &cpuset);

    void* dl_h = dlopen ("./vmi.so", RTLD_NOW);
    if (!dl_h)
    {
        printf ("%s\n", dlerror());
        exit(1);
    }
    // void* (*p2)() = (void*(*)()) dlsym (dl_h, "get_buf");
    // buffer = (*p2)();
    buffer = valloc (4096);
    // the watermark
    *((int*) (buffer + 4092)) = 0xDEADBEEF;

    p1 = dlsym (dl_h, "entry");
    // printf ("p1: %p\n", p1);
    // printf ("buffer: %p\n", buffer);
    // printf ("pid: %d\n", getpid());

    // preparing args
    // dl_iterate_phdr (phdr_iterator, NULL);

    args.entry = (unsigned long) p1;
    args.code_host = args.entry & ~0xFFFU;
    args.data_host = buffer;
    args.num_x_page = 1;
    args.num_w_page = 1;

    mlockall(MCL_CURRENT);

    // // start ImEE
    // void* stk = valloc (4096);
    // * (int*) stk = 0; // touch the page, so linux allocates it.
    // clone (go, (char*)stk + 4092, CLONE_VM | CLONE_FS | CLONE_FILES, NULL);

    setup_imee (&args, p1);

    volatile int* queue = (int*) buffer;
    volatile int tmp;

    int r = 0;
    int c = 0; 
    unsigned long long t = 0;

	unsigned long start = init_task; 
	unsigned long cur = start;
	void *res_buffer = (void *)malloc(4096 * 2);		
	memset(res_buffer, 0, 4096 * 2);
	

    // for (; c < 100; c ++)
    // {
        queue[1] = cur;
        queue[2] = ts_tasks;
        queue[3] = ts_pid;
        queue[4] = 4; // 4bytes
        queue[5] = ts_comm;
        queue[6] = 16; // 16bytes
        queue[0] = 1; // lock
        t0 = rdtsc ();
        r = run_imee ();
        // while(queue[0]);
        t1 = rdtsc ();
        if (r < 0) 
        {
            printf ("sleeping\n");
            sleep (1);
            return 0;
        }
        t += t1 - t0;
    // }

    // printf("%lld\n", t / 100);
    printf("%lld\n", t);

    int i = 0;
    for (; i < 30; i ++)
    {
		// printf("%d %s\n", *(queue + 7 + i * 5), (queue +7 + i * 5 + 1));
    }

    // sleep (9999);

    return 0;
}

static int go ()
{
    cpu_set_t cpuset;

    CPU_ZERO (&cpuset);
    CPU_SET (2, &cpuset);
    sched_setaffinity (0, sizeof (cpuset), &cpuset);

    run_imee (&args, p1);

	return 0; 
}

static int phdr_iterator (struct dl_phdr_info* info, size_t size, void* data)
{
    if (!strcmp ("./vmi.so", info->dlpi_name))
    {
        args.code_host = (info->dlpi_addr + info->dlpi_phdr[0].p_vaddr) & ~0xFFF;
        args.data_host = (info->dlpi_addr + info->dlpi_phdr[1].p_vaddr) & ~0xFFF;
        args.offset = args.data_host - args.code_host - 0x1000; // in bytes
        args.num_x_page = (info->dlpi_phdr[0].p_memsz + 0xFFF) / 0x1000;
        args.num_w_page = (info->dlpi_phdr[1].p_memsz + 0xFFF) / 0x1000;
#ifdef DEBUG
        printf ("code_host: %lX data_host: %lX, offset: %lX\n", args.code_host, args.data_host, args.offset);
        printf ("num_x_page: %ld num_w_page: %ld\n", args.num_x_page, args.num_w_page);
#endif

        return 1;
    }

    return 0;
}
