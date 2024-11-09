#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "imee.h"

// void* p1;

int func()
{
    printf("PID: %d\n",getpid());
    return 0;
}

int main()
{
    printf ("PID: %d\n", getpid());
    cpu_set_t cpuset;
    CPU_ZERO (&cpuset);
    CPU_SET (1, &cpuset);
    sched_setaffinity (0, sizeof (cpuset), &cpuset);

    setup_imee (intros);
    run_imee ();
    goto intros;

intros:

    unsigned long a = 0x06000000U;
    unsigned long b = 0x06200000U;
    char* buf;
    int c = b - a;
    func();
    printf ("%p\n", malloc);
    char str[10] = "string1";
    char str2[] = "string2";
    strcpy (str, str2);
    printf ("%s\n", str);
   // float val;
   // val = atof (str);
   // printf ("%f\n", val);
    void* pointer = 0x0806d000;
    printf ("Initialized brk: %p\n", sbrk(0));
    int ret = sbrk (0x1000); 
    printf ("Return value of sbrk: %x\n", ret);
    printf ("brk after brk increase: %p\n", sbrk(0));
    //sleep (4);
    //printf ("%p\n", pointer);
    buf = (char*)malloc(1);
    char* buf1;
    buf1 = (char*)malloc(1);
    printf ("buf: %p\n", buf);
    printf ("buf1: %p\n", buf1);

    void* dl_h = dlopen("/home/beverly/Documents/play/test/vmi.so", RTLD_NOW);
   // if (dl_h == 0)
   // {
   //     return 0;
   // }
   // else
   // {
   //     printf ("%p\n", dl_h);
   // }

    sleep(10000000);
    printf("%d\n", c);
    return 0;
}

