/* gcc hyp.c -nostdlib -fPIC -shared -o vmi.so */
/*
block read
buffer[0] lock
buffer[1] type
buffer[2] base
buffer[3] size

batch read
buffer[0] lock
buffer[1] type
buffer[2] start
buffer[3] next_offset 
buffer[4] offset1
buffer[5] size1
buffer[6] offset2
buffer[7] size2

buffer[1023] watermark
*/

void entry ()
{
    // watermark in ECX, buffer start address in EDX
    asm (// "movl 0xFFC(%edx), %eax;\n\t"
         // "cmpl %ecx, %eax;\n\t"
         // "jne 1f;\n\t"
         "2: \n\t"
         "movl (%edx), %eax;\n\t" // (%ebx) : lock
         "cmpl $1, %eax; \n\t"
         "jne 2b;\n\t"

         "movl 4(%edx), %eax;\n\t" // 12(%edx) : source addr
         "movl 8(%edx), %ebx;\n\t" // 16(%edx) : size in dword
         "xorl %esi, %esi; \n\t"

         "4: \n\t"
         "movl (%eax, %esi, 0x4), %ecx;\n\t"
         "movl %ecx, 12(%edx, %esi, 0x4);\n\t"
         "inc %esi;\n\t"
         "cmpl %esi, %ebx;\n\t"
         "jl 4b; \n\t"

         "xorl %eax, %eax; \n\t"
         "movl %eax, (%edx); \n\t"
         "jmp 2b; \n\t"
            
         "1: \n\t"
         "jmp 3f;\n\t"
         "3: \n\t"
            
            );

}
