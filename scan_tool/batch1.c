/*
batch read
buffer[0] lock
buffer[1] start
buffer[2] next_offset 
buffer[3] offset1
buffer[4] size1

buffer[1023] watermark
*/

inline void memcpy_v(unsigned long *dst, unsigned long *src, unsigned long size) {
	//int i;
	//for (i = 0; i < size; i++)
	//	dst[i] = src[i];

	while(size--)
		*(dst++)=*(src++);
}

inline void traverse(unsigned long dst, unsigned long start, unsigned long next_offset,
												unsigned long offset1, unsigned long size1) {
	unsigned long cur = start;
	unsigned long pos = 0;

	do
	{
		memcpy_v((unsigned long *)(dst + pos), (unsigned long *)(cur + offset1), size1);
		pos += size1;
		cur = *(unsigned long *)(cur + next_offset) - next_offset;
	} while (cur != start);
}

__attribute__((fastcall)) void entry (unsigned long watermark, unsigned long *buffer)
{
	while(1)
	{
//		if (buffer[1023] !=  watermark)
//			goto fail;
		while (1)
		{
			if (buffer[0] == 1) break;
		}

		traverse((unsigned long)(&buffer[5]), buffer[1], buffer[2],
				buffer[3], buffer[4]);

		buffer[0] = 0;
	}

	/*
    // watermark in EAX, buffer start address in EBX
    asm ("movl 0xFFC(%ebx), %ecx;\n\t"
         "cmpl %eax, %ecx;\n\t"
         "jne 1f;\n\t"
         "2: \n\t"
         "movl (%ebx), %eax;\n\t" // (%ebx) : lock
         "cmpl $1, %eax; \n\t"
         "jne 2b;\n\t"
         "movl 4(%ebx), %ecx;\n\t" // $4(%ebx) : source addr
         "movl 8(%ebx), %edx;\n\t" // $8(%ebx) : size
         "4: \n\t"
         "movl -4(%ecx, %edx), %ecx;\n\t"
         "movl %ecx, 0xc(%ebx, %edx);\n\t"
         "subl $4, %edx;\n\t"
         "cmpl $0, %edx;\n\t"
         "jg 4b; \n\t"
         "jmp 2b; \n\t"
            
            
         "1: \n\t"
         "jmp 3f;\n\t"
         "3: \n\t"
            
            );
*/
}
