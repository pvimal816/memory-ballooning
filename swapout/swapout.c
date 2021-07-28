#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/mman.h>

#define MAX_SIZE 1<<20
unsigned long buf[MAX_SIZE];

extern unsigned long sigballoon_shrink_all_memory(unsigned long);

SYSCALL_DEFINE2(swapout, void __user *, start, size_t, size)
{	
	size_t i, nr_entries;

	if(size>(MAX_SIZE<<3))
		size=MAX_SIZE<<3;

	if(copy_from_user((void*)buf, start, size))
		return -1;
	nr_entries = size>>3;
	for(i=0; i<nr_entries; ++i){
		do_madvise(current->mm, buf[i], 1<<12, MADV_PAGEOUT);
	}

	sigballoon_shrink_all_memory(nr_entries*100);

    return 0;
}