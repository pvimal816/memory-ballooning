#include "sigballoon.h"

int SIGBALLOON_TARGET_TGID = -1;
int SIGBALLOON_TARGET_NOTIFIED = 0;

asmlinkage long __x64_sys_sigballon_reg(void)
{
    SIGBALLOON_TARGET_TGID = current->tgid;
	printk("sigballon_syscall called from pid %d.", current->tgid);
    return 0;
}

asmlinkage long __ia32_sys_sigballon_reg(void)
{
	SIGBALLOON_TARGET_TGID = current->tgid;
	printk("sigballon_syscall called from pid %d.", current->tgid);
	return 0;
}