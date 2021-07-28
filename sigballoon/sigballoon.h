#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/current.h>

#define SIGBALLOON 40
#define SIGBALLOON_FREE_MEMORY_THRESHOLD 1000000 //in KB
#define SIGBALLOON_MIN_MEMORY_THRESHOLD 100000