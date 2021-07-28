#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "testcases.h"

/*
* syscall() and signal 
* specific headers
*/
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <assert.h>
#include <sys/types.h>

void *buff;
unsigned long nr_signals = 0;

#define PAGE_SIZE (4096)
#define HUGE 17

/*
 * 			placeholder-3
 * implement your page replacement policy here
 */

// Helper Macros
#define 	GetVpnFromVpa(vpa) 						((vpa) >> 12)
#define 	GetPfnFromPte(pte) 						((pte)&0x7FFFFFFFFFFFFFL)
#define 	IsSwappedOut(pte) 						((pte >> 62) & 1)
#define 	IsPresent(pte) 							((pte >> 63) & 1)
#define 	GetNormalizedAddress(vpn) 				(vpn-start_vpn)
#define 	GetUnNormalizedAddress(vpn) 			(vpn+start_vpn)


// Heap macros
#define 	LeftChild(x) ((x<<1) | 1)
#define 	RightChild(x) (LeftChild(x) + 1)
#define 	Parent(x) ((x-1)>>1)


// Constants
#define 	LRU_LIST_UPDATE_FREQUENCY_IN_SEC 		16
#define 	MAX_LRU_LIST_UPDATE_FREQUENCY_IN_SEC 	600 	// 10 minutes
#define 	FREE_MEM_THRESHOLD 						(1 << 20)
#define 	PAGE_COUNT 								(TOTAL_MEMORY_SIZE / PAGE_SIZE + (TOTAL_MEMORY_SIZE % PAGE_SIZE == 0 ? 0 : 1))
#define 	SIGBALLOON 								40
#define		SIGBALLOON_WAKEUP						41
#define		IDLE_BITMAP_MAX_PAGES					(1<<28)	// supports 1TB of physical memory			
#define		MAX_PAGE_TO_SWAPOUT_PER_CALL			(1<<16) // swapout atmost 256 MB in single invocation of sigballoon_handler
#define 	LOG_LEVEL_NO_LOG						1
#define 	LOG_LEVEL_INFO 							2
#define 	LOG_LEVEL_VERBOS						3

// Configuration variable

/**
 * log_level = LOG_LEVEL_NO_LOG 		=> No logs will be printed except critical msgs.
 * log_level = LOG_LEVEL_INFO 			=> only errors will be printed.
 * log_level = LOG_LEVEL_VERBOS			=> On top of above, the information 
 * 											related to various events will 
 *											also be printed.
 */
int log_level = LOG_LEVEL_NO_LOG;

// definitions of shared data-structures
sig_atomic_t 	entry_flag;
unsigned long 	start_vpn;
unsigned long 	idle_bitmap_buffer[IDLE_BITMAP_MAX_PAGES >> 6]; // 64 page info per entry.
unsigned long 	idle_bitmap_buffer_size;
unsigned short 	ishugepage_buffer[IDLE_BITMAP_MAX_PAGES];
unsigned long 	ishugepage_buffer_size;

unsigned long 	current_update_frequency;

/**
 * @brief 
 * pte_cache array holds vpn to pfn mapping 
 * which will reduce the number of syscalls
 * needed to translate vpn to pfn
 * need to invalidate this entry when we 
 * swap a page
 */
typedef struct pte_cache_entry
{
	unsigned long pte;
	short valid;
} pte_cache_entry_t;

pte_cache_entry_t pte_cache[PAGE_COUNT];

/**
 * @brief 
 * Contains entry for each page.
 * Higher the score more the chances
 * that the page will be accessed in the 
 * near future. 
 *
 * There is an exception though: swapped 
 * out pages have the highest possible score.
 */
typedef struct {
	unsigned int score;
	// unnormalized vpn
	unsigned long vpn;
} lru_list_entry_t;

lru_list_entry_t lru_list[PAGE_COUNT];

/**
 * @brief ith entry stores the index at which 
 * the heap_node for ith page can be found in 
 * the lru_list.
 */
size_t lru_list_lookup[PAGE_COUNT];

/**
 * @brief
 * Prints the logs based on the log level to 
 * the error stream.
 * 
 * @param
 * msg: logs to be printed
 */
void log(char *msg, int msg_level){
	if(!msg)
		return;
	if(log_level<msg_level)
		return;
	fprintf(stderr, "%s\n", msg);
}

/**
 * @brief
 * A helper function to maintain a min_heap
 * 
 * @returns
 * -1 on error
 * 0 otherwise
 */
int min_heapify(size_t pos){
	if(pos<0 || PAGE_COUNT<=pos){
		char msg[150];
		sprintf(msg, "[min_heapify] Received invalid pos %lu, when PAGE_COUNT is %lu.", pos, PAGE_COUNT);
		log(msg, LOG_LEVEL_INFO);
		return -1;
	}
	size_t minn = pos;
	if(LeftChild(pos) < PAGE_COUNT && lru_list[minn].score > lru_list[LeftChild(pos)].score)
		minn = LeftChild(pos);
	
	if(RightChild(pos) < PAGE_COUNT && lru_list[minn].score > lru_list[RightChild(pos)].score)
		minn = RightChild(pos);
	
	if(minn!=pos){
		lru_list_entry_t temp = lru_list[pos];
		lru_list[pos] = lru_list[minn];
		lru_list[minn] = temp;
		lru_list_lookup[GetNormalizedAddress(lru_list[minn].vpn)] = minn;
		lru_list_lookup[GetNormalizedAddress(lru_list[pos].vpn)] = pos;
		return min_heapify(minn);
	}
	return 0;
}

/**
 * @brief
 * organize the content of lru_list in 
 * min_heap. It also, updates lru_list_lookup
 * accordingly.
 * 
 * This function expects that lru_list has been
 * initialized with ith location containing heap_node
 * of ith page. It also expects that lru_list_lookup 
 * is consistent with lru_list.
 * 
 * @returns
 * -1 on error
 *  0 otherwise
 */
int build_min_heap(){
	int ret;
	for(int i = (PAGE_COUNT>>1) - 1; i>=0; i--)
		if((ret = min_heapify((size_t)i))==-1){
			char msg[150];
			sprintf(msg, "[build_min_heap] Failed to build heap: i=%d.", i);
			log(msg, LOG_LEVEL_INFO);
			return ret;
		}
	return 0;
}

/**
 * @brief
 * increases the score of the lru_list entry
 * and then enforce the min_heap invariant.
 * 
 * @param
 * vpn: unnormalized vpn for which the score is to be increased
 * new_score: the score which is to be assigned
 **/
int increase_score(unsigned long vpn, unsigned int new_score){
	vpn = GetNormalizedAddress(vpn);
	if(vpn<0 || PAGE_COUNT<=vpn)
		return -1;

	unsigned int old_score = lru_list[lru_list_lookup[vpn]].score;
	if(new_score<old_score)
		return -1;

	lru_list[lru_list_lookup[vpn]].score = new_score;
	return min_heapify(lru_list_lookup[vpn]);
}

/**
 * @brief
 * decreases the score of the lru_list entry
 * and then enforce the min_heap invariant.
 * 
 * @param
 * vpn: unnormalized vpn for which the score is to be increased
 * new_score: the score which is to be assigned
 **/
int decrease_score(unsigned long vpn, unsigned int new_score){
	vpn = GetNormalizedAddress(vpn);
	if(vpn<0 || PAGE_COUNT<=vpn)
		return -1;

	unsigned int old_score = lru_list[lru_list_lookup[vpn]].score;
	if(new_score>old_score)
		return -1;

	size_t cur = lru_list_lookup[vpn];
	lru_list_entry_t temp = lru_list[cur];
	temp.score = new_score;
	while(cur>0 && lru_list[Parent(cur)].score > new_score){
		lru_list[cur] = lru_list[Parent(cur)];
		lru_list_lookup[GetNormalizedAddress(lru_list[cur].vpn)] = cur;
		cur = Parent(cur);
	}

	lru_list[cur] = temp;
	lru_list_lookup[GetNormalizedAddress(lru_list[cur].vpn)] = cur;

	return 0;
}

/**
 * @brief
 * updates the score of the lru_list entry
 * and then enforce the min_heap invariant.
 * 
 * @param
 * vpn: unnormalized vpn for which the score is to be increased
 * new_score: the score which is to be assigned
 **/
int update_score(unsigned long vpn, unsigned int new_score){
	unsigned long nvpn = GetNormalizedAddress(vpn);
	if(nvpn<0 || PAGE_COUNT<=nvpn)
		return -1;

	unsigned int old_score = lru_list[lru_list_lookup[nvpn]].score;
	
	if(old_score < new_score)
		return increase_score(vpn, new_score);
	else if(old_score > new_score)
		return decrease_score(vpn, new_score);

	return 0;
}

/**
 * @brief
 * checks if the lru_list 
 * maintains a heap invariant.
 * 
 * @returns
 * 1 if invariant is satisfied 
 * 0 otherwise
 */
int is_heap(int pos){
	int ret = 1;

	if(LeftChild(pos)<PAGE_COUNT){
		if(lru_list[LeftChild(pos)].score < lru_list[pos].score)
			return 0;
		ret &= is_heap(LeftChild(pos));
	}

	if(RightChild(pos)<PAGE_COUNT){ 
		if(lru_list[RightChild(pos)].score < lru_list[pos].score)
			return 0;
		ret &= is_heap(RightChild(pos));
	}

	return ret;
}

/**
 * @brief
 * 
 * @returns 
 * The amount of available 
 * free memory in KB
 */
unsigned long calc_free_mem()
{
	struct sysinfo info;
	if (sysinfo(&info))
	{
		log("[calc_free_mem] sysinfo returned nonzero code", LOG_LEVEL_NO_LOG);
		exit(1);
	}
	return info.freeram >> 10;
}

/**
 * @brief 
 * This function translates unnormalized 
 * vpn to pte and stores the result into 
 * pte_cache
 * 
 * @return
 * -1 on error
 *  0 otherwise
 */
int get_pte(unsigned long vpn, unsigned long *pte)
{
	unsigned long _pte = 0;
	static int pagemap_fd;

	if (vpn < start_vpn || vpn >= start_vpn + PAGE_COUNT)
	{
		log("[get_pte] Invalid vpn.", LOG_LEVEL_INFO);
		return -1;
	}

	if (pte == NULL)
	{
		log("[get_pte] Invalid pfn.", LOG_LEVEL_INFO);
		return -1;
	}

	if (pte_cache[vpn - start_vpn].valid)
	{
		*pte = pte_cache[vpn - start_vpn].pte;
		return 0;
	}

	if (!pagemap_fd)
		pagemap_fd = open("/proc/self/pagemap", O_RDONLY);

	if (pagemap_fd < 0)
	{
		log("[get_pte] Failed to open pagemap file.", LOG_LEVEL_INFO);
		return -1;
	}

	unsigned long seek_offset = vpn << 3;
	if (pread(pagemap_fd, &_pte, sizeof(_pte), seek_offset) != sizeof(_pte))
	{
		log("[get_pte] Failed to read pfn.", LOG_LEVEL_INFO);
		return -1;
	}

	pte_cache[vpn - start_vpn].pte = _pte;
	/**
	 * Mark the entry valid only if
	 * the page is not swapped out.
	 * Otherwise, the page might get 
	 * swapped in and we wouldn't
	 * know it resulting in inconsistent 
	 * cache state.
	 */
	if(!IsSwappedOut(_pte))
		pte_cache[vpn - start_vpn].valid = 1;

	*pte = _pte;
	
	assert(_pte!=0);

	return 0;
}

/**
 * @brief
 * reads entire idle_map file in idle_bitmap_buffer.
 *
 * @returns
 * 0 on success
 * -1 otherwise
 */
int load_idle_bitmap_buffer(){
	int idle_fd;
	if ((idle_fd = open("/sys/kernel/mm/page_idle/bitmap", O_RDONLY)) < 0)
	{
		log("[load_idle_bitmap_buffer] Unable to open page_idle file.", LOG_LEVEL_INFO);
		return -1;
	}
	
	idle_bitmap_buffer_size = 0;
	unsigned long * ptr = idle_bitmap_buffer;

	while(read(idle_fd, ptr++, 8)>0)
		++idle_bitmap_buffer_size;

	idle_bitmap_buffer_size++;

	close(idle_fd);

	return 0;
}

/**
 * @brief
 * reads huge page flags from the kpageflags file in ishugepage_buffer.
 *
 * @returns
 * 0 on success
 * -1 otherwise
 */
int load_ishugepage_buffer(){
	int kpageflags_fd;
	if((kpageflags_fd = open("/proc/kpageflags", O_RDONLY)) < 0)
	{
		log("[load_ishugepage_buffer] Unable to open kpageflags file.", LOG_LEVEL_INFO);
		return -1;
	}
	
	ishugepage_buffer_size = 0;
	unsigned long temp;
	
	int err;
	while((err=read(kpageflags_fd, &temp, 8))>0){
		ishugepage_buffer[ishugepage_buffer_size++] = (temp >> HUGE) & 1;
	}
	
	if(err<0){
		log("[load_ishugepage_buffer] Error while reading kpageflags file.", LOG_LEVEL_INFO);
		return -1;
	}

	close(kpageflags_fd);

	return 0;
}

int is_huge_page(unsigned long vpn)
{
	unsigned long pfn;
	unsigned long pte;
	if(get_pte(vpn, &pte)){
		log("[is_huge_page] Error in get_pte.", LOG_LEVEL_INFO);
		return -1;
	}

	pfn = GetPfnFromPte(pte);
	
	if(pfn<0 || pfn>=ishugepage_buffer_size){
		char logbuf[1000];
		sprintf(logbuf, "[is_huge_page] Invalid pfn! (pfn=%lu, ishugepage_buffer_size=%lu, idle_bitmap_buffer_size=%lu)", 
			pfn, ishugepage_buffer_size, idle_bitmap_buffer_size);
		log(logbuf, LOG_LEVEL_INFO);
		return -1;
	}
	
	return ishugepage_buffer[pfn];
}

/**
 * @brief
 * writes entire idle_bitmap_buffer to 
 * the idle_map file.
 *
 * @returns
 * 0 on success
 * -1 otherwise
 */
int flush_idle_bitmap_buffer(){
	int idle_fd;
	if ((idle_fd = open("/sys/kernel/mm/page_idle/bitmap", O_RDWR)) < 0)
	{
		log("[flush_idle_bitmap_buffer] Unable to open page_idle file.", LOG_LEVEL_INFO);
		return -1;
	}
	
	unsigned long * ptr = idle_bitmap_buffer;

	for(size_t i=0; i<idle_bitmap_buffer_size-1; i++)
		if(write(idle_fd, ptr++, 8)!=8){
			log("[flush_idle_bitmap_buffer] Unable to write all 8 bytes to page_idle file.", LOG_LEVEL_INFO);
			return -1;
		}

	return 0;
}

/**
 * @brief 
 * This function reads the idle bit for 
 * given vpn. It assumes that the 
 * idle_bitmap_buffer is in a valid state.
 *
 * @returns -1 on error
 */
int is_idle(unsigned long vpn)
{
	unsigned long pfn;
	unsigned long pte;
	if(get_pte(vpn, &pte)){
		log("[is_idle] Error in get_pte.", LOG_LEVEL_INFO);
		return -1;
	}
	
	pfn = GetPfnFromPte(pte);
	
	/**
	 * read the idle bit of the head page in case of 
	 * current page is part of a huge page.
	 */ 
	if(is_huge_page(vpn))
		pfn &= ~(0x1ffULL);

	if(IsSwappedOut(pfn))
		return 1;

	unsigned long seek_offset = (pfn >> 6);
	
	if(seek_offset<0 || seek_offset>=idle_bitmap_buffer_size){
		log("[is_idle] Invalid pfn!", LOG_LEVEL_INFO);
		return -1;
	}
	
	unsigned long entry = idle_bitmap_buffer[seek_offset];

	return (entry >> (pfn & 63)) & 1;
}

/**
 * @brief 
 * This function sets the idle bit in 
 * idle_bitmap_buffer so it should be 
 * in the valid state before this 
 * function gets called. Also, the 
 * buffer needs to be flushed to the 
 * idle bitmap file at last.
 */
int set_page_idle(unsigned long vpn)
{
	unsigned long pfn;
	unsigned long pte;
	
	if(get_pte(vpn, &pte)){
		log("[is_idle] Error in get_pte.", LOG_LEVEL_INFO);
		return -1;
	}

	pfn = GetPfnFromPte(pte);

	/**
	 * write the idle bit of the head page in case of 
	 * current page is part of a huge page.
	 */ 
	if(is_huge_page(vpn))
		pfn &= ~(0x1ffULL);

	unsigned long seek_offset = (pfn >> 6);

	if(seek_offset<0 || seek_offset>=idle_bitmap_buffer_size){
		log("[set_page_idle] Invalid pfn.", LOG_LEVEL_INFO);
		return -1;
	}

	unsigned long entry = idle_bitmap_buffer[seek_offset];

	if ((entry >> (pfn & 63)) & 1)
		return 0;

	entry |= 1ULL << (pfn & 63);

	idle_bitmap_buffer[seek_offset] = entry;

	return 0;
}

/**
 * @brief 
 * 
 * @return
 * 1 if vpn is swapped out
 * 0 if vpn is not swapped out
 * -1 on error
 */
int is_swapped_out(unsigned long vpn)
{
	unsigned long pte;
	
	if(get_pte(vpn, &pte)){
		log("[is_idle] Error in get_pte.", LOG_LEVEL_INFO);
		return -1;
	}

	return IsSwappedOut(pte);
}

/**
 * @brief 
 * This function need to be invoked at 
 * some regular interval
 */
void update_lru_score()
{
	/**
	 * Check if the sigballoon_handler is 
	 * under execution. If so, just return. 
	 * Otherwise we risk corrupting the 
	 * shared state.
	 */
	if(!entry_flag)
		return;
	entry_flag = 0;

	// disable the timer
	struct itimerval it_val;
	it_val.it_value.tv_sec = 0;
	it_val.it_value.tv_usec = 0;
	it_val.it_interval = it_val.it_value;

	if (setitimer(ITIMER_REAL, &it_val, NULL))
	{
		log("[update_lru_score] Failed to disable the timer.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	log("[update_lru_score] starting to update lru score.", LOG_LEVEL_VERBOS);

	if(load_idle_bitmap_buffer()){
		log("[update_lru_score] Failed to load idle bitmap buffer.", LOG_LEVEL_NO_LOG);
		exit(1);
	}
	
	if(load_ishugepage_buffer()){
		log("[update_lru_score] Failed to load huge pageflag buffer.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	for(int i=0; i<PAGE_COUNT; i++){
		unsigned long vpn = GetUnNormalizedAddress(i);
		
		int swapped_out = is_swapped_out(vpn);
		if(swapped_out == -1){
			log("[update_lru_score] Error while checking swap status of vpn.", LOG_LEVEL_NO_LOG);
			exit(1);
		}

		int huge_page = (swapped_out || is_huge_page(vpn)) ? 1 : 0;
		if(huge_page==-1){
			log("[update_lru_score] Error while checking if the page is a huge page.", LOG_LEVEL_NO_LOG);
			exit(1);
		}
		unsigned int regular_page = huge_page^1;
		int active = (swapped_out || is_idle(vpn)) ? 0 : 1;
		unsigned int old_score = lru_list[lru_list_lookup[i]].score;
		unsigned int new_score = old_score>>1;

		// TODO: Fix this. As of now active bit has no effect on score history because it's effect is getting
		// absorbed into huge page bit(3rd MSB).

		// clear first 2 MSBs
		new_score &= 0x3fffffffU;
		// set 1st MSB if page is swapped out
		new_score |= swapped_out << 31;
		// set 2nd MSB if page is not accessed after last score update
		new_score |= active << 30;
		/**
		 * Clear 6th MSB. Then set it iff page is a regular page. Doing so favors
		 * the regular pages over huge pages during page selection for
		 * swapout.
		 */
		new_score &= ~(1U<<26);
		new_score |= regular_page << 26;

		lru_list[lru_list_lookup[i]].score = new_score;

		if(!swapped_out && set_page_idle(vpn)){
			log("[update_lru_score] Failed to mark the page idle.", LOG_LEVEL_NO_LOG);
			exit(1);
		}
	}

	if(build_min_heap()){
		log("[update_lru_score] Failed to update heap.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	flush_idle_bitmap_buffer();

	log("[update_lru_score] done updating lru score.", LOG_LEVEL_VERBOS);

	//release lock
	entry_flag = 1;

	// enable the timer
	it_val.it_value.tv_sec = current_update_frequency;
	it_val.it_value.tv_usec = 0;
	it_val.it_interval = it_val.it_value;

	if (setitimer(ITIMER_REAL, &it_val, NULL))
	{
		log("[update_lru_score] Failed to schedule the timer.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	/**
	 * If the free memory is below the 
	 * threshold then invoke the sigballoon
	 * handler.
	 */
	if(calc_free_mem()<FREE_MEM_THRESHOLD){
		log("[update_lru_score] Free memory below the threshold.", LOG_LEVEL_VERBOS);
		/**
		 * Since memory is low in near future 
		 * there might be more request to swapout 
		 * pages. Therefore we need more precise 
		 * page scoring. Thus, reset current_update_frequency
		 * to take samples at the highest rate.
		 */
		current_update_frequency = LRU_LIST_UPDATE_FREQUENCY_IN_SEC;
		raise(SIGBALLOON);
	}else{
		/**
		 * There seems more free memory.
		 * So, decrease the rate of sampling.
		 *
		 * rate will decrease exponentially until
		 * the it reaches the rate of 1 sample per minute.
		 */
		current_update_frequency = current_update_frequency * 1.5;
		if(current_update_frequency > MAX_LRU_LIST_UPDATE_FREQUENCY_IN_SEC)
			current_update_frequency = MAX_LRU_LIST_UPDATE_FREQUENCY_IN_SEC;
	}
}

/**
 * @brief tries to swapout atmost nr_pages
 * and returns the number of pages swapped out.
 */
int swapout_pages(int nr_pages){

	unsigned long *victims = (unsigned long *)malloc(nr_pages * sizeof(unsigned long));

	int nr_freed = 0;

	for(int i=0; i<nr_pages; i++, nr_freed++){
		/**
		 * First element in lru_list always 
		 * has the smallest score. Thus, it is
		 * a victim.
		 */
		unsigned long vpn = lru_list[0].vpn;
		unsigned long pte;
		if(get_pte(vpn, &pte)){
			log("[swapout_pages] error while get_pte.", LOG_LEVEL_INFO);
			nr_freed = -1;
			goto ret;
		}
		/**
		 * If this page is swappedout then probably 
		 * remaining pages should also have been 
		 * swapped out because swapped out pages 
		 * have highest score.
		 */
		if(IsSwappedOut(pte))
			goto invoke_swapout;

		// invalidate pte_cache entry
		pte_cache[GetNormalizedAddress(vpn)].valid = 0;
		
		// update lru_list
		increase_score(vpn, 0xffffffff);

		// swapout this page
		victims[i] = vpn<<12;
	}

invoke_swapout:
	
	if(syscall(443, (void*) victims, nr_freed<<3)){
		log("[swapout_pages] sys_swapout returned with nonzero code.", LOG_LEVEL_INFO);
		nr_freed = -1;
		goto ret;
	}

ret:
	free(victims);

	return nr_freed;
}

/*
 * 			placeholder-2
 * implement your signal handler here
 */
void sigballoon_handler(int sig)
{
	if(!entry_flag)
		return;
	entry_flag = 0;

	++nr_signals;

	log("[sigballoon_handler] sigballoon handler called.", LOG_LEVEL_VERBOS);

	unsigned long free_pages = calc_free_mem()>>2;
	unsigned long free_page_threshold = FREE_MEM_THRESHOLD>>2;
	
	if(free_page_threshold <= free_pages){
		log("[sigballoon_handler] Returning without freeing any memory.", LOG_LEVEL_VERBOS);
		entry_flag = 1;
		return;
	}

	unsigned long nr_pages = free_page_threshold - free_pages;

	char msg[200];
	sprintf(msg, "[sigballoon_handler] Trying to free %lu memory pages.", nr_pages);
	log(msg, LOG_LEVEL_VERBOS);

	if(nr_pages>MAX_PAGE_TO_SWAPOUT_PER_CALL)
		nr_pages = MAX_PAGE_TO_SWAPOUT_PER_CALL;
	
	int ret = swapout_pages(nr_pages);

	if (ret==-1)
	{
		log("[sigballoon_handler] Error in swapout_pages.", LOG_LEVEL_NO_LOG);
		exit(1);
	}else{
		sprintf(msg, "[sigballoon_handler] %d pages swapped out.", ret);
		log(msg, LOG_LEVEL_VERBOS);
	}
	
	entry_flag = 1;

	/** We're running low on memory therefore it makes sense
	 * to have more precise page scores. Thus, increase sampling
	 * rate and wakeup update_lru_score if it is in sleep.
	 */
	if(current_update_frequency!=LRU_LIST_UPDATE_FREQUENCY_IN_SEC){
		current_update_frequency = LRU_LIST_UPDATE_FREQUENCY_IN_SEC;
		raise(SIGALRM);
	}
}

/**
 * @brief 
 * Initialize the data structures and 
 * register the signal handlers.
 */
void sigballoon_init(int *ptr)
{

	// set log level
	char* log_level_var = getenv("SIGBALLOON_LOG_LEVEL");
	if(log_level_var){
		log_level = atoi(log_level_var);
		if(log_level<LOG_LEVEL_NO_LOG || log_level>LOG_LEVEL_VERBOS){
			log("[sigballoon_init] Invalid value of environment variable SIGBALLOON_LOG_LEVEL. Defaulting to no logs.\n", LOG_LEVEL_NO_LOG);
			log_level = LOG_LEVEL_NO_LOG;
		}
	}

	start_vpn = GetVpnFromVpa((unsigned long)ptr);
	memset(pte_cache, 0, sizeof(pte_cache));

	// initialize pte_cache
	size_t vpn = GetUnNormalizedAddress(0);
	unsigned long seek_offset = vpn<<3;
	
	int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0)
	{
		log("[sigballoon_init] Unable to open pagemap file.", LOG_LEVEL_NO_LOG);
		exit(1);
	}
	
	lseek(pagemap_fd, seek_offset, SEEK_SET);

	for(size_t i = 0; i<PAGE_COUNT; i++){
		if(read(pagemap_fd, &pte_cache[i].pte, 8)!=8){
			log("[sigballoon_init] Unable to read pte from pagemap file.", LOG_LEVEL_NO_LOG);
			exit(1);
		}
		pte_cache[i].valid = 1;
	}

	// initialize lru_list
	for(size_t i=0; i<PAGE_COUNT; i++){
		lru_list[i].score = 0;
		lru_list[i].vpn = GetUnNormalizedAddress(i);
		lru_list_lookup[i] = i;
	}

	// allow handlers to run
	entry_flag = 1;

	if (signal(SIGALRM, update_lru_score))
	{
		log("[sigballoon_init] Failed to register SIGALRM handler.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	struct itimerval it_val;
	it_val.it_value.tv_sec = LRU_LIST_UPDATE_FREQUENCY_IN_SEC;
	it_val.it_value.tv_usec = 0;
	it_val.it_interval = it_val.it_value;
	current_update_frequency = LRU_LIST_UPDATE_FREQUENCY_IN_SEC;

	if (setitimer(ITIMER_REAL, &it_val, NULL))
	{
		log("[sigballoon_init] Failed to set timer for update_lru_score.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	if (signal(SIGBALLOON, sigballoon_handler))
	{
		log("[sigballoon_init] Failed to register SIGBALLOON handler.", LOG_LEVEL_NO_LOG);
		exit(1);
	}

	if (syscall(442) != 0)
	{
		log("[sigballoon_init] sys_sigballon_reg returned nonzero code.", LOG_LEVEL_NO_LOG);
	 	exit(1);
	}

}



int main(int argc, char *argv[])
{
	int *ptr, nr_pages;

	ptr = mmap(NULL, TOTAL_MEMORY_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if (ptr == MAP_FAILED)
	{
		perror("mmap failed ");
		exit(1);
	}
	buff = ptr;
	memset(buff, 0, TOTAL_MEMORY_SIZE);

	/*
	 * 		placeholder-1
	 * register me with the kernel ballooning subsystem
	 */
	sigballoon_init(ptr);

	/* test-case */
	test_case_main(buff, TOTAL_MEMORY_SIZE);

	munmap(ptr, TOTAL_MEMORY_SIZE);
	printf("I received SIGBALLOON %lu times\n", nr_signals);
}
