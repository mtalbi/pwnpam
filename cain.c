#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define PAGE_NB 256

/* from https://github.com/felixwilhelm/mario_baslr */
uint64_t rdtsc() {
	uint32_t high, low;
	asm volatile(".att_syntax\n\t"
		"RDTSCP\n\t"
		: "=a"(low), "=d"(high)::);
	return ((uint64_t)high << 32) | low;
}

int main()
{
	void *buffer, *half;
	int page_size = sysconf(_SC_PAGESIZE);
	size_t size =  page_size * PAGE_NB;

	buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	madvise(buffer, size, MADV_MERGEABLE);

	srand(time(NULL));

	size_t i;
	for (i = 0; i < PAGE_NB; i++)
		*(uint32_t *)(buffer + (page_size * i)) = rand();

	half = buffer + (page_size * (PAGE_NB / 2));
	for (i = 0; i < (PAGE_NB / 2); i += 2)
		memcpy(buffer + (page_size * i), half + (page_size * i), page_size);

	sleep(10);

	uint64_t start, end;
	for (i = 0; i < (PAGE_NB / 2); i++) {
		start = rdtsc();
		*(uint8_t *)(buffer + (page_size * i)) = '\xff';
		end = rdtsc();
		printf("[+] page modification took %" PRIu64 " cycles\n", end - start);
	}

	return 0;
}
