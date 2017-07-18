//
//  lfalloc.cpp
//  lfalloc_test
//
//  Created by hari on 09/07/17.
//  Copyright © 2017 hari. All rights reserved.
//

// uncomment to disable assert()
// #define NDEBUG
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <cstdio>
#include <iostream>

#include "lfalloc.h"
#include "ilist.h"

#include <sys/mman.h>
#include <unistd.h>

// From postgres.h
#define TYPEALIGN(ALIGNVAL,LEN)	\
			(((uintptr_t) (LEN) + ((ALIGNVAL) - 1)) & ~((uintptr_t) ((ALIGNVAL) - 1)))
#define AssertPointerAlignment(ptr, bndr) \
			assert(TYPEALIGN(bndr, (uintptr_t)(ptr)) == (uintptr_t)(ptr) && "UnalignedPointer")


#define CACHE_LINE_SIZE			64
#define CACHE_LINE_SIZE_BITS	6
#define SLAB_BLOCKS_PER_CHUNK	64

// Current Hard Limit is 64 GB
#define SLAB_MAX_RESERVE_MEMORY (64 * 1024 * 1024 * 1024UL)
#define SLAB_BLOCK_SIZE			(64 * 1024L)

#define SLAB_MAX_ALLOC_SIZE			(1 * 1024)
#define SLABINC						16
#define SLAB_MAX					(SLAB_MAX_ALLOC_SIZE / SLABINC)
#define MaxSlabChunks(slab_max_mem) \
				((reinterpret_cast<long>(slab_max_mem) * 1.0) / (sizeof(slab_chunk) + \
											SLAB_BLOCK_SIZE * SLAB_BLOCKS_PER_CHUNK))

#define SlabSizeAlign(LEN)	TYPEALIGN(SLAB_BLOCK_SIZE, LEN)

struct
{
	int page_size;
} common;

struct
{
	char	*sbrk_base;
	char	*sbrk_end;
	size_t	sbrk_size;
} sbrk_data;

struct slabheader
{
	dlist_node	node;
	dlist_head	free_list;
	size_t		alloc_size;
	unsigned	slab_available_slots;
	unsigned	slab_max_slots;
	char		data[];
} __attribute__ ((aligned(16)));

struct slab_chunk
{
	dlist_node	node;
	dlist_head	freelist;
	unsigned	start_block;
	unsigned	used_blocks_count;
} __attribute__ ((aligned(CACHE_LINE_SIZE)));

struct
{
	slab_chunk *schunk;
	slabheader *slab_start;
	unsigned total_chunks;
	unsigned total_usable_blocks;

	dlist_head free_list;
	dlist_head inuse_list;

	slabheader *slab[SLAB_MAX];

	bool oom;
} slab_data;

static void *sys_alloc(size_t size);
static int init_sbrk(size_t max_slab_reserve);
static size_t page_align(size_t s);

static int init_slab(void);
static slabheader *get_slab_header(slabheader *slabs, unsigned i);
static unsigned get_slab(size_t size);
static slabheader *get_slab(void *p);
static slab_chunk *get_slab_chunk(slabheader *slab);

static void *slab_alloc(size_t size);
static void slab_free(void *p);

static slabheader *slab_alloc_block(size_t alloc_size);
static void slab_free_block(slabheader *slab);

static slab_chunk *slab_alloc_chunk(void);
static void slab_free_chunk(slab_chunk *schunk);


int lfmalloc_init(size_t max_slab_reserve)
{
	int rc;

	rc = init_sbrk(max_slab_reserve);

	if (rc)
		return rc;

	return init_slab();
}

int lfmalloc_init_default(void)
{
	return lfmalloc_init(SLAB_MAX_RESERVE_MEMORY);
}

void *lfmalloc(size_t size)
{
	return slab_alloc(size);
}

void lffree(void *ptr)
{
	slab_free(ptr);
}

void *lfrealloc(void *ptr, size_t newsize)
{
	void *newp = lfmalloc(newsize);
	slabheader *slab = get_slab(ptr);

	memcpy(newp, ptr, slab->alloc_size);
	slab_free(ptr);

	return newp;
}

static int
init_slab(void)
{
	unsigned max_chunks;
	long chunks_data_size;
	unsigned blockno;
	slab_chunk *chunk;
	void *chunk_header_end;

	StaticAssertStmt(sizeof(slab_chunk) == CACHE_LINE_SIZE,
					 "sizeof slab_chunk must be cache aligned");

	if (sbrk_data.sbrk_base == NULL)
		return -1;

	slab_data.schunk = reinterpret_cast<slab_chunk *>(sbrk_data.sbrk_base);

	dlist_init(&slab_data.free_list);
	dlist_init(&slab_data.inuse_list);
	slab_data.oom = false;

	max_chunks = MaxSlabChunks(sbrk_data.sbrk_end - sbrk_data.sbrk_base);
	chunks_data_size = max_chunks * sizeof(slab_chunk);
	chunks_data_size = SlabSizeAlign(chunks_data_size) >= chunks_data_size ?
							SlabSizeAlign(chunks_data_size) - SLAB_BLOCK_SIZE : chunks_data_size;

	max_chunks = unsigned(chunks_data_size / sizeof(slab_chunk));
	blockno = 0;

	slab_data.total_chunks = max_chunks;

	for (unsigned i = 0; i < max_chunks; i++)
	{
		chunk = slab_data.schunk + i;

		chunk->used_blocks_count = 0;
		chunk->start_block = blockno;
		blockno += SLAB_BLOCKS_PER_CHUNK;

		dlist_push_head(&slab_data.free_list, &chunk->node);
	}

	slab_data.total_usable_blocks = blockno;

	madvise(sbrk_data.sbrk_base + common.page_size, sbrk_data.sbrk_size - common.page_size,
			MADV_DONTNEED);

	chunk_header_end = sbrk_data.sbrk_base + sizeof(slab_chunk) * long(max_chunks);
	chunk_header_end = (void *) SlabSizeAlign(chunk_header_end);
	slab_data.slab_start = static_cast<slabheader *>(chunk_header_end);

	return 0;
}

static slabheader *
get_slab_header(slabheader *slabs, unsigned i)
{
	char *slab_start = reinterpret_cast<char *>(slab_data.slab_start);

	Assert(i < SLAB_MAX_RESERVE_MEMORY / SLAB_BLOCK_SIZE);

	return reinterpret_cast<slabheader *>(slab_start + long(i) * SLAB_BLOCK_SIZE);
}

static unsigned
get_slab(size_t size)
{
	Assert(size <= SLAB_MAX_ALLOC_SIZE);

	return unsigned(size) / SLABINC;
}

static slabheader *
get_slab(void *p)
{
	return reinterpret_cast<slabheader *>(SlabSizeAlign(p) - SLAB_BLOCK_SIZE);
}

static slab_chunk *
get_slab_chunk(slabheader *slab)
{
	unsigned chunk;

	AssertPointerAlignment(slab, SLAB_BLOCK_SIZE);

	chunk = (unsigned(reinterpret_cast<char *>(slab) -
					  reinterpret_cast<char *>(slab_data.slab_start)) / SLAB_BLOCK_SIZE)
						/ SLAB_BLOCKS_PER_CHUNK;

	Assert(chunk < slab_data.total_chunks);

	return slab_data.schunk + chunk;
}

static void *
slab_alloc(size_t size)
{
	unsigned slabno;
	slabheader *slab;

	Assert(size <= SLAB_MAX_ALLOC_SIZE);

	slabno = get_slab(size);
	slab = slab_data.slab[slabno];

	if (slab == NULL)
	{
		slab = slab_alloc_block((slabno + 1) * SLABINC);
		slab_data.slab[slabno] = slab;
	}

	if (dlist_is_empty(&slab->free_list))
	{
		Assert(slab->slab_available_slots <= slab->slab_max_slots);

		if (slab->slab_available_slots)
		{
			slab->slab_available_slots--;
			return slab->data + slab->slab_available_slots * slab->alloc_size;
		}

		slab = slab_alloc_block((slabno + 1) * SLABINC);
		slab->slab_available_slots--;
		slab_data.slab[slabno] = slab;

		return slab->data + slab->slab_available_slots * slab->alloc_size;
	}

	return dlist_pop_head_node(&slab->free_list);
}

static void
slab_free(void *p)
{
	slabheader *slab = get_slab(p);

	slab->slab_available_slots++;

	if (slab->slab_available_slots == slab->slab_max_slots)
		slab_free_block(slab);
	else
		dlist_push_head(&slab->free_list, reinterpret_cast<dlist_node *>(p));
}

static slabheader *
slab_alloc_block(size_t alloc_size)
{
	slab_chunk *chunk;
	slabheader *slab;

	if (dlist_is_empty(&slab_data.inuse_list))
	{
		chunk = slab_alloc_chunk();

		if (chunk == NULL)
			return NULL;
	}
	else
	{
		chunk = dlist_head_element(slab_chunk, node, &slab_data.inuse_list);
	}

	if (chunk->used_blocks_count == SLAB_BLOCKS_PER_CHUNK)
	{
		chunk = slab_alloc_chunk();

		if (chunk == NULL)
			return NULL;
	}

	if (dlist_is_empty(&chunk->freelist))
	{
		Assert(chunk->used_blocks_count < SLAB_BLOCKS_PER_CHUNK);

		slab = get_slab_header(slab_data.slab_start, chunk->start_block +
							   chunk->used_blocks_count++);
		slab->alloc_size = alloc_size;
		slab->slab_max_slots = (SLAB_BLOCK_SIZE - sizeof(slabheader)) / alloc_size;
		slab->slab_available_slots = slab->slab_max_slots;
		dlist_init(&slab->free_list);

		return slab;
	}

	chunk->used_blocks_count++;

	slab = dlist_container(slabheader, node, dlist_pop_head_node(&chunk->freelist));
	slab->alloc_size = alloc_size;
	slab->slab_max_slots = (SLAB_BLOCK_SIZE - sizeof(slabheader)) / alloc_size;
	slab->slab_available_slots = slab->slab_max_slots;
	dlist_init(&slab->free_list);

	return slab;
}

static void
slab_free_block(slabheader *slab)
{
	slab_chunk *chunk;

	AssertPointerAlignment(slab, SLAB_BLOCK_SIZE);
	Assert(!dlist_is_empty(&slab_data.inuse_list));

	chunk = get_slab_chunk(slab);
	chunk->used_blocks_count--;

	dlist_push_head(&chunk->freelist, &slab->node);

	slab->slab_max_slots = slab->alloc_size = slab->slab_available_slots = 0;
	dlist_init(&slab->free_list);

	if (chunk->used_blocks_count == 0)
		slab_free_chunk(chunk);
}

static slab_chunk *
slab_alloc_chunk(void)
{
	slab_chunk *chunk;

	Assert(!dlist_is_empty(&slab_data.free_list));

	chunk = dlist_head_element(slab_chunk, node, &slab_data.free_list);

	dlist_pop_head_node(&slab_data.free_list);
	dlist_push_head(&slab_data.inuse_list, &chunk->node);

	chunk->used_blocks_count = 0;

	std::cout << chunk << '\n';

	return chunk;
}

static void
slab_free_chunk(slab_chunk *chunk)
{
	AssertPointerAlignment(chunk, sizeof(slab_chunk));
	Assert(chunk->used_blocks_count == 0);

	dlist_delete(&chunk->node);
	dlist_push_head(&slab_data.free_list, &chunk->node);
	chunk->used_blocks_count = 0;

	for (unsigned block = 0; block < SLAB_BLOCKS_PER_CHUNK; block++)
	{
		madvise(get_slab_header(slab_data.slab_start, chunk->start_block + block),
				SLAB_BLOCK_SIZE, MADV_DONTNEED);
	}
}


static int
init_sbrk(size_t max_slab_reserve)
{
	void *brk_ptr;

	assert(common.page_size == 0);

	common.page_size = getpagesize();
	max_slab_reserve = page_align(max_slab_reserve);

	if (max_slab_reserve > SLAB_MAX_RESERVE_MEMORY)
		max_slab_reserve = SLAB_MAX_RESERVE_MEMORY;

	brk_ptr = sys_alloc(max_slab_reserve);

	if (brk_ptr == MAP_FAILED)
	{
		perror("mmap");
		return -1;
	}

	sbrk_data.sbrk_base = static_cast<char *>(brk_ptr);
	sbrk_data.sbrk_end = sbrk_data.sbrk_base + max_slab_reserve;
	sbrk_data.sbrk_size = max_slab_reserve;

	return 0;
}

static void *
sys_alloc(size_t size)
{
	return mmap(NULL, page_align(size), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
}

static size_t
page_align(size_t s)
{
	assert(common.page_size != 0);

	return TYPEALIGN(common.page_size, s);
}
