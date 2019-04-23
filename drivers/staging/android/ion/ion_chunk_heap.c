/*
 * drivers/staging/android/ion/ion_chunk_heap.c
 *
 * Copyright (C) 2012 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "ion.h"

#define to_chunk_heap(x) container_of(x, struct ion_chunk_heap, heap)

struct ion_chunk_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
	phys_addr_t base;
	unsigned long chunk_size;
	unsigned long size;
	unsigned long allocated;
	#ifdef CONFIG_ION_MONITOR
	unsigned long free_size;
	unsigned long largest_free_buf;
	unsigned long allocated_peak;
	#endif /* CONFIG_ION_MONITOR */
};

static int ion_chunk_heap_allocate(struct ion_heap *heap,
				   struct ion_buffer *buffer,
				   unsigned long size,
				   unsigned long flags)
{
	struct ion_chunk_heap *chunk_heap =
		container_of(heap, struct ion_chunk_heap, heap);
	struct sg_table *table;
	struct scatterlist *sg;
	int ret, i;
	unsigned long num_chunks;
	unsigned long allocated_size;

	allocated_size = ALIGN(size, chunk_heap->chunk_size);
	num_chunks = allocated_size / chunk_heap->chunk_size;

	if (allocated_size > chunk_heap->size - chunk_heap->allocated)
		return -ENOMEM;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	ret = sg_alloc_table(table, num_chunks, GFP_KERNEL);
	if (ret) {
		kfree(table);
		return ret;
	}

	sg = table->sgl;
	for (i = 0; i < num_chunks; i++) {
		unsigned long paddr = gen_pool_alloc(chunk_heap->pool,
						     chunk_heap->chunk_size);
		if (!paddr)
			goto err;
		sg_set_page(sg, pfn_to_page(PFN_DOWN(paddr)),
			    chunk_heap->chunk_size, 0);
		sg = sg_next(sg);
	}

	buffer->sg_table = table;
	chunk_heap->allocated += allocated_size;
	return 0;
err:
	sg = table->sgl;
	for (i -= 1; i >= 0; i--) {
		gen_pool_free(chunk_heap->pool, page_to_phys(sg_page(sg)),
			      sg->length);
		sg = sg_next(sg);
	}
	sg_free_table(table);
	kfree(table);
	return -ENOMEM;
}

static void ion_chunk_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct ion_chunk_heap *chunk_heap =
		container_of(heap, struct ion_chunk_heap, heap);
	struct sg_table *table = buffer->sg_table;
	struct scatterlist *sg;
	int i;
	unsigned long allocated_size;

	allocated_size = ALIGN(buffer->size, chunk_heap->chunk_size);

	ion_heap_buffer_zero(buffer);

	for_each_sg(table->sgl, sg, table->nents, i) {
		gen_pool_free(chunk_heap->pool, page_to_phys(sg_page(sg)),
			      sg->length);
	}
	chunk_heap->allocated -= allocated_size;
	sg_free_table(table);
	kfree(table);
}

static struct ion_heap_ops chunk_heap_ops = {
	.allocate = ion_chunk_heap_allocate,
	.free = ion_chunk_heap_free,
	.map_user = ion_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

#ifdef CONFIG_ION_MONITOR

/**
 * update_chunk_heap_info - Update the debug info of the heap
 * @heap: ion heap
 */
static void update_chunk_heap_info(struct ion_heap *heap)
{
	struct ion_chunk_heap *chunk_heap = to_chunk_heap(heap);

	chunk_heap->free_size = gen_pool_avail(chunk_heap->pool);
	if(chunk_heap->allocated > chunk_heap->allocated_peak) chunk_heap->allocated_peak = chunk_heap->allocated;
	chunk_heap->largest_free_buf = gen_pool_largest_free_buf(chunk_heap->pool);
}

#endif /* CONFIG_ION_MONITOR */

static int ion_chunk_heap_debug_show(struct ion_heap *heap, struct seq_file *s, void *unused)
{
	#ifdef CONFIG_ION_MONITOR

	if(!heap->debug_state) {
		seq_puts(s, "\n ION monitor tool is disabled.\n");
		return 0;
	}

	seq_puts(s, "\n----- ION CHUNK HEAP DEBUG -----\n");

	struct ion_chunk_heap *chunk_heap = to_chunk_heap(heap);
	size_t heap_frag = 0;
	
	if(heap->type == ION_HEAP_TYPE_CHUNK) {
		update_chunk_heap_info(heap);

		heap_frag = ((chunk_heap->free_size - chunk_heap->largest_free_buf) * 100) / chunk_heap->free_size;

		seq_printf(s, "%19s %19x\n", "base address", chunk_heap->base);
		seq_printf(s, "%19s %19zu\n", "heap size", chunk_heap->size);
		seq_printf(s, "%19s %19zu\n", "chunk size", chunk_heap->chunk_size);
		seq_printf(s, "%19s %19zu\n", "free size", chunk_heap->free_size);
		seq_printf(s, "%19s %19zu\n", "allocated size", chunk_heap->allocated);
		seq_printf(s, "%19s %19zu\n", "allocated peak", chunk_heap->allocated_peak);
		seq_printf(s, "%19s %19zu\n", "largest free buffer", chunk_heap->largest_free_buf);
		seq_printf(s, "%19s %19zu\n", "heap fragmentation", heap_frag);		
	}
	else {
		pr_err("%s: Invalid heap type for debug: %d\n", __func__, heap->type);
	}
	seq_puts(s, "\n");

	#endif /* CONFIG_ION_MONITOR */
	return 0;
}

struct ion_heap *ion_chunk_heap_create(struct ion_platform_heap *heap_data)
{
	struct ion_chunk_heap *chunk_heap;
	int ret;
	struct page *page;
	size_t size;

	page = pfn_to_page(PFN_DOWN(heap_data->base));
	size = heap_data->size;

	ret = ion_heap_pages_zero(page, size, pgprot_writecombine(PAGE_KERNEL));
	if (ret)
		return ERR_PTR(ret);

	chunk_heap = kzalloc(sizeof(*chunk_heap), GFP_KERNEL);
	if (!chunk_heap)
		return ERR_PTR(-ENOMEM);

	chunk_heap->chunk_size = (unsigned long)heap_data->priv;
	chunk_heap->pool = gen_pool_create(get_order(chunk_heap->chunk_size) +
					   PAGE_SHIFT, -1);
	if (!chunk_heap->pool) {
		ret = -ENOMEM;
		goto error_gen_pool_create;
	}
	chunk_heap->base = heap_data->base;
	chunk_heap->size = heap_data->size;
	chunk_heap->allocated = 0;

	gen_pool_add(chunk_heap->pool, chunk_heap->base, heap_data->size, -1);
	chunk_heap->heap.ops = &chunk_heap_ops;
	chunk_heap->heap.type = ION_HEAP_TYPE_CHUNK;
	chunk_heap->heap.flags = ION_HEAP_FLAG_DEFER_FREE;
	chunk_heap->heap.debug_show = ion_chunk_heap_debug_show;
	pr_debug("%s: base %pa size %zu\n", __func__,
		 &chunk_heap->base, heap_data->size);

	#ifdef CONFIG_ION_MONITOR

	chunk_heap->free_size = gen_pool_avail(chunk_heap->pool);
	chunk_heap->allocated_peak = chunk_heap->allocated;
	chunk_heap->largest_free_buf = gen_pool_largest_free_buf(chunk_heap->pool);
	chunk_heap->heap.debug_state = 1;
	
	#endif /* CONFIG_ION_MONITOR */ 

	return &chunk_heap->heap;

error_gen_pool_create:
	kfree(chunk_heap);
	return ERR_PTR(ret);
}

