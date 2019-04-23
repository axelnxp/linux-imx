/*
 * drivers/staging/android/ion/ion_cma_heap.c
 *
 * Copyright (C) Linaro 2012
 * Author: <benjamin.gaignard@linaro.org> for ST-Ericsson.
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

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cma.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>

#include "ion.h"

struct ion_cma_heap {
	struct ion_heap heap;
	struct cma *cma;

	#ifdef CONFIG_ION_MONITOR
	size_t heap_size;
	size_t free_size;
	size_t allocated_size;
	size_t allocated_peak;
	size_t largest_free_buf;
	#endif /* CONFIG_ION_MONITOR */
};

#define to_cma_heap(x) container_of(x, struct ion_cma_heap, heap)

/* ION CMA heap operations functions */
static int ion_cma_allocate(struct ion_heap *heap, struct ion_buffer *buffer,
			    unsigned long len,
			    unsigned long flags)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(heap);
	struct sg_table *table;
	struct page *pages;
	unsigned long size = PAGE_ALIGN(len);
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long align = get_order(size);
	int ret;

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	pages = cma_alloc(cma_heap->cma, nr_pages, align, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	if (PageHighMem(pages)) {
		unsigned long nr_clear_pages = nr_pages;
		struct page *page = pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(pages), 0, size);
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, size, 0);

	buffer->priv_virt = pages;
	buffer->sg_table = table;
	return 0;

free_mem:
	kfree(table);
err:
	cma_release(cma_heap->cma, pages, nr_pages);
	return -ENOMEM;
}

static void ion_cma_free(struct ion_buffer *buffer)
{
	struct ion_cma_heap *cma_heap = to_cma_heap(buffer->heap);
	struct page *pages = buffer->priv_virt;
	unsigned long nr_pages = PAGE_ALIGN(buffer->size) >> PAGE_SHIFT;

	/* release memory */
	cma_release(cma_heap->cma, pages, nr_pages);
	/* release sg table */
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
}

static struct ion_heap_ops ion_cma_ops = {
	.allocate = ion_cma_allocate,
	.free = ion_cma_free,
	.map_user = ion_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

#ifdef CONFIG_ION_MONITOR
static void update_cma_heap_info(struct ion_heap* heap) 
{
	struct ion_cma_heap *cma_heap;
	cma_heap = to_cma_heap(heap);

	cma_heap->heap_size = cma_get_size(cma_heap->cma);
	cma_heap->free_size = cma_get_free_size(cma_heap->cma);
	cma_heap->allocated_size = cma_heap->heap_size - cma_heap->free_size;
	if(cma_heap->allocated_size > cma_heap->allocated_peak) cma_heap->allocated_peak = cma_heap->allocated_size;
	cma_heap->largest_free_buf = cma_get_largest_free_buf(cma_heap->cma);
}
#endif /* CONFIG_ION_MONITOR */ 

static int ion_cma_heap_debug_show(struct ion_heap *heap, struct seq_file *s, void *unused)
{
	#ifdef CONFIG_ION_MONITOR

	if(!heap->debug_state) {
		seq_puts(s, "\n ION monitor tool is disabled.\n");
		return 0;
	}

	struct ion_cma_heap *cma_heap;
	size_t heap_frag;

	cma_heap = to_cma_heap(heap);
	
	seq_puts(s, "\n----- ION CMA HEAP DEBUG -----\n");

	if(heap->type == ION_HEAP_TYPE_DMA) {
		update_cma_heap_info(heap);

		heap_frag = ((cma_heap->free_size - cma_heap->largest_free_buf) * 100) / cma_heap->free_size;

		seq_printf(s, "%19s %19zu\n", "heap size", cma_heap->heap_size);
		seq_printf(s, "%19s %19zu\n", "free size", cma_heap->free_size);
		seq_printf(s, "%19s %19zu\n", "allocated size", cma_heap->allocated_size);
		seq_printf(s, "%19s %19zu\n", "allocated peak", cma_heap->allocated_peak);
		seq_printf(s, "%19s %19zu\n", "largest free buffer", cma_heap->largest_free_buf);
		seq_printf(s, "%19s %19zu\n", "heap fragmentation", heap_frag);
	}
	else {
		pr_err("%s: Invalid heap type for debug: %d\n", __func__, heap->type);
	}
	seq_puts(s, "\n");
	#endif /* CONFIG_ION_MONITOR */
	return 0;
}

static struct ion_heap *__ion_cma_heap_create(struct cma *cma)
{
	struct ion_cma_heap *cma_heap;

	cma_heap = kzalloc(sizeof(*cma_heap), GFP_KERNEL);

	if (!cma_heap)
		return ERR_PTR(-ENOMEM);

	cma_heap->heap.ops = &ion_cma_ops;
	/*
	 * get device from private heaps data, later it will be
	 * used to make the link with reserved CMA memory
	 */
	cma_heap->cma = cma;
	cma_heap->heap.type = ION_HEAP_TYPE_DMA;

	#ifdef CONFIG_ION_MONITOR
	cma_heap->heap.debug_show = ion_cma_heap_debug_show;
	cma_heap->heap.name = cma_get_name(cma);
	cma_heap->heap.debug_state = 1;
	cma_heap->heap_size = cma_get_size(cma_heap->cma);
	cma_heap->free_size = cma_get_free_size(cma_heap->cma);
	cma_heap->allocated_size = cma_heap->heap_size - cma_heap->free_size;
	cma_heap->allocated_peak = cma_heap->allocated_size;
	cma_heap->largest_free_buf = cma_get_largest_free_buf(cma_heap->cma);
	#endif /* CONFIG_ION_MONITOR */

	return &cma_heap->heap;
}

static int __ion_add_cma_heaps(struct cma *cma, void *data)
{
	struct ion_heap *heap;

	heap = __ion_cma_heap_create(cma);
	if (IS_ERR(heap))
		return PTR_ERR(heap);

	heap->name = cma_get_name(cma);

	ion_device_add_heap(heap);
	return 0;
}

static int ion_add_cma_heaps(void)
{
	cma_for_each_area(__ion_add_cma_heaps, NULL);
	return 0;
}
device_initcall(ion_add_cma_heaps);
