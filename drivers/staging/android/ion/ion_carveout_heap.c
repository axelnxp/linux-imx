/*
 * drivers/staging/android/ion/ion_carveout_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
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
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include "ion.h"

#define ION_CARVEOUT_ALLOCATE_FAIL	-1

#define to_carveout_heap(x) container_of(x, struct ion_carveout_heap, heap)

struct rmem_carveout {
	phys_addr_t base;
	phys_addr_t size;
};
static struct rmem_carveout carveout_data;

struct ion_carveout_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
	phys_addr_t base;
	#ifdef CONFIG_ION_MONITOR
	size_t size;
	size_t free_size;
	size_t allocated_size;
	size_t allocated_peak;
	size_t largest_free_buf;
	#endif /* CONFIG_ION_MONITOR */
};

static phys_addr_t ion_carveout_allocate(struct ion_heap *heap,
					 unsigned long size)
{
	struct ion_carveout_heap *carveout_heap =
		container_of(heap, struct ion_carveout_heap, heap);
	unsigned long offset = gen_pool_alloc(carveout_heap->pool, size);

	if (!offset)
		return ION_CARVEOUT_ALLOCATE_FAIL;

	return offset;
}

static void ion_carveout_free(struct ion_heap *heap, phys_addr_t addr,
			      unsigned long size)
{
	struct ion_carveout_heap *carveout_heap =
		container_of(heap, struct ion_carveout_heap, heap);

	if (addr == ION_CARVEOUT_ALLOCATE_FAIL)
		return;
	gen_pool_free(carveout_heap->pool, addr, size);
}

static int ion_carveout_heap_allocate(struct ion_heap *heap,
				      struct ion_buffer *buffer,
				      unsigned long size,
				      unsigned long flags)
{
	struct sg_table *table;
	phys_addr_t paddr;
	int ret;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto err_free;

	paddr = ion_carveout_allocate(heap, size);
	if (paddr == ION_CARVEOUT_ALLOCATE_FAIL) {
		ret = -ENOMEM;
		goto err_free_table;
	}

	sg_set_page(table->sgl, pfn_to_page(PFN_DOWN(paddr)), size, 0);
	buffer->sg_table = table;

	return 0;

err_free_table:
	sg_free_table(table);
err_free:
	kfree(table);
	return ret;
}

static void ion_carveout_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	ion_heap_buffer_zero(buffer);

	ion_carveout_free(heap, paddr, buffer->size);
	sg_free_table(table);
	kfree(table);
}

static struct ion_heap_ops carveout_heap_ops = {
	.allocate = ion_carveout_heap_allocate,
	.free = ion_carveout_heap_free,
	.map_user = ion_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

#ifdef CONFIG_ION_MONITOR

/**
 * update_carveout_heap_info - Update the debug info of the heap
 * @heap: ion heap
 */
static void update_carveout_heap_info(struct ion_heap *heap)
{
	struct ion_carveout_heap *carveout_heap = to_carveout_heap(heap);

	carveout_heap->free_size = gen_pool_avail(carveout_heap->pool);
	carveout_heap->allocated_size = carveout_heap->size - carveout_heap->free_size;
	if(carveout_heap->allocated_size > carveout_heap->allocated_peak) carveout_heap->allocated_peak = carveout_heap->allocated_size;
	carveout_heap->largest_free_buf = gen_pool_largest_free_buf(carveout_heap->pool);
}

#endif /* CONFIG_ION_MONITOR */

static int ion_carveout_heap_debug_show(struct ion_heap *heap, struct seq_file *s, void *unused)
{
	#ifdef CONFIG_ION_MONITOR

	if(!heap->debug_state) {
		seq_puts(s, "\n ION monitor tool is disabled.\n");
		return 0;
	}

	seq_puts(s, "\n----- ION CARVEOUT HEAP DEBUG -----\n");

	struct ion_carveout_heap *carveout_heap = to_carveout_heap(heap);
	size_t heap_frag = 0;
	
	if(heap->type == ION_HEAP_TYPE_CARVEOUT) {
		update_carveout_heap_info(heap);

		heap_frag = ((carveout_heap->free_size - carveout_heap->largest_free_buf) * 100) / carveout_heap->free_size;

		seq_printf(s, "%19s %19x\n", "base address", carveout_heap->base);
		seq_printf(s, "%19s %19zu\n", "heap size", carveout_heap->size);
		seq_printf(s, "%19s %19zu\n", "free size", carveout_heap->free_size);
		seq_printf(s, "%19s %19zu\n", "allocated size", carveout_heap->allocated_size);
		seq_printf(s, "%19s %19zu\n", "allocated peak", carveout_heap->allocated_peak);
		seq_printf(s, "%19s %19zu\n", "largest free buffer", carveout_heap->largest_free_buf);
		seq_printf(s, "%19s %19zu\n", "heap fragmentation", heap_frag);		
	}
	else {
		pr_err("%s: Invalid heap type for debug: %d\n", __func__, heap->type);
	}
	seq_puts(s, "\n");
	#endif /* CONFIG_ION_MONITOR */
	return 0;
}

struct ion_heap *ion_carveout_heap_create(struct rmem_carveout *heap_data)
{
	struct ion_carveout_heap *carveout_heap;
	int ret;

	struct page *page;
	size_t size;

	page = pfn_to_page(PFN_DOWN(heap_data->base));
	size = heap_data->size;

	ret = ion_heap_pages_zero(page, size, pgprot_writecombine(PAGE_KERNEL));
	if (ret)
		return ERR_PTR(ret);

	carveout_heap = kzalloc(sizeof(*carveout_heap), GFP_KERNEL);
	if (!carveout_heap)
		return ERR_PTR(-ENOMEM);

	// ensure memory address align to 64K which can meet VPU requirement.
	carveout_heap->pool = gen_pool_create(PAGE_SHIFT+4, -1);
	if (!carveout_heap->pool) {
		kfree(carveout_heap);
		return ERR_PTR(-ENOMEM);
	}
	carveout_heap->base = heap_data->base;
	gen_pool_add(carveout_heap->pool, carveout_heap->base, heap_data->size,
		     -1);
	carveout_heap->heap.ops = &carveout_heap_ops;
	carveout_heap->heap.type = ION_HEAP_TYPE_CARVEOUT;
	carveout_heap->heap.flags = ION_HEAP_FLAG_DEFER_FREE;
	carveout_heap->heap.debug_show = ion_carveout_heap_debug_show;

	#ifdef CONFIG_ION_MONITOR
	
	carveout_heap->size = size;
	carveout_heap->free_size = gen_pool_avail(carveout_heap->pool);
	carveout_heap->allocated_size = carveout_heap->size - carveout_heap->free_size;
	carveout_heap->allocated_peak = carveout_heap->allocated_size;
	carveout_heap->largest_free_buf = gen_pool_largest_free_buf(carveout_heap->pool);
	carveout_heap->heap.debug_state = 1;

	#endif /* CONFIG_ION_MONITOR */

	return &carveout_heap->heap;
}

static int ion_add_carveout_heap(void)
{
	struct ion_heap *heap;

	if (carveout_data.base == 0 || carveout_data.size == 0)
		return -EINVAL;

	heap = ion_carveout_heap_create(&carveout_data);
	if (IS_ERR(heap))
		return PTR_ERR(heap);

	heap->name = "carveout";

	ion_device_add_heap(heap);
	return 0;
}

static int rmem_carveout_device_init(struct reserved_mem *rmem,
					 struct device *dev)
{
	dev_set_drvdata(dev, rmem);
	return 0;
}

static void rmem_carveout_device_release(struct reserved_mem *rmem,
					 struct device *dev)
{
	dev_set_drvdata(dev, NULL);
}

static const struct reserved_mem_ops rmem_dma_ops = {
	.device_init    = rmem_carveout_device_init,
	.device_release = rmem_carveout_device_release,
};

static int __init rmem_carveout_setup(struct reserved_mem *rmem)
{
	carveout_data.base = rmem->base;
	carveout_data.size = rmem->size;
	rmem->ops = &rmem_dma_ops;
	pr_info("Reserved memory: ION carveout pool at %pa, size %ld MiB\n",
			&rmem->base, (unsigned long)rmem->size / SZ_1M);
	return 0;
}

RESERVEDMEM_OF_DECLARE(carveout, "imx-ion-pool", rmem_carveout_setup);

device_initcall(ion_add_carveout_heap);
