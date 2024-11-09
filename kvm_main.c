/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "iodev.h"

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/kvm_para.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

#include <asm/processor.h>
#include <asm/io.h>
#include <asm/ioctl.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

#include "coalesced_mmio.h"
#include "async_pf.h"

#define CREATE_TRACE_POINTS
#include <trace/events/kvm.h>

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

/*
 * Ordering of locks:
 *
 * 		kvm->lock --> kvm->slots_lock --> kvm->irq_lock
 */

DEFINE_RAW_SPINLOCK(kvm_lock);
LIST_HEAD(vm_list);

static cpumask_var_t cpus_hardware_enabled;
static int kvm_usage_count = 0;
static atomic_t hardware_enable_failed;

struct kmem_cache *kvm_vcpu_cache;
EXPORT_SYMBOL_GPL(kvm_vcpu_cache);

static __read_mostly struct preempt_ops kvm_preempt_ops;

struct dentry *kvm_debugfs_dir;

static long kvm_vcpu_ioctl(struct file *file, unsigned int ioctl,
			   unsigned long arg);
#ifdef CONFIG_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *file, unsigned int ioctl,
				  unsigned long arg);
#endif
static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void kvm_io_bus_destroy(struct kvm_io_bus *bus);

bool kvm_rebooting;
EXPORT_SYMBOL_GPL(kvm_rebooting);

static bool largepages_enabled = false;

/* Siqi
static bool largepages_enabled = true;
*/

static struct page *hwpoison_page;
static pfn_t hwpoison_pfn;

struct page *fault_page;
pfn_t fault_pfn;

/* <Siqi> */
#include <asm/desc.h>
#include <asm/apic.h>
LIST_HEAD(pt_page);
LIST_HEAD(non_leaf_page);
volatile int exit_flg;
EXPORT_SYMBOL_GPL (exit_flg);
struct task_struct* target_proc;
volatile pid_t target_vm_pid;
EXPORT_SYMBOL_GPL (target_vm_pid);

volatile struct kvm_vcpu* imee_vcpu;
EXPORT_SYMBOL_GPL (imee_vcpu);
volatile struct kvm* target_kvm;
EXPORT_SYMBOL_GPL (target_kvm);

spinlock_t sync_lock;
EXPORT_SYMBOL_GPL(sync_lock);
volatile unsigned char go_flg;
EXPORT_SYMBOL_GPL(go_flg);
volatile int imee_pid;
EXPORT_SYMBOL_GPL(imee_pid);
volatile int last_cr3;
EXPORT_SYMBOL_GPL(last_cr3);
volatile int switched_cr3;
EXPORT_SYMBOL_GPL(switched_cr3);
struct desc_ptr imee_idt, imee_gdt;
EXPORT_SYMBOL_GPL(imee_idt);
EXPORT_SYMBOL_GPL(imee_gdt);
struct kvm_segment imee_tr;
EXPORT_SYMBOL_GPL(imee_tr);

volatile int demand_switch;
EXPORT_SYMBOL_GPL(demand_switch);

unsigned long long* code_ept_pte_p;
unsigned long long code_ept_pte;
unsigned long long* data_ept_pte_p;
unsigned long long data_ept_pte;

int enable_notifier;
volatile int do_switch;
EXPORT_SYMBOL_GPL(do_switch);

#define NBASE 4
void* p_bases[NBASE];
void* p_base;
int p_base_idx;
int p_idx;
#define PAGE_ORDER 10

ulong code_hpa, data_hpa;

struct arg_blk 
{
    ulong cr3; 
    ulong num_x_page;
    ulong num_w_page;
    ulong offset;
    ulong code_host;
    ulong data_host;
    ulong stack;
    ulong entry;
    ulong int_handler;
    ulong thunk;
    ulong got;
    ulong got_len;
    ulong gotplt;
    ulong gotplt_len;
};

struct arg_blk imee_arg;

struct region 
{
    u32 start;
    u32 end;
    int type;
};

void change_imee_ept (ulong hva, pte_t pte);
void invalidate_imee_ept (ulong gpa);

// 64bit guest, 64bit host
// #define GPA_MASK (0xFFFUL | (1UL << 63))
// 32bit guest, 64bit host
// #define GPA_MASK (0xFFFU)
// 32bit guest, 32bit host
#define GPA_MASK (0xFFFU)
// 32bit PAE guest...
// ...

// 64bit
// #define HPA_MASK (0xFFFUL | (1UL << 63))
// 32bit
#define HPA_MASK (0xFFFU)
// 32bit PAE
// #define HPA_MASK (0xFFFULL | (1ULL << 63))

// 64bit
// #define EPT_MASK (0xFFFUL | (1UL << 63))
// 32bit
#define EPT_MASK (0xFFFULL | (1ULL << 63))

// #define DBG(fmt, ...) \
//     do {printk ("%s():" fmt, __func__, ##__VA_ARGS__); } while (0)
    
#define DBG(fmt, ...) 

static __attribute__((always_inline)) unsigned long long rdtsc(void)
{
    unsigned long long x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}
unsigned long long t0, t1;
unsigned long long total_cycle;
unsigned long long setup_cycle;

unsigned long long t[100];
int cycle_idx = 0;

unsigned long long* ts_buffer;
EXPORT_SYMBOL_GPL(ts_buffer);
volatile int ts_buffer_idx;
EXPORT_SYMBOL_GPL(ts_buffer_idx);

int __tmp_counter1;
int __tmp_counter2;
int __tmp_counter4;
int __tmp_counter5;

int __tmp_counter3;
EXPORT_SYMBOL_GPL(__tmp_counter3);
int __tmp_counter;
EXPORT_SYMBOL_GPL(__tmp_counter);
/* </Siqi> */

inline int kvm_is_mmio_pfn(pfn_t pfn)
{
	if (pfn_valid(pfn)) {
		int reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_trans_head(tail);
		reserved = PageReserved(head);
		if (head != tail) {
			/*
			 * "head" is not a dangling pointer
			 * (compound_trans_head takes care of that)
			 * but the hugepage may have been splitted
			 * from under us (and we may not hold a
			 * reference count on the head page so it can
			 * be reused before we run PageReferenced), so
			 * we've to check PageTail before returning
			 * what we just read.
			 */
			smp_rmb();
			if (PageTail(tail))
				return reserved;
		}
		return PageReserved(tail);
	}

	return true;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
void vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu;

	mutex_lock(&vcpu->mutex);
	if (unlikely(vcpu->pid != current->pids[PIDTYPE_PID].pid)) {
		/* The thread running this VCPU changed. */
		struct pid *oldpid = vcpu->pid;
		struct pid *newpid = get_task_pid(current, PIDTYPE_PID);
		rcu_assign_pointer(vcpu->pid, newpid);
		synchronize_rcu();
		put_pid(oldpid);
	}
	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	kvm_arch_vcpu_load(vcpu, cpu);
	put_cpu();
}

void vcpu_put(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	kvm_arch_vcpu_put(vcpu);
	preempt_notifier_unregister(&vcpu->preempt_notifier);
	preempt_enable();
	mutex_unlock(&vcpu->mutex);
}

static void ack_flush(void *_completed)
{
}

static bool make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i, cpu, me;
	cpumask_var_t cpus;
	bool called = true;
	struct kvm_vcpu *vcpu;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = get_cpu();
	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode */
		smp_mb();

		if (cpus != NULL && cpu != -1 && cpu != me &&
		      kvm_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE)
			cpumask_set_cpu(cpu, cpus);
	}
	if (unlikely(cpus == NULL))
		smp_call_function_many(cpu_online_mask, ack_flush, NULL, 1);
	else if (!cpumask_empty(cpus))
		smp_call_function_many(cpus, ack_flush, NULL, 1);
	else
		called = false;
	put_cpu();
	free_cpumask_var(cpus);
	return called;
}

void kvm_flush_remote_tlbs(struct kvm *kvm)
{
	int dirty_count = kvm->tlbs_dirty;

	smp_mb();
	if (make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		++kvm->stat.remote_tlb_flush;
	cmpxchg(&kvm->tlbs_dirty, dirty_count, 0);
}

void kvm_reload_remote_mmus(struct kvm *kvm)
{
	make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

int kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	struct page *page;
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->pid = NULL;
	init_waitqueue_head(&vcpu->wq);
	kvm_async_pf_vcpu_init(vcpu);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		r = -ENOMEM;
		goto fail;
	}
	vcpu->run = page_address(page);

	r = kvm_arch_vcpu_init(vcpu);
	if (r < 0)
		goto fail_free_run;
	return 0;

fail_free_run:
	free_page((unsigned long)vcpu->run);
fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_init);

void kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	put_pid(vcpu->pid);
	kvm_arch_vcpu_uninit(vcpu);
	free_page((unsigned long)vcpu->run);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_uninit);

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return container_of(mn, struct kvm, mmu_notifier);
}

int ncnt;

static void kvm_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
					     struct mm_struct *mm,
					     unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush, idx;

    /* <Siqi> */
    if (imee_vcpu && kvm == imee_vcpu->kvm)
        return;
    /* ??? update imee's page table first, it's a MUST */
    // if (imee_pid && kvm == target_kvm && ncnt < 100)
    if (enable_notifier && kvm == target_kvm)
    {
        DBG ("mmu_notifier_invalidate_page on target VM, pid: %d, hva: %lX\n", target_proc->pid, address);
        DBG ("called from: %s\n", current->comm);
        // printk (KERN_ERR "mmu_notifier_invalidate_page on target VM, pid: %d\n", current->pid);
        spin_lock (&imee_vcpu->kvm->mmu_lock);
        invalidate_imee_ept (address);
        // ncnt ++;
        spin_unlock (&imee_vcpu->kvm->mmu_lock);
    }
    /* </Siqi> */

	/*
	 * When ->invalidate_page runs, the linux pte has been zapped
	 * already but the page is still allocated until
	 * ->invalidate_page returns. So if we increase the sequence
	 * here the kvm page fault will notice if the spte can't be
	 * established because the page is going to be freed. If
	 * instead the kvm page fault establishes the spte before
	 * ->invalidate_page runs, kvm_unmap_hva will release it
	 * before returning.
	 *
	 * The sequence increase only need to be seen at spin_unlock
	 * time, and not at spin_lock time.
	 *
	 * Increasing the sequence after the spin_unlock would be
	 * unsafe because the kvm page fault could then establish the
	 * pte after kvm_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	kvm->mmu_notifier_seq++;
	need_tlb_flush = kvm_unmap_hva(kvm, address) | kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

    /* <Siqi> */
    if (imee_vcpu && kvm == imee_vcpu->kvm)
        return;
    // if (imee_pid && kvm == target_kvm && ncnt < 100)
    if (enable_notifier && kvm == target_kvm)
    {
        DBG ("mmu_notifier_change_pte on target VM, pid: %d, hva: %lX, pte: %lX\n", 
                target_proc->pid, address, pte);
        DBG ("called from: %s\n", current->comm);
        spin_lock (&imee_vcpu->kvm->mmu_lock);
        change_imee_ept (address, pte);
        // ncnt ++;
        spin_unlock (&imee_vcpu->kvm->mmu_lock);
    }
    /* </Siqi> */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush = 0, idx;

    /* <Siqi> */
    if (imee_vcpu && kvm == imee_vcpu->kvm)
        return;
    // if (imee_pid && kvm == target_kvm && ncnt < 100)
    if (enable_notifier && kvm == target_kvm)
    {
        DBG ("mmu_notifier_invalidate_range_start on target VM, pid: %d start: %lX, end: %lX\n", 
               target_proc->pid, start, end);
        DBG ("called from: %s\n", current->comm);
        spin_lock (&imee_vcpu->kvm->mmu_lock);
        ulong temp = start; // the loop below changes __start__, don't touch it
        for (; temp < end; temp += PAGE_SIZE)
            invalidate_imee_ept (temp);
        // ncnt ++;
        spin_unlock (&imee_vcpu->kvm->mmu_lock);
    }
    /* </Siqi> */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	for (; start < end; start += PAGE_SIZE)
		need_tlb_flush |= kvm_unmap_hva(kvm, start);
	need_tlb_flush |= kvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	spin_lock(&kvm->mmu_lock);
	/*
	 * This sequence increase will notify the kvm page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	kvm->mmu_notifier_seq++;
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease but both values are read by the kvm
	 * page fault under mmu_lock spinlock so we don't need to add
	 * a smb_wmb() here in between the two.
	 */
	kvm->mmu_notifier_count--;
	spin_unlock(&kvm->mmu_lock);

	BUG_ON(kvm->mmu_notifier_count < 0);
}

static int kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);

	young = kvm_age_hva(kvm, address);
	if (young)
		kvm_flush_remote_tlbs(kvm);

	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static int kvm_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	young = kvm_test_age_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	return young;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.invalidate_page	= kvm_mmu_notifier_invalidate_page,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.test_young		= kvm_mmu_notifier_test_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
	.release		= kvm_mmu_notifier_release,
};

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, current->mm);
}

#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */

static struct kvm *kvm_create_vm(void)
{
	int r, i;
	struct kvm *kvm = kvm_arch_alloc_vm();

	if (!kvm)
		return ERR_PTR(-ENOMEM);

	r = kvm_arch_init_vm(kvm);
	if (r)
		goto out_err_nodisable;

	r = hardware_enable_all();
	if (r)
		goto out_err_nodisable;

#ifdef CONFIG_HAVE_KVM_IRQCHIP
	INIT_HLIST_HEAD(&kvm->mask_notifier_list);
	INIT_HLIST_HEAD(&kvm->irq_ack_notifier_list);
#endif

	r = -ENOMEM;
	kvm->memslots = kzalloc(sizeof(struct kvm_memslots), GFP_KERNEL);
	if (!kvm->memslots)
		goto out_err_nosrcu;
	if (init_srcu_struct(&kvm->srcu))
		goto out_err_nosrcu;
	for (i = 0; i < KVM_NR_BUSES; i++) {
		kvm->buses[i] = kzalloc(sizeof(struct kvm_io_bus),
					GFP_KERNEL);
		if (!kvm->buses[i])
			goto out_err;
	}

	spin_lock_init(&kvm->mmu_lock);
	kvm->mm = current->mm;
	atomic_inc(&kvm->mm->mm_count);
	kvm_eventfd_init(kvm);
	mutex_init(&kvm->lock);
	mutex_init(&kvm->irq_lock);
	mutex_init(&kvm->slots_lock);
	atomic_set(&kvm->users_count, 1);

	r = kvm_init_mmu_notifier(kvm);
	if (r)
		goto out_err;

	raw_spin_lock(&kvm_lock);
	list_add(&kvm->vm_list, &vm_list);
	raw_spin_unlock(&kvm_lock);

	return kvm;

out_err:
	cleanup_srcu_struct(&kvm->srcu);
out_err_nosrcu:
	hardware_disable_all();
out_err_nodisable:
	for (i = 0; i < KVM_NR_BUSES; i++)
		kfree(kvm->buses[i]);
	kfree(kvm->memslots);
	kvm_arch_free_vm(kvm);
	return ERR_PTR(r);
}

static void kvm_destroy_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
		return;

	if (2 * kvm_dirty_bitmap_bytes(memslot) > PAGE_SIZE)
		vfree(memslot->dirty_bitmap_head);
	else
		kfree(memslot->dirty_bitmap_head);

	memslot->dirty_bitmap = NULL;
	memslot->dirty_bitmap_head = NULL;
}

/*
 * Free any memory in @free but not in @dont.
 */
static void kvm_free_physmem_slot(struct kvm_memory_slot *free,
				  struct kvm_memory_slot *dont)
{
	int i;

	if (!dont || free->rmap != dont->rmap)
		vfree(free->rmap);

	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		kvm_destroy_dirty_bitmap(free);


	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		if (!dont || free->lpage_info[i] != dont->lpage_info[i]) {
			vfree(free->lpage_info[i]);
			free->lpage_info[i] = NULL;
		}
	}

	free->npages = 0;
	free->rmap = NULL;
}

void kvm_free_physmem(struct kvm *kvm)
{
	int i;
	struct kvm_memslots *slots = kvm->memslots;

	for (i = 0; i < slots->nmemslots; ++i)
		kvm_free_physmem_slot(&slots->memslots[i], NULL);

	kfree(kvm->memslots);
}

static void kvm_destroy_vm(struct kvm *kvm)
{
	int i;
	struct mm_struct *mm = kvm->mm;

	kvm_arch_sync_events(kvm);
	raw_spin_lock(&kvm_lock);
	list_del(&kvm->vm_list);
	raw_spin_unlock(&kvm_lock);
	kvm_free_irq_routing(kvm);
	for (i = 0; i < KVM_NR_BUSES; i++)
		kvm_io_bus_destroy(kvm->buses[i]);
	kvm_coalesced_mmio_free(kvm);
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	mmu_notifier_unregister(&kvm->mmu_notifier, kvm->mm);
#else
	kvm_arch_flush_shadow(kvm);
#endif
	kvm_arch_destroy_vm(kvm);
	kvm_free_physmem(kvm);
	cleanup_srcu_struct(&kvm->srcu);
	kvm_arch_free_vm(kvm);
	hardware_disable_all();
	mmdrop(mm);
}

void kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc(&kvm->users_count);
}
EXPORT_SYMBOL_GPL(kvm_get_kvm);

void kvm_put_kvm(struct kvm *kvm)
{
	if (atomic_dec_and_test(&kvm->users_count))
		kvm_destroy_vm(kvm);
}
EXPORT_SYMBOL_GPL(kvm_put_kvm);


static int kvm_vm_release(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = filp->private_data;

	kvm_irqfd_release(kvm);

	kvm_put_kvm(kvm);
	return 0;
}

#ifndef CONFIG_S390
/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * This makes it possible to do double buffering: see x86's
 * kvm_vm_ioctl_get_dirty_log().
 */
static int kvm_create_dirty_bitmap(struct kvm_memory_slot *memslot)
{
	unsigned long dirty_bytes = 2 * kvm_dirty_bitmap_bytes(memslot);

	if (dirty_bytes > PAGE_SIZE)
		memslot->dirty_bitmap = vzalloc(dirty_bytes);
	else
		memslot->dirty_bitmap = kzalloc(dirty_bytes, GFP_KERNEL);

	if (!memslot->dirty_bitmap)
		return -ENOMEM;

	memslot->dirty_bitmap_head = memslot->dirty_bitmap;
	return 0;
}
#endif /* !CONFIG_S390 */

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mmap_sem for write.
 */
int __kvm_set_memory_region(struct kvm *kvm,
			    struct kvm_userspace_memory_region *mem,
			    int user_alloc)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct kvm_memory_slot *memslot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots, *old_memslots;

	r = -EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	/* We can read the guest memory with __xxx_user() later on. */
	if (user_alloc &&
	    ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
	     !access_ok(VERIFY_WRITE,
			(void __user *)(unsigned long)mem->userspace_addr,
			mem->memory_size)))
		goto out;
	if (mem->slot >= KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot = &kvm->memslots->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	r = -EINVAL;
	if (npages > KVM_MEM_MAX_NR_PAGES)
		goto out;

	if (!npages)
		mem->flags &= ~KVM_MEM_LOG_DIRTY_PAGES;

	new = old = *memslot;

	new.id = mem->slot;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	/* Disallow changing a memory slot's size. */
	r = -EINVAL;
	if (npages && old.npages && npages != old.npages)
		goto out_free;

	/* Check for overlaps */
	r = -EEXIST;
	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *s = &kvm->memslots->memslots[i];

		if (s == memslot || !s->npages)
			continue;
		if (!((base_gfn + npages <= s->base_gfn) ||
		      (base_gfn >= s->base_gfn + s->npages)))
			goto out_free;
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = -ENOMEM;

	/* Allocate if a slot is being created */
#ifndef CONFIG_S390
	if (npages && !new.rmap) {
		new.rmap = vzalloc(npages * sizeof(*new.rmap));

		if (!new.rmap)
			goto out_free;

		new.user_alloc = user_alloc;
		new.userspace_addr = mem->userspace_addr;
	}
	if (!npages)
		goto skip_lpage;

	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		unsigned long ugfn;
		unsigned long j;
		int lpages;
		int level = i + 2;

		/* Avoid unused variable warning if no large pages */
		(void)level;

		if (new.lpage_info[i])
			continue;

		lpages = 1 + ((base_gfn + npages - 1)
			     >> KVM_HPAGE_GFN_SHIFT(level));
		lpages -= base_gfn >> KVM_HPAGE_GFN_SHIFT(level);

		new.lpage_info[i] = vzalloc(lpages * sizeof(*new.lpage_info[i]));

		if (!new.lpage_info[i])
			goto out_free;

		if (base_gfn & (KVM_PAGES_PER_HPAGE(level) - 1))
			new.lpage_info[i][0].write_count = 1;
		if ((base_gfn+npages) & (KVM_PAGES_PER_HPAGE(level) - 1))
			new.lpage_info[i][lpages - 1].write_count = 1;
		ugfn = new.userspace_addr >> PAGE_SHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, or if explicitly asked to, disable large page
		 * support for this slot
		 */
		if ((base_gfn ^ ugfn) & (KVM_PAGES_PER_HPAGE(level) - 1) ||
		    !largepages_enabled)
			for (j = 0; j < lpages; ++j)
				new.lpage_info[i][j].write_count = 1;
	}

skip_lpage:

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (kvm_create_dirty_bitmap(&new) < 0)
			goto out_free;
		/* destroy any largepage mappings for dirty tracking */
	}
#else  /* not defined CONFIG_S390 */
	new.user_alloc = user_alloc;
	if (user_alloc)
		new.userspace_addr = mem->userspace_addr;
#endif /* not defined CONFIG_S390 */

	if (!npages || base_gfn != old.base_gfn) {
		r = -ENOMEM;
		slots = kzalloc(sizeof(struct kvm_memslots), GFP_KERNEL);
		if (!slots)
			goto out_free;
		memcpy(slots, kvm->memslots, sizeof(struct kvm_memslots));
		if (mem->slot >= slots->nmemslots)
			slots->nmemslots = mem->slot + 1;
		slots->generation++;
		slots->memslots[mem->slot].flags |= KVM_MEMSLOT_INVALID;

		old_memslots = kvm->memslots;
		rcu_assign_pointer(kvm->memslots, slots);
		synchronize_srcu_expedited(&kvm->srcu);
		/* slot was deleted or moved, clear iommu mapping */
		kvm_iommu_unmap_pages(kvm, &old);
		/* From this point no new shadow pages pointing to a deleted,
		 * or moved, memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 * 	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow(kvm);
		kfree(old_memslots);
	}

	r = kvm_arch_prepare_memory_region(kvm, &new, old, mem, user_alloc);
	if (r)
		goto out_free;

	r = -ENOMEM;
	slots = kzalloc(sizeof(struct kvm_memslots), GFP_KERNEL);
	if (!slots)
		goto out_free;
	memcpy(slots, kvm->memslots, sizeof(struct kvm_memslots));
	if (mem->slot >= slots->nmemslots)
		slots->nmemslots = mem->slot + 1;
	slots->generation++;

	/* map new memory slot into the iommu */
	if (npages) {
		r = kvm_iommu_map_pages(kvm, &new);
		if (r)
			goto out_slots;
	}

	/* actual memory is freed via old in kvm_free_physmem_slot below */
	if (!npages) {
		new.rmap = NULL;
		new.dirty_bitmap = NULL;
		for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i)
			new.lpage_info[i] = NULL;
	}

	slots->memslots[mem->slot] = new;
	old_memslots = kvm->memslots;
	rcu_assign_pointer(kvm->memslots, slots);
	synchronize_srcu_expedited(&kvm->srcu);

	kvm_arch_commit_memory_region(kvm, mem, old, user_alloc);

	/*
	 * If the new memory slot is created, we need to clear all
	 * mmio sptes.
	 */
	if (npages && old.base_gfn != mem->guest_phys_addr >> PAGE_SHIFT)
		kvm_arch_flush_shadow(kvm);

	kvm_free_physmem_slot(&old, &new);
	kfree(old_memslots);

	return 0;

out_slots:
	kfree(slots);
out_free:
	kvm_free_physmem_slot(&new, &old);
out:
	return r;

}
EXPORT_SYMBOL_GPL(__kvm_set_memory_region);

int kvm_set_memory_region(struct kvm *kvm,
			  struct kvm_userspace_memory_region *mem,
			  int user_alloc)
{
	int r;

	mutex_lock(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem, user_alloc);
	mutex_unlock(&kvm->slots_lock);
	return r;
}
EXPORT_SYMBOL_GPL(kvm_set_memory_region);

int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
				   struct
				   kvm_userspace_memory_region *mem,
				   int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
		return -EINVAL;
	return kvm_set_memory_region(kvm, mem, user_alloc);
}

int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty)
{
	struct kvm_memory_slot *memslot;
	int r, i;
	unsigned long n;
	unsigned long any = 0;

	r = -EINVAL;
	if (log->slot >= KVM_MEMORY_SLOTS)
		goto out;

	memslot = &kvm->memslots->memslots[log->slot];
	r = -ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	for (i = 0; !any && i < n/sizeof(long); ++i)
		any = memslot->dirty_bitmap[i];

	r = -EFAULT;
	if (copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
		goto out;

	if (any)
		*is_dirty = 1;

	r = 0;
out:
	return r;
}

void kvm_disable_largepages(void)
{
	largepages_enabled = false;
}
EXPORT_SYMBOL_GPL(kvm_disable_largepages);

int is_error_page(struct page *page)
{
	return page == bad_page || page == hwpoison_page || page == fault_page;
}
EXPORT_SYMBOL_GPL(is_error_page);

int is_error_pfn(pfn_t pfn)
{
	return pfn == bad_pfn || pfn == hwpoison_pfn || pfn == fault_pfn;
}
EXPORT_SYMBOL_GPL(is_error_pfn);

int is_hwpoison_pfn(pfn_t pfn)
{
	return pfn == hwpoison_pfn;
}
EXPORT_SYMBOL_GPL(is_hwpoison_pfn);

int is_fault_pfn(pfn_t pfn)
{
	return pfn == fault_pfn;
}
EXPORT_SYMBOL_GPL(is_fault_pfn);

int is_noslot_pfn(pfn_t pfn)
{
	return pfn == bad_pfn;
}
EXPORT_SYMBOL_GPL(is_noslot_pfn);

int is_invalid_pfn(pfn_t pfn)
{
	return pfn == hwpoison_pfn || pfn == fault_pfn;
}
EXPORT_SYMBOL_GPL(is_invalid_pfn);

static inline unsigned long bad_hva(void)
{
	return PAGE_OFFSET;
}

int kvm_is_error_hva(unsigned long addr)
{
	return addr == bad_hva();
}
EXPORT_SYMBOL_GPL(kvm_is_error_hva);

static struct kvm_memory_slot *__gfn_to_memslot(struct kvm_memslots *slots,
						gfn_t gfn)
{
	int i;

	for (i = 0; i < slots->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages)
			return memslot;
	}
	return NULL;
}

struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_memslot(kvm_memslots(kvm), gfn);
}
EXPORT_SYMBOL_GPL(gfn_to_memslot);

int kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_memslots *slots = kvm_memslots(kvm);

	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (memslot->flags & KVM_MEMSLOT_INVALID)
			continue;

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages)
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_is_visible_gfn);

unsigned long kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGE_SIZE;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return PAGE_SIZE;

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
		goto out;

	size = vma_kernel_pagesize(vma);

out:
	up_read(&current->mm->mmap_sem);

	return size;
}

static unsigned long gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				     gfn_t *nr_pages)
{
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return bad_hva();

	if (nr_pages)
		*nr_pages = slot->npages - (gfn - slot->base_gfn);

	return gfn_to_hva_memslot(slot, gfn);
}

unsigned long gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	return gfn_to_hva_many(gfn_to_memslot(kvm, gfn), gfn, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_hva);

static pfn_t get_fault_pfn(void)
{
	get_page(fault_page);
	return fault_pfn;
}

int get_user_page_nowait(struct task_struct *tsk, struct mm_struct *mm,
	unsigned long start, int write, struct page **page)
{
	int flags = FOLL_TOUCH | FOLL_NOWAIT | FOLL_HWPOISON | FOLL_GET;

	if (write)
		flags |= FOLL_WRITE;

	return __get_user_pages(tsk, mm, start, 1, flags, page, NULL, NULL);
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_WRITE;

	rc = __get_user_pages(current, current->mm, addr, 1,
			      flags, NULL, NULL, NULL);
	return rc == -EHWPOISON;
}

static pfn_t hva_to_pfn(struct kvm *kvm, unsigned long addr, bool atomic,
			bool *async, bool write_fault, bool *writable)
{
	struct page *page[1];
	int npages = 0;
	pfn_t pfn;

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

	BUG_ON(!write_fault && !writable);

	if (writable)
		*writable = true;

	if (atomic || async)
		npages = __get_user_pages_fast(addr, 1, 1, page);

	if (unlikely(npages != 1) && !atomic) {
		might_sleep();

		if (writable)
			*writable = write_fault;

		if (async) {
			down_read(&current->mm->mmap_sem);
			npages = get_user_page_nowait(current, current->mm,
						     addr, write_fault, page);
			up_read(&current->mm->mmap_sem);
		} else
			npages = get_user_pages_fast(addr, 1, write_fault,
						     page);

		/* map read fault as writable if possible */
		if (unlikely(!write_fault) && npages == 1) {
			struct page *wpage[1];

			npages = __get_user_pages_fast(addr, 1, 1, wpage);
			if (npages == 1) {
				*writable = true;
				put_page(page[0]);
				page[0] = wpage[0];
			}
			npages = 1;
		}
	}

	if (unlikely(npages != 1)) {
		struct vm_area_struct *vma;

		if (atomic)
			return get_fault_pfn();

		down_read(&current->mm->mmap_sem);
		if (npages == -EHWPOISON ||
			(!async && check_user_page_hwpoison(addr))) {
			up_read(&current->mm->mmap_sem);
			get_page(hwpoison_page);
			return page_to_pfn(hwpoison_page);
		}

		vma = find_vma_intersection(current->mm, addr, addr+1);

		if (vma == NULL)
			pfn = get_fault_pfn();
		else if ((vma->vm_flags & VM_PFNMAP)) {
			pfn = ((addr - vma->vm_start) >> PAGE_SHIFT) +
				vma->vm_pgoff;
			BUG_ON(!kvm_is_mmio_pfn(pfn));
		} else {
			if (async && (vma->vm_flags & VM_WRITE))
				*async = true;
			pfn = get_fault_pfn();
		}
		up_read(&current->mm->mmap_sem);
	} else
		pfn = page_to_pfn(page[0]);

	return pfn;
}

pfn_t hva_to_pfn_atomic(struct kvm *kvm, unsigned long addr)
{
	return hva_to_pfn(kvm, addr, true, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(hva_to_pfn_atomic);

static pfn_t __gfn_to_pfn(struct kvm *kvm, gfn_t gfn, bool atomic, bool *async,
			  bool write_fault, bool *writable)
{
	unsigned long addr;

	if (async)
		*async = false;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr)) {
		get_page(bad_page);
		return page_to_pfn(bad_page);
	}

	return hva_to_pfn(kvm, addr, atomic, async, write_fault, writable);
}

pfn_t gfn_to_pfn_atomic(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_pfn(kvm, gfn, true, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_atomic);

pfn_t gfn_to_pfn_async(struct kvm *kvm, gfn_t gfn, bool *async,
		       bool write_fault, bool *writable)
{
	return __gfn_to_pfn(kvm, gfn, false, async, write_fault, writable);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_async);

pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	return __gfn_to_pfn(kvm, gfn, false, NULL, true, NULL);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn);

pfn_t gfn_to_pfn_prot(struct kvm *kvm, gfn_t gfn, bool write_fault,
		      bool *writable)
{
	return __gfn_to_pfn(kvm, gfn, false, NULL, write_fault, writable);
}
EXPORT_SYMBOL_GPL(gfn_to_pfn_prot);

pfn_t gfn_to_pfn_memslot(struct kvm *kvm,
			 struct kvm_memory_slot *slot, gfn_t gfn)
{
	unsigned long addr = gfn_to_hva_memslot(slot, gfn);
	return hva_to_pfn(kvm, addr, false, NULL, true, NULL);
}

int gfn_to_page_many_atomic(struct kvm *kvm, gfn_t gfn, struct page **pages,
								  int nr_pages)
{
	unsigned long addr;
	gfn_t entry;

	addr = gfn_to_hva_many(gfn_to_memslot(kvm, gfn), gfn, &entry);
	if (kvm_is_error_hva(addr))
		return -1;

	if (entry < nr_pages)
		return 0;

	return __get_user_pages_fast(addr, nr_pages, 1, pages);
}
EXPORT_SYMBOL_GPL(gfn_to_page_many_atomic);

struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	pfn_t pfn;

	pfn = gfn_to_pfn(kvm, gfn);
	if (!kvm_is_mmio_pfn(pfn))
		return pfn_to_page(pfn);

	WARN_ON(kvm_is_mmio_pfn(pfn));

	get_page(bad_page);
	return bad_page;
}

EXPORT_SYMBOL_GPL(gfn_to_page);

void kvm_release_page_clean(struct page *page)
{
	kvm_release_pfn_clean(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_clean);

void kvm_release_pfn_clean(pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		put_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_release_pfn_clean);

void kvm_release_page_dirty(struct page *page)
{
	kvm_release_pfn_dirty(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_release_page_dirty);

void kvm_release_pfn_dirty(pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
}
EXPORT_SYMBOL_GPL(kvm_release_pfn_dirty);

void kvm_set_page_dirty(struct page *page)
{
	kvm_set_pfn_dirty(page_to_pfn(page));
}
EXPORT_SYMBOL_GPL(kvm_set_page_dirty);

void kvm_set_pfn_dirty(pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
		if (!PageReserved(page))
			SetPageDirty(page);
	}
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_dirty);

void kvm_set_pfn_accessed(pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		mark_page_accessed(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_set_pfn_accessed);

void kvm_get_pfn(pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		get_page(pfn_to_page(pfn));
}
EXPORT_SYMBOL_GPL(kvm_get_pfn);

static int next_segment(unsigned long len, int offset)
{
	if (len > PAGE_SIZE - offset)
		return PAGE_SIZE - offset;
	else
		return len;
}

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_from_user(data, (void __user *)addr + offset, len);
	if (r)
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest_page);

int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest);

int kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data,
			  unsigned long len)
{
	int r;
	unsigned long addr;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int offset = offset_in_page(gpa);

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	pagefault_disable();
	r = __copy_from_user_inatomic(data, (void __user *)addr + offset, len);
	pagefault_enable();
	if (r)
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(kvm_read_guest_atomic);

int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn, const void *data,
			 int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = __copy_to_user((void __user *)addr + offset, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty(kvm, gfn);
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest_page);

int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}

int kvm_gfn_to_hva_cache_init(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			      gpa_t gpa, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int offset = offset_in_page(gpa);
	gfn_t start_gfn = gpa >> PAGE_SHIFT;
	gfn_t end_gfn = (gpa + len - 1) >> PAGE_SHIFT;
	gfn_t nr_pages_needed = end_gfn - start_gfn + 1;
	gfn_t nr_pages_avail;

	ghc->gpa = gpa;
	ghc->generation = slots->generation;
	ghc->len = len;
	ghc->memslot = __gfn_to_memslot(slots, start_gfn);
	ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn, &nr_pages_avail);
	if (!kvm_is_error_hva(ghc->hva) && nr_pages_avail >= nr_pages_needed) {
		ghc->hva += offset;
	} else {
		/*
		 * If the requested region crosses two memslots, we still
		 * verify that the entire region is valid here.
		 */
		while (start_gfn <= end_gfn) {
			ghc->memslot = __gfn_to_memslot(slots, start_gfn);
			ghc->hva = gfn_to_hva_many(ghc->memslot, start_gfn,
						   &nr_pages_avail);
			if (kvm_is_error_hva(ghc->hva))
				return -EFAULT;
			start_gfn += nr_pages_avail;
		}
		/* Use the slow path for cross page reads and writes. */
		ghc->memslot = NULL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_gfn_to_hva_cache_init);

int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_write_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_to_user((void __user *)ghc->hva, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(kvm, ghc->memslot, ghc->gpa >> PAGE_SHIFT);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_write_guest_cached);

int kvm_read_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_read_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_from_user(data, (void __user *)ghc->hva, len);
	if (r)
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_read_guest_cached);

int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	return kvm_write_guest_page(kvm, gfn, (const void *) empty_zero_page,
				    offset, len);
}
EXPORT_SYMBOL_GPL(kvm_clear_guest_page);

int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

        while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_clear_guest_page(kvm, gfn, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		++gfn;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_clear_guest);

void mark_page_dirty_in_slot(struct kvm *kvm, struct kvm_memory_slot *memslot,
			     gfn_t gfn)
{
	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;

		__set_bit_le(rel_gfn, memslot->dirty_bitmap);
	}
}

void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = gfn_to_memslot(kvm, gfn);
	mark_page_dirty_in_slot(kvm, memslot, gfn);
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	DEFINE_WAIT(wait);

	for (;;) {
		prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

		if (kvm_arch_vcpu_runnable(vcpu)) {
			kvm_make_request(KVM_REQ_UNHALT, vcpu);
			break;
		}
		if (kvm_cpu_has_pending_timer(vcpu))
			break;
		if (signal_pending(current))
			break;

		schedule();
	}

	finish_wait(&vcpu->wq, &wait);
}

void kvm_resched(struct kvm_vcpu *vcpu)
{
	if (!need_resched())
		return;
	cond_resched();
}
EXPORT_SYMBOL_GPL(kvm_resched);

void kvm_vcpu_on_spin(struct kvm_vcpu *me)
{
	struct kvm *kvm = me->kvm;
	struct kvm_vcpu *vcpu;
	int last_boosted_vcpu = me->kvm->last_boosted_vcpu;
	int yielded = 0;
	int pass;
	int i;

	/*
	 * We boost the priority of a VCPU that is runnable but not
	 * currently running, because it got preempted by something
	 * else and called schedule in __vcpu_run.  Hopefully that
	 * VCPU is holding the lock that we need and will release it.
	 * We approximate round-robin by starting at the last boosted VCPU.
	 */
	for (pass = 0; pass < 2 && !yielded; pass++) {
		kvm_for_each_vcpu(i, vcpu, kvm) {
			struct task_struct *task = NULL;
			struct pid *pid;
			if (!pass && i < last_boosted_vcpu) {
				i = last_boosted_vcpu;
				continue;
			} else if (pass && i > last_boosted_vcpu)
				break;
			if (vcpu == me)
				continue;
			if (waitqueue_active(&vcpu->wq))
				continue;
			rcu_read_lock();
			pid = rcu_dereference(vcpu->pid);
			if (pid)
				task = get_pid_task(vcpu->pid, PIDTYPE_PID);
			rcu_read_unlock();
			if (!task)
				continue;
			if (task->flags & PF_VCPU) {
				put_task_struct(task);
				continue;
			}
			if (yield_to(task, 1)) {
				put_task_struct(task);
				kvm->last_boosted_vcpu = i;
				yielded = 1;
				break;
			}
			put_task_struct(task);
		}
	}
}
EXPORT_SYMBOL_GPL(kvm_vcpu_on_spin);

static int kvm_vcpu_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kvm_vcpu *vcpu = vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff == 0)
		page = virt_to_page(vcpu->run);
#ifdef CONFIG_X86
	else if (vmf->pgoff == KVM_PIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->arch.pio_data);
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	else if (vmf->pgoff == KVM_COALESCED_MMIO_PAGE_OFFSET)
		page = virt_to_page(vcpu->kvm->coalesced_mmio_ring);
#endif
	else
		return VM_FAULT_SIGBUS;
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct kvm_vcpu_vm_ops = {
	.fault = kvm_vcpu_fault,
};

static int kvm_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_vcpu_vm_ops;
	return 0;
}

/* <Siqi> */
int kvm_imee_stop ();
/* </Siqi> */

static int kvm_vcpu_release(struct inode *inode, struct file *filp)
{
	struct kvm_vcpu *vcpu = filp->private_data;

    /* <Siqi> */
    // TODO: clean up properly

    DBG ("current->pid: %d, parent->pid: %d imee_pid: %d\n", current->pid, current->parent->pid, imee_pid);
    if (current->pid == imee_pid || current->pid - imee_pid < 5)//TODO: this is really ugly
    {
        // smp_mb ();
        spin_lock (&sync_lock);
        if (ACCESS_ONCE (go_flg) == 2)
        {
            ACCESS_ONCE(go_flg) = 3;
        }
        spin_unlock (&sync_lock);

        smp_mb ();

        // while (ACCESS_ONCE (go_flg) != 0)
        //     continue;

        spin_lock (&sync_lock);
        ACCESS_ONCE (target_vm_pid) = 0;
        ACCESS_ONCE(imee_pid) = 0;
        ACCESS_ONCE(imee_vcpu) = 0;
        spin_unlock (&sync_lock);

        smp_mb ();

        DBG ("releasing IMEE.\n");
        vcpu->arch.mmu.root_hpa = INVALID_PAGE;
        // spin_unlock (&target_kvm->mmu_lock);
        enable_notifier = 0;
        target_proc = 0;
        target_kvm = 0;
        code_hpa = 0;
        data_hpa = 0;
        last_cr3 = 0;
        kvm_imee_stop ();
    }
    /* </Siqi> */

	kvm_put_kvm(vcpu->kvm);
	return 0;
}

static struct file_operations kvm_vcpu_fops = {
	.release        = kvm_vcpu_release,
	.unlocked_ioctl = kvm_vcpu_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = kvm_vcpu_compat_ioctl,
#endif
	.mmap           = kvm_vcpu_mmap,
	.llseek		= noop_llseek,
};

/*
 * Allocates an inode for the vcpu.
 */
static int create_vcpu_fd(struct kvm_vcpu *vcpu)
{
	return anon_inode_getfd("kvm-vcpu", &kvm_vcpu_fops, vcpu, O_RDWR);
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
static int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, u32 id)
{
	int r;
	struct kvm_vcpu *vcpu, *v;

	if (id >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_arch_vcpu_create(kvm, id);
	if (IS_ERR(vcpu))
		return PTR_ERR(vcpu);

	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);

	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

	mutex_lock(&kvm->lock);
	if (!kvm_vcpu_compatible(vcpu)) {
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}
	if (atomic_read(&kvm->online_vcpus) == KVM_MAX_VCPUS) {
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}

	kvm_for_each_vcpu(r, v, kvm)
		if (v->vcpu_id == id) {
			r = -EEXIST;
			goto unlock_vcpu_destroy;
		}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);
	r = create_vcpu_fd(vcpu);
	if (r < 0) {
		kvm_put_kvm(kvm);
		goto unlock_vcpu_destroy;
	}

	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	if (kvm->bsp_vcpu_id == id)
		kvm->bsp_vcpu = vcpu;
#endif
	mutex_unlock(&kvm->lock);
	return r;

unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
vcpu_destroy:
	kvm_arch_vcpu_destroy(vcpu);
	return r;
}

static int kvm_vcpu_ioctl_set_sigmask(struct kvm_vcpu *vcpu, sigset_t *sigset)
{
	if (sigset) {
		sigdelsetmask(sigset, sigmask(SIGKILL)|sigmask(SIGSTOP));
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	} else
		vcpu->sigset_active = 0;
	return 0;
}

/* <Siqi> */

static int walk_gpt (struct task_struct* tsk, struct kvm* target_kvm, struct arg_blk* args);

// this function runs on the core that IMEE is running, guranteed by the IPI
// sent by the trapping core, see arch/x86/kvm/vmx.c, inside handle_cr ()
void do_switch_cr3 ()
{
    t0 = rdtsc ();
    u64* code_epte_p = code_ept_pte_p;
    u64* data_epte_p = data_ept_pte_p;
    u64 code_epte = code_ept_pte;
    u64 data_epte = data_ept_pte;

    smp_mb();
    spin_lock (&sync_lock);
    last_cr3 = ACCESS_ONCE (switched_cr3);
    spin_unlock (&sync_lock);
    smp_mb();

    barrier ();

    int r = walk_gpt (target_proc, target_kvm, &imee_arg);

    // kvm_flush_remote_tlbs (imee_vcpu->kvm);

    if (r == 0)
    {
        if (code_ept_pte_p != code_epte_p) // code_ept_pte_p is changed by walk_gpt ()
        {
            *code_epte_p = code_epte;
        }

        if (data_ept_pte_p != data_epte_p) // data_ept_pte_p is changed by walk_gpt ()
        {
            *data_epte_p = data_epte;
        }

        imee_vcpu->arch.cr3 = switched_cr3;
        kvm_x86_ops->write_cr3(imee_vcpu->arch.cr3);
        __tmp_counter2 ++;
    }

    do_switch = 0;

    t1 = rdtsc ();
    total_cycle += t1 - t0;
}
EXPORT_SYMBOL_GPL (do_switch_cr3);

void imee_trace_cr3 ()
{
    apic->write (APIC_EOI, 0);
    do_switch = 1;
    __tmp_counter1 ++;
}

asmlinkage void imee_int_handler (void);
asm ("  .text");
asm ("  .type   imee_int_handler, @function");
asm ("imee_int_handler: \n");
asm ("cli \n");
asm ("pushl %ds \n");
asm ("pushl %eax \n");
asm ("pushl %ebx \n");
asm ("pushl %ecx \n");
asm ("pushl %edx \n");
asm ("pushl %esi \n");
asm ("pushl %edi \n");
asm ("pushl %esp \n");
asm ("pushl %ebp \n");
asm ("movl $0x68, %eax \n");
asm ("movl %eax, %ds \n");
asm ("call imee_trace_cr3 \n");
asm ("popl %ebp \n");
asm ("popl %esp \n");
asm ("popl %edi \n");
asm ("popl %esi \n");
asm ("popl %edx \n");
asm ("popl %ecx \n");
asm ("popl %ebx \n");
asm ("popl %eax \n");
asm ("popl %ds \n");
asm ("sti \n");
asm ("iretl");

unsigned long long intt;
void imee_write_eoi ()
{
    apic->write (APIC_EOI, 0);
    intt = rdtsc ();
    kvm_x86_ops->decache_cr3 (target_kvm->bsp_vcpu);

    if (!last_cr3)
    {
        kvm_x86_ops->get_seg_sec (target_kvm->bsp_vcpu, &imee_tr, VCPU_SREG_TR);
        kvm_x86_ops->get_idt (target_kvm->bsp_vcpu, &imee_idt);
        kvm_x86_ops->get_gdt (target_kvm->bsp_vcpu, &imee_gdt);
    }

    if (last_cr3 != target_kvm->bsp_vcpu->arch.cr3)
    {
        last_cr3 = target_kvm->bsp_vcpu->arch.cr3;
        exit_flg ++;
    }

    // kvm_x86_ops->intercept_cr3 (target_kvm->bsp_vcpu);
    
    // we don't need to acquire the spinlock because this function runs in the 
    // interrupt context with interrupt disabled.
    if (ACCESS_ONCE (go_flg) == 0 || ACCESS_ONCE (go_flg) == 3)
    {
        ACCESS_ONCE(go_flg) = 1;
    }
}

asmlinkage void imee_guest_int (void);
asm ("  .text");
asm ("  .type   imee_guest_int, @function");
asm ("imee_guest_int: \n");
asm ("cli \n");
asm ("pushl %ds \n");
asm ("pushl %eax \n");
asm ("pushl %ebx \n");
asm ("pushl %ecx \n");
asm ("pushl %edx \n");
asm ("pushl %esi \n");
asm ("pushl %edi \n");
asm ("pushl %esp \n");
asm ("pushl %ebp \n");
asm ("movl $0x68, %eax \n");
asm ("movl %eax, %ds \n");
asm ("call imee_write_eoi \n");
asm ("popl %ebp \n");
asm ("popl %esp \n");
asm ("popl %edi \n");
asm ("popl %esi \n");
asm ("popl %edx \n");
asm ("popl %ecx \n");
asm ("popl %ebx \n");
asm ("popl %eax \n");
asm ("popl %ds \n");
asm ("sti \n");
asm ("iretl");

static struct kvm_vcpu* pick_cpu (struct kvm* target_kvm)
{
    // TODO: randomly pick a cpu?
    return target_kvm->bsp_vcpu;
}

#define T_CODE 1
#define T_DATA 2
#define T_NORM 3
#define PAGESIZE 0x1000
#define PTE_P_BIT           0x1
#define PTE_RW_BIT          0x2

static pte_t* get_pte (struct task_struct *tsk, unsigned long addr)
{
    pgd_t* pgd;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;

    struct mm_struct* mm = tsk->mm;

    pgd = pgd_offset (mm, addr);
    if (pgd_none (*pgd) || pgd_bad (*pgd)) return NULL;

    pud = pud_offset (pgd,addr);
    if (pud_none (*pud) || pud_bad (*pud)) return NULL;

    pmd = pmd_offset (pud, addr);
    if (pmd_none (*pmd) || pmd_bad (*pmd)) return NULL;

    pte = pte_offset_map (pmd, addr);
    if (pte_none(*pte))
    {
        pte_unmap (pte);
        return NULL;
    }

    return pte;
}

// takes a guest physical address and return a pointer to that page
static ulong get_ptr_guest_page (struct task_struct* target_proc, struct kvm* target_kvm, gpa_t gpa)
{
    struct kvm_arch *arch = &target_kvm->arch;
    struct kvm_mmu_page *page;

    list_for_each_entry(page, &arch->active_mmu_pages, link)
    {
        if (page->gfn == ((gpa >> 12) & ~0x1FFUL) && page->role.level == 1)
        {
            u64* p = page->spt;
            int idx = (gpa >> 12) & 0x1FFUL;
            ulong r = (ulong) (p[idx] & ~EPT_MASK);
            // DBG ("r: %lX gpa: %lX\n", r, gpa);
            return r;
        }
    }
    // DBG ("mapping not found for gpa: %lX\n", gpa);
    return NULL;

    /*
    unsigned long hva = gfn_to_hva (target_kvm, gpa_to_gfn(gpa));
    pte_t* ptep = get_pte (target_proc, hva); //TODO: what if that page is paged out / not mapped?
    if (!ptep)
    {
        // DBG ("qemu pte not found, gpa: %lX hva: %lX\n", gpa, hva);
        return NULL;
    }
    ulong pte = pte_val(*ptep);
    pte_unmap (ptep);

    DBG ("got pte: %lX for gpa: %lX hva: %lX\n", pte, gpa, hva);

    if (pte & PTE_P_BIT)
    {
        ulong hpa = pte & ~GPA_MASK;
        return hpa;
    }
    else
    {
        DBG ("qemu pte p_bit not set, pte: %lX\n", pte);
        return NULL;
    }
    */
}

// TODO: assuming 32bit guest, change it to be more generic
static u32 get_guest_pte (struct task_sturct* target_proc, struct kvm* target_kvm, u32 cr3, gva_t gva)
{
    int idx[4] = {
        (gva >> 22) & 0x3FF,
        (gva >> 12) & 0x3FF
    };
    int page_level = 2;

    int lv = 0;
    u32 next, next_addr;
    next = cr3;
    next_addr = cr3 & ~0xFFFU;

    // DBG ("gva: %lX\n", gva);

    for ( ; lv < page_level; lv++)
    {
        ulong hpa = get_ptr_guest_page (target_proc, target_kvm, next_addr);
        if (hpa)
        {
            ulong pfn = hpa >> 12;
            struct page* pg = pfn_to_page (pfn);
            u32* pp = (u32*) kmap_atomic (pg);
            // DBG ("ptr to guest page: %p\n", p);
            next = pp[idx[lv]];
            // DBG ("lv: %d next: %lX\n", lv, next);
            kunmap_atomic (pp);

            if (!next || !(next & PTE_P_BIT)) 
                break;
            next_addr = next & ~GPA_MASK;
            // DBG ("lv: %d, next_addr: %lX\n", lv, next_addr);
        }
        else
        {
            break;
        }
    }
    
    if (lv == page_level)
    {
        return next;
    }
    else
    {
        return NULL;
    }
}

u64* get_epte (gpa_t gpa)
{
    struct kvm_mmu_page* cur;
    gpa_t needle = (gpa >> 12);
    int idx = (gpa >> 12) & 0x1FFUL;
    list_for_each_entry (cur, &pt_page, link)
    {
        if (cur->gfn == (needle & ~0x1FFUL))
        {
            // DBG ("Found epte: %lX\n", cur->spt[idx]);
            return &cur->spt[idx];
        }
    }

    // DBG ("epte not found: %lX\n", gpa);
    return NULL;
}
EXPORT_SYMBOL_GPL(get_epte);

void* alloc_non_leaf_page (int lv);
void* alloc_leaf_page (gpa_t gpa);

u64* map_epte (gpa_t gpa, ulong new_hpa)
{
    u64* r = 0;
    u64* root = __va (imee_vcpu->arch.mmu.root_hpa);
    int idx[4] = {
        (gpa >> 39) & 0x1FF,
        (gpa >> 30) & 0x1FF,
        (gpa >> 21) & 0x1FF,
        (gpa >> 12) & 0x1FF
    };

    int page_level = 4;
    int i = 0;
    u64* table = root;
    u64 entry;
    for ( ; i < page_level; i ++)
    {
        DBG ("lv: %d table: %p\n", i, table);
        entry = table[idx[i]];
        if (!entry)
        {
            u64* tbl;
            if (i < page_level - 2)
            {
                DBG ("allocating new non-leaf page for gpa: %lX\n", gpa);
                tbl = (u64*) alloc_non_leaf_page (page_level - i);
            }
            else if (i < page_level - 1) // i == page_level - 2
            {
                DBG ("allocating new leaf page for gpa: %lX\n", gpa);
                tbl = (u64*) alloc_leaf_page (gpa);
            }
            else // i == page_level - 1
            {
                // we are at leaf now
                // set the PTE, at last!
                u64 e = (new_hpa & ~EPT_MASK) | 0x3;
                DBG ("new EPTE: %llX\n", e);
                table[idx[i]] = e;
                r = &table[idx[i]];
                break;
            }
            table[idx[i]] = __pa (tbl) | 0x7;
            table = tbl;
        }
        else
        {
            if (i < page_level - 1)
            {
                table = __va (entry & ~EPT_MASK);
            }
            else
            {
                table[idx[i]] = (new_hpa & ~EPT_MASK) | 0x3;
                r = &table[idx[i]];
                break;
            }
        }
    }

    return r;
}

gfn_t hva_to_gfn (hva_t hva)
{
    int i;
	struct kvm_memslots *slots;
    gfn_t gfn;

	slots = kvm_memslots(target_kvm);

	for (i = 0; i < slots->nmemslots; i++) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];
		unsigned long start = memslot->userspace_addr;
		unsigned long end;

		end = start + (memslot->npages << PAGE_SHIFT);

		if (hva >= start && hva < end) {
			gfn_t gfn_offset = (hva - start) >> PAGE_SHIFT;
			gfn = memslot->base_gfn + gfn_offset;
        }
    }

    return gfn;
    // return NULL;
}

void invalidate_imee_ept (hva_t hva)
{
    u64* epte;
    gpa_t gpa = (hva_to_gfn (hva)) << 12;
    if (gpa == code_hpa || gpa == data_hpa)
        return;
    if (gpa && (epte = get_epte (gpa)))
    {
        // DBG ("gpa: %lX\n", gpa);
        *epte = 0;
    }
}

void change_imee_ept (ulong hva, pte_t pte)
{
    u32 ptev = pte_val(pte);
    // DBG ("ptev: %X\n", ptev);
    ulong new_hpa = ptev & ~0xFFF;
    gpa_t gpa = (hva_to_gfn (hva)) << 12;
    DBG ("gpa: %llX new_hpa: %lX\n", gpa, new_hpa);
    if (gpa == code_hpa || gpa == data_hpa)
        return;
    if (gpa)
        map_epte (gpa, new_hpa);
}

/*
static void patch_table (ulong dest, ulong len, int patch)
{
    ulong* buf = (ulong*) kmalloc (len * sizeof (ulong*), GFP_KERNEL);
    int i;

    copy_from_user ((void*) buf, dest, len * sizeof (ulong*));
    for (i = 0; i < len; i ++)
    {
        DBG ("before patch: %lX\n", buf[i]);
        buf[i] += patch;
        DBG ("after patch: %lX\n", buf[i]);
    }
    copy_to_user (dest, (void*) buf, len * sizeof (ulong*));

    kfree (buf);
}

void patch_got (ulong got, ulong got_len, int got_patch, ulong plt, ulong plt_len, int plt_patch)
{
    DBG ("got_patch: %X\n", got_patch);
    DBG ("gotplt_patch: %X\n", plt_patch);
    DBG ("got: %lX\n", got);
    DBG ("gotplt: %lX\n", plt);

    patch_table (got, got_len, got_patch);
    patch_table (plt, plt_len, plt_patch);
}
*/

static int fix_lib_normal (struct task_struct* target_proc, struct kvm* target_kvm, ulong cr3, ulong code, ulong num_x_page, ulong code_host, ulong data, ulong num_w_page, ulong data_host, ulong got, ulong got_len, ulong gotplt, ulong gotplt_len)
{
    int i;
    // printk ("code: %lX data: %lX code_host: %lX data_host: %lX\n", code, data, code_host, data_host);
    for (i = 0; i < num_x_page; i ++)
    {
        ulong addr = code + i * PAGE_SIZE;
        ulong pte = get_guest_pte (target_proc, target_kvm, cr3, addr);
        if (!pte)
        {
            printk ("cannot find guest code mapping: %lX.\n", addr);
            return -1;
        }
        // DBG ("pte: %lX\n", pte);

        ulong h_addr = code_host + i * PAGE_SIZE;
        pte_t* ptep = get_pte (current, h_addr);
        if (!ptep)
        {
            printk ("ERROR: cannot find host mapping, but host memory should already be pinned: %lX\n", h_addr);
            return -1;
        }
        ulong ptev = pte_val(*ptep);
        pte_unmap (ptep);
        ulong code_phys = ptev & ~HPA_MASK;

        // there is only one page, so this HACK works
        code_hpa = code_phys;

        u64* epte = get_epte (pte & ~GPA_MASK);
        if (epte)
        {
            code_ept_pte_p = epte;
            code_ept_pte = *epte;
            *epte = ((*epte) & EPT_MASK) | ((u64) code_phys) | 0x4; // 0x4: Exec bit
            // printk ("replaced code epte: %llX at: %p with: %llX\n", code_ept_pte, code_ept_pte_p, *epte);
        }
        else
        {
            code_ept_pte_p = map_epte (pte & ~GPA_MASK, code_phys | 0x4); // hack, setting Exec bit here
            code_ept_pte = 0;
            // printk ("remapped code epte at: %p\n", code_ept_pte_p);
        }
    }

    for (i = 0; i < num_w_page; i ++)
    {
        ulong addr = data + i * PAGE_SIZE;
        ulong pte = get_guest_pte (target_proc, target_kvm, cr3, addr);
        if (!pte)
        {
            printk ("cannot find guest data mapping: %lX\n", addr);
            return -1;
        }
        // DBG ("pte: %lX\n", pte);

        ulong h_addr = data_host + i * PAGE_SIZE;
        pte_t* ptep = get_pte (current, h_addr);
        if (!ptep)
        {
            printk ("ERROR: cannot find host data mapping, but host memory should already be pinned: %lX\n", h_addr);
            return -1;
        }
        ulong ptev = pte_val(*ptep);
        pte_unmap (ptep);
        ulong data_phys = ptev & ~HPA_MASK;

        // there is only one page, so this HACK works
        data_hpa = data_phys;

        u64* epte = get_epte (pte & ~GPA_MASK);
        if (epte)
        {
            data_ept_pte_p = epte;
            data_ept_pte = *epte;
            *epte = ((*epte) & EPT_MASK) | ((u64) data_phys) | 0x3;
            // printk ("replaced data epte: %llX at: %p with: %llX\n", data_ept_pte, data_ept_pte_p, *epte);
        }
        else
        {
            data_ept_pte_p = map_epte (pte & ~GPA_MASK, data_phys | 0x3); //hack
            data_ept_pte = 0;
            // printk ("remapped data epte at: %p\n", data_ept_pte_p);
        }
    }

    /*
    int got_patch = data - data_host;
    int gotplt_patch = code - code_host;

    patch_got (got, got_len, got_patch, gotplt, gotplt_len, gotplt_patch);
    */

    return 0;
}

/*
void fix_lib_scattered_page ()
{
}

static int fix_lib_regions (struct task_struct* target_proc, struct kvm* target_kvm, ulong cr3, ulong code, ulong num_x_page, ulong code_host, ulong data, ulong num_w_page, ulong data_host, ulong offset, ulong thunk, ulong got, ulong got_len, ulong gotplt, ulong gotplt_len)
{
    DBG ("code: %lX data: %lX code_host: %lX data_host: %lX offset: %lX thunk: %lX\n", 
            code, data, code_host, data_host, offset, thunk);
    u32 new_offset = data - code - num_x_page * 0x1000;
    int got_base_patch = new_offset - offset;
    unsigned char add_ebx_ret[10] = {
        0x8b, 0x1c, 0x24,               // mov (%esp), %ebx
        0x81, 0xc3, 0x0, 0x0, 0x0, 0x0, // add $0, %ebx
        0xc3                            // ret
    };
    unsigned char* p = &got_base_patch;
    DBG ("patch: %X\n", got_base_patch);

    // intel uses little endian
    int i;
    for (i = 3; i >= 0; i--)
    {
        add_ebx_ret[i + 5] = p[i];
    }

    // patch __i686.get_pc_thunk.bx
   
    copy_to_user ((void*) thunk, add_ebx_ret, 10);

    for (i = 0; i < 10; i ++)
    {
        printk ("%X ", add_ebx_ret[i]);
    }
    DBG ("\n");

    return fix_lib_normal (target_proc, target_kvm, cr3, code, num_x_page, code_host, data, num_w_page, data_host, got, got_len, gotplt, gotplt_len);
}
*/

static void adjust_imee_vcpu (ulong rip, ulong data)
{
    imee_vcpu->arch.regs[VCPU_REGS_RIP] = rip; 
    imee_vcpu->arch.regs[VCPU_REGS_RCX] = 0xDEADBEEF;
    imee_vcpu->arch.regs[VCPU_REGS_RDX] = data; 
    imee_vcpu->arch.regs[VCPU_REGS_RSP] = data + 0xFF0;
}

static int walk_gpt (struct task_struct* tsk, struct kvm* target_kvm, struct arg_blk* args) 
{
    ulong hpa = get_ptr_guest_page (target_proc, target_kvm, last_cr3);
    int code_flg, data_flg;
    struct region code_region = {0, 0, T_CODE};
    struct region data_region = {0, 0, T_DATA};

    code_flg = data_flg = 0;

    ulong num_x_page = args->num_x_page;
    ulong num_w_page = args->num_w_page;
    ulong offset = args->offset;
    ulong code_host = args->code_host;
    ulong data_host = args->data_host;
    ulong tgt = args->thunk;
    ulong got = args->got;
    ulong got_len = args->got_len;
    ulong gotplt = args->gotplt;
    ulong gotplt_len = args->gotplt_len;

    if (hpa)
    {
        ulong pfn = hpa >> 12;
        struct page* pg = pfn_to_page (pfn);
        u32* pp = (u32*) kmap_atomic (pg);
        int i = 0;
        for (; i < 768; i ++)
        {
            if (pp[i])
            {
                ulong pt_hpa = get_ptr_guest_page (target_proc, target_kvm, pp[i] & ~GPA_MASK);
                struct page* pt_pg = pfn_to_page (pt_hpa >> 12);
                u32* pt_pp = (u32*) kmap_atomic (pt_pg);

                int j = 0;
                for (; j < 1024; j ++)
                {
                    if (pt_pp[j])
                    {
                        // DBG ("pte: %X\n", pt_pp[j]);
                        if (!code_flg && (pt_pp[j] & PTE_P_BIT) && !(pt_pp[j] & PTE_RW_BIT))
                        {
                            code_region.start = (i << 22 | j << 12);
                            code_region.end = code_region.start;
                            // DBG ("added code region\n");
                            code_flg = 1;
                        }
                        if (!data_flg && (pt_pp[j] & PTE_P_BIT) && (pt_pp[j] & PTE_RW_BIT))
                        {

                            data_region.start = (i << 22 | j << 12);
                            data_region.end = data_region.start;
                            // DBG ("added data region\n");
                            data_flg = 1;
                        }

                        if (code_flg && data_flg)
                        {
                            kunmap_atomic (pt_pp);
                            kunmap_atomic (pp);
                            goto found;
                        }
                    }
                }
                kunmap_atomic (pt_pp);
            }
        }
        kunmap_atomic (pp);
    }

found:

    // DBG ("code region %lX\n", code_region.start);
    // DBG ("data region %lX\n", data_region.start);
    adjust_imee_vcpu (args->entry + code_region.start - code_host, data_region.start);
    return fix_lib_normal (target_proc, target_kvm, last_cr3, code_region.start, num_x_page, code_host, data_region.start, num_w_page, data_host, got, got_len, gotplt, gotplt_len);
}

static void* do_alloc_ept_frames (void* base)
{
    base = __get_free_pages (GFP_KERNEL, PAGE_ORDER);
    return base;
}

static void init_ept_frames ()
{
    if (!p_base)
    {
        p_idx = 0;
        p_base_idx = 0;
        p_base = do_alloc_ept_frames (p_bases[p_base_idx]);
    }
}

static ulong* get_ept_page ()
{
    if (p_base)
    {
        p_idx ++;
        if (p_idx < (1 << PAGE_ORDER))
        {
            int i;
            ulong* p = (ulong*) (((ulong) p_base) + p_idx * PAGE_SIZE);
            for (i = 0; i < PAGE_SIZE / sizeof (ulong); i ++)
            {
                p[i] = 0;
            }
            return p;
        }
        else
        {
            p_base_idx ++;
            if (p_base_idx < NBASE)
            {
                p_base = do_alloc_ept_frames (p_bases[p_base_idx]);
                p_idx = 0;
                return (ulong*) p_base;
            }
            else
            {
                printk (KERN_ERR "EPT frames have been used up, p_base_idx: %d p_idx: %d\n", p_base_idx, p_idx);
                return NULL;
            }
        }
    }
    else
    {
        printk (KERN_ERR "EPT frames have not been allocated.");
        return NULL;
    }
}

void* alloc_non_leaf_page (int lv)
{
    struct kvm_mmu_page* temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    INIT_LIST_HEAD(&temp_page->link);
    void* page = get_ept_page();
    temp_page->spt = page;
    temp_page->role.level = lv;
    list_add (&temp_page->link, &non_leaf_page);
    return page;
}

void* alloc_leaf_page (gpa_t gpa)
{
    struct kvm_mmu_page* temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    INIT_LIST_HEAD(&temp_page->link);
    void* page = get_ept_page();
    temp_page->spt = page;
    temp_page->role.level = 1;
    temp_page->gfn = (gpa >> 12) & ~0x1FFUL; 
    list_add (&temp_page->link, &pt_page);
    return page;
}


u64 make_imee_ept ()
{
    struct kvm_mmu_page* root_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    root_page->spt = (u64*) get_ept_page ();
    root_page->role.level = 4;
    INIT_LIST_HEAD (&root_page->link);
    list_add (&root_page->link, &non_leaf_page);

    u64* root = root_page->spt;
    struct kvm_mmu_page* cur;
    list_for_each_entry (cur, &pt_page, link)
    {
        // DBG ("building higher level pages for GFN: %llX\n", cur->gfn);
        int pml4_ind = ((cur->gfn) >> 27) & 0x1FF;
        int pdpt_ind = ((cur->gfn) >> 18) & 0x1FF;
        int pd_ind = ((cur->gfn) >> 9) & 0x1FF;
        // DBG ("pml4_ind: %X\n", pml4_ind);
        // DBG ("pdpt_ind: %X\n", pdpt_ind);
        // DBG ("pd_ind: %X\n", pd_ind);

        u64 *pdpt, *pd;
        if (root[pml4_ind] == 0)
        {
            pdpt = (u64*) alloc_non_leaf_page (3);
            root[pml4_ind] = __pa (pdpt) | 0x7;
            // DBG ("added root[pml4_ind]: %llX\n", root[pml4_ind]);
        }
        else
        {
            pdpt = __va (root[pml4_ind] & ~EPT_MASK);
            // DBG ("found pdpt: %llX\n", pdpt);
        }

        if (pdpt[pdpt_ind] == 0)
        {
            pd = (u64*) alloc_non_leaf_page (2);
            pdpt[pdpt_ind] = __pa (pd) | 0x7;
            // DBG ("added pdpt[pdpt_ind]: %llX\n", pdpt[pdpt_ind]);
        }
        else
        {
            pd = __va (pdpt[pdpt_ind] & ~EPT_MASK);
            // DBG ("found pd: %llX\n", pd);
        }

        if (pd[pd_ind] == 0)
        {
            pd[pd_ind] = __pa (cur->spt) | 0x7;
        }
    }

    list_for_each_entry (cur, &non_leaf_page, link)
    {
        // DBG ("new non-leaf page at: %p\n", cur->spt);
    }

    return (u64) __pa (root);
}

static void install_int_handlers ()
{
    unsigned long long idtr;
    unsigned long long* idt;
    gate_desc s;

    asm ("sidt %0":"=m"(idtr)::);

    idt = (unsigned long long*) (idtr >> 16);
    pack_gate(&s, GATE_INTERRUPT, (unsigned long) imee_int_handler, 0, 0, __KERNEL_CS);
    idt[0x55] = * ((unsigned long long*) (&s));
    pack_gate(&s, GATE_INTERRUPT, (unsigned long) imee_guest_int, 0, 0, __KERNEL_CS);
    idt[0x56] = * ((unsigned long long*) (&s));

    DBG ("imee_int_handler: %p\n", imee_int_handler);
    DBG ("idt: %p, IDT gate descriptor: %llX\n", idt, s);
}

static void remove_int_handlers ()
{
}

static long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu, void* argp)
{
    int r = 0;
    struct kvm *kvm;

    code_ept_pte_p = 0;
    code_ept_pte = 0;
    data_ept_pte_p = 0;
    data_ept_pte = 0;

    __tmp_counter = 0;
    __tmp_counter1 = 0;
    __tmp_counter2 = 0;
    __tmp_counter3 = 0;
    __tmp_counter5 = 0;

    total_cycle = 0;
    cycle_idx = 0;

    printk ("================start==================\n");

    t0 = rdtsc ();

    // install the handlers to IDT
    install_int_handlers ();

    struct arg_blk* args = &imee_arg;
    copy_from_user (&imee_arg, argp, sizeof (struct arg_blk));

    /* allocate page frames for EPT from the kernel */
    init_ept_frames();

    /* now look for the VM we want to watch */
    // preempt_disable ();
    pid_t temp_pid;
	list_for_each_entry(kvm, &vm_list, vm_list)
    {
        if (kvm->mm->owner->pid != current->parent->pid)
        {
            target_proc = kvm->mm->owner;
            target_kvm = kvm;
            temp_pid = target_proc->pid;
            DBG ("target_vm_pid: %d process: %s\n", target_vm_pid, kvm->mm->owner->comm);
        }
    }

    /* initializes global variables */
    smp_mb ();
    spin_lock (&sync_lock);
    ACCESS_ONCE (target_vm_pid) = temp_pid;
    ACCESS_ONCE (imee_vcpu) = vcpu;
    ACCESS_ONCE (exit_flg) = 0;
    ACCESS_ONCE (imee_pid) = current->pid;
    spin_unlock (&sync_lock);
    smp_mb ();
    DBG ("current->pid: %d parent->pid: %d\n", current->pid, current->parent->pid);

    t1 = rdtsc ();
    // t[cycle_idx] = t1 - t0;
    // cycle_idx ++;

    DBG ("task: %d own the VM.\n", target_proc->pid);

    // t0 = rdtsc ();

    struct kvm_arch *arch = &target_kvm->arch;
    struct kvm_mmu_page *page;

    struct kvm_vcpu *guest_vcpu = pick_cpu (target_kvm);

    // copy leaf EPTs 
    // spin_lock (&guest_vcpu->kvm->mmu_lock);
    list_for_each_entry(page, &arch->active_mmu_pages, link)
    {
        // DBG ("level: %d gfn: %lX\n", page->role.level, page->gfn);
        // copy all leaf page
        if (page->role.level == 1)
        {
            void *newpage = (void*) get_ept_page ();
            struct kvm_mmu_page* new_pt_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
            new_pt_page->spt = newpage;
            new_pt_page->role.level = 1;
            new_pt_page->gfn = page->gfn;
            INIT_LIST_HEAD (&new_pt_page->link);
            list_add (&new_pt_page->link, &pt_page);
            u64 *pte = (u64*) newpage;
            int i = 0;
            for (; i < 512; i ++)
            {
                pte[i] = page->spt[i] & ~0x6;
            }
        }
    }
    u64 eptptr = make_imee_ept ();
    // turn on MMU notifier
    // enable_notifier = 1;
    // spin_unlock (&guest_vcpu->kvm->mmu_lock);

    // setup vCPU
    DBG ("guest vcpu regs avail: %X\n", guest_vcpu->arch.regs_avail);
    DBG ("guest vcpu regs dirty: %X\n", guest_vcpu->arch.regs_dirty);
    vcpu->arch.mmu.root_hpa = (u64) eptptr;

    struct kvm_sregs *imee_sregs = kmalloc (sizeof (struct kvm_sregs), GFP_KERNEL);
    kvm_arch_vcpu_ioctl_get_sregs (guest_vcpu, imee_sregs);
    // kvm_arch_vcpu_ioctl_set_sregs (vcpu, imee_sregs);

    // init CS register
    imee_sregs->cs.selector = 0x60;
    imee_sregs->cs.base = 0x0;
    imee_sregs->cs.limit = 0xFFFFFFFF;
    imee_sregs->cs.type = 0xB;
    imee_sregs->cs.s = 1;
    imee_sregs->cs.dpl = 0;
    imee_sregs->cs.present = 1;
    imee_sregs->cs.avl = 0;
    imee_sregs->cs.l = 0;
    imee_sregs->cs.db = 1;
    imee_sregs->cs.g = 1;

    // DS register
    imee_sregs->ds.selector = 0x7B;
    imee_sregs->ds.base = 0x0;
    imee_sregs->ds.limit = 0xFFFFFFFF;
    imee_sregs->ds.type = 0x3;
    imee_sregs->ds.s = 1;
    imee_sregs->ds.dpl = 3;
    imee_sregs->ds.present = 1;
    imee_sregs->ds.avl = 0;
    imee_sregs->ds.l = 0;
    imee_sregs->ds.db = 1;
    imee_sregs->ds.g = 1;

    // SS register
    imee_sregs->ss.selector = 0x68;
    imee_sregs->ss.base = 0x0;
    imee_sregs->ss.limit = 0xFFFFFFFF;
    imee_sregs->ss.type = 0x3;
    imee_sregs->ss.s = 1;
    imee_sregs->ss.dpl = 0;
    imee_sregs->ss.present = 1;
    imee_sregs->ss.avl = 0;
    imee_sregs->ss.l = 0;
    imee_sregs->ss.db = 1;
    imee_sregs->ss.g = 1;

    // GS register
    imee_sregs->gs.selector = 0x68;
    imee_sregs->gs.base = 0x0;
    imee_sregs->gs.limit = 0xFFFFFFFF;
    imee_sregs->gs.type = 0x3;
    imee_sregs->gs.s = 1;
    imee_sregs->gs.dpl = 0;
    imee_sregs->gs.present = 1;
    imee_sregs->gs.avl = 0;
    imee_sregs->gs.l = 0;
    imee_sregs->gs.db = 1;
    imee_sregs->gs.g = 1;

    DBG ("CS selector: %X base: %llX limit: %X\n", imee_sregs->cs.selector, imee_sregs->cs.base, imee_sregs->cs.limit);
    DBG ("DS selector: %X base: %llX limit: %X\n", imee_sregs->ds.selector, imee_sregs->ds.base, imee_sregs->ds.limit);
    DBG ("SS selector: %X base: %llX limit: %X\n", imee_sregs->ss.selector, imee_sregs->ss.base, imee_sregs->ss.limit);
    DBG ("ES selector: %X base: %llX limit: %X\n", imee_sregs->es.selector, imee_sregs->es.base, imee_sregs->es.limit);
    DBG ("FS selector: %X base: %llX limit: %X\n", imee_sregs->fs.selector, imee_sregs->fs.base, imee_sregs->fs.limit);
    DBG ("GS selector: %X base: %llX limit: %X\n", imee_sregs->gs.selector, imee_sregs->gs.base, imee_sregs->gs.limit);
    DBG ("IDT base: %llX limit: %X\n", imee_sregs->idt.base, imee_sregs->idt.limit);
    DBG ("GDT base: %llX limit: %X\n", imee_sregs->gdt.base, imee_sregs->gdt.limit);
    DBG ("TR  base: %llX limit: %X sel: %X\n", imee_sregs->tr.base, imee_sregs->tr.limit, imee_sregs->tr.selector);
    DBG ("CR0:%llX CR2: %llX, CR3: %llX, CR4: %llX\n", imee_sregs->cr0, imee_sregs->cr2, imee_sregs->cr3, imee_sregs->cr4);
    DBG ("CR8:%llX EFER: %X\n", imee_sregs->cr8, imee_sregs->efer);

    kvm_x86_ops->set_segment (vcpu, &imee_sregs->cs, VCPU_SREG_CS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ds, VCPU_SREG_DS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ss, VCPU_SREG_SS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ds, VCPU_SREG_ES);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->fs, VCPU_SREG_FS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->gs, VCPU_SREG_GS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ldt, VCPU_SREG_LDTR);

    kvm_x86_ops->set_rflags (vcpu, 0x2);

	vcpu->arch.cr2 = imee_sregs->cr2;
	
	kvm_x86_ops->set_efer(vcpu, imee_sregs->efer);
	kvm_x86_ops->set_cr0(vcpu, imee_sregs->cr0);
	kvm_x86_ops->set_cr4(vcpu, imee_sregs->cr4);

    // set_cr3 seems to be quite strange in its EPTP handling, I gotta roll my
    // own, root_hpa has already been filled above.
    kvm_x86_ops->write_eptp (vcpu);

    DBG ("imee vcpu regs avail: %X\n", vcpu->arch.regs_avail);
    DBG ("imee vcpu regs dirty: %X\n", vcpu->arch.regs_dirty);
    vcpu->arch.regs_dirty = 0xFFFFFFFFU;
    vcpu->arch.regs_avail = 0xFFFFFFFFU;

    t1 = rdtsc ();
    // t[cycle_idx] = t1 - t0;
    setup_cycle = t1 - t0;
    // cycle_idx ++;

    return r;
}

static int start_guest_intercept (struct kvm_vcpu *vcpu)
{
    cycle_idx = 0;
    int r = 0;
    ulong flags;

    t0 = rdtsc ();

    // DBG ("sending\n");
    // DBG ("%p\n", target_kvm);

    last_cr3 = 0;

    // /* temp */
    // ts_buffer = (unsigned long long*) __get_free_pages (GFP_KERNEL, PAGE_ORDER);
    // ts_buffer_idx = 0;
    // /* temp */

    spin_lock (&sync_lock);
    if (ACCESS_ONCE (go_flg) == 2)
    {
        printk ("WARNING: last scan ended without resetting CR3 scanning, skipping now.\n");
    }
    else if (ACCESS_ONCE (go_flg) == 1)
    {
        ACCESS_ONCE (go_flg) = 0;
    }
    else if (ACCESS_ONCE (go_flg) == 3)
    {
        ACCESS_ONCE (go_flg) = 2;
    }
    spin_unlock (&sync_lock);


    t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++; 

    int k = 0;
    while (k < 100)
    {
        t0 = rdtsc ();

        k ++;

        ACCESS_ONCE (exit_flg) = 1;
        smp_mb ();
        int cpu = task_cpu (target_kvm->mm->owner);
        apic->send_IPI_mask (cpumask_of (cpu), 0x56);

        t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++; 
        t0 = rdtsc ();

        // /* temp */
        // return -1;

        smp_mb ();
        int j = 0;
        while (ACCESS_ONCE(exit_flg) == 1)
        {
            j ++;
            if (j > 1000000) 
            {
                printk ("Waited for too long for exit_flg\n");
                return -4;
            }
        }
        // DBG ("%d times, last_cr3: %lX\n", j, last_cr3);

        t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++;

        t0 = rdtsc ();
        int ii = walk_gpt (target_proc, target_kvm, &imee_arg);
        t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++;
        // DBG ("load cycles: %lld i: %d\n", t1 - t0, i);

        t0 = rdtsc ();
        if (ii == 0)
        {
            vcpu->arch.cr3 = last_cr3;
            kvm_x86_ops->set_cr3(vcpu, vcpu->arch.cr3);

            // // use PF handler inside IMEE
            // gate_desc s;
            // pack_gate(&s, GATE_INTERRUPT, (unsigned long)imee_arg.int_handler, 0, 0, imee_sregs->cs.selector);
            // copy_to_user (args->data_host + 0xFF8, &s, sizeof (gate_desc));
            // imee_idt.address = args->data_host + (0xFF8 - 8 * 14); // magic
            // // use PF handler inside IMEE

            kvm_x86_ops->set_segment (vcpu, &imee_tr, VCPU_SREG_TR);
            kvm_x86_ops->set_idt (vcpu, &imee_idt);
            kvm_x86_ops->set_gdt (vcpu, &imee_gdt);

            break;
        }

        t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++;
    }

    t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++;

    t0 = rdtsc ();
    if (k == 100)
    {
        r = -3;
        printk ("Guest PT walk failed\n");
    }

    t1 = rdtsc (); t[cycle_idx] = t1 - t0; cycle_idx ++; 
    
    // DBG ("exit_flg: %d\n", exit_flg);

    return r;
}

int kvm_imee_stop ()
{
    struct kvm_mmu_page *cur, *n;

    list_for_each_entry_safe (cur, n, &pt_page, link)
    {
        // DBG ("releasing leaf page: %llX lv: %d\n", cur->gfn, cur->role.level);
        if (cur->gfn == ((last_cr3 >> 12) & ~0x1FF))
        {
            int i;
            for (i = 0; i < 512; i++)
            {
                u64* p = cur->spt;
                // if (p[i])
                //     DBG ("\t i:%d -> %llX\n", i, p[i]);
            }
        }

        list_del (&cur->link);
        // free_page (cur->spt);
        kfree (cur);
    }

    list_for_each_entry_safe (cur, n, &non_leaf_page, link)
    {
        // DBG ("releasing non-leaf page: %llX lv: %d\n", cur->gfn, cur->role.level);
        int i;
        for (i = 0; i < 512; i++)
        {
            u64* p = cur->spt;
            // if (p[i])
            //     DBG ("\t i:%d -> %llX\n", i, p[i]);
        }

        list_del (&cur->link);
        // free_page (cur->spt);
        kfree (cur);
    }
    
    free_pages (p_base, PAGE_ORDER);
    p_base = 0;
    p_idx = 0;
    ACCESS_ONCE(exit_flg) = 0;

    remove_int_handlers ();

    while (cycle_idx >= 0)
    {
        printk ("cycles: %d - %lld\n", cycle_idx, t[cycle_idx]);
        cycle_idx--;
    }

    printk ("__tmp_counter: %d\n", __tmp_counter);
    printk ("__tmp_counter3: %d\n", __tmp_counter3);
    DBG ("__tmp_counter4: %d\n", __tmp_counter4);
    DBG ("__tmp_counter5: %d\n", __tmp_counter5);
    printk ("__tmp_counter1: %d\n", __tmp_counter1);
    printk ("__tmp_counter2: %d\n", __tmp_counter2);
    DBG ("last_cr3: %lX\n", last_cr3);
    DBG ("go_flg: %lX\n", go_flg);
    printk ("total_cycle: %lld\n", total_cycle);
    printk ("setup_cycle: %lld\n", setup_cycle);

    // /* temp */
    // int i;
    // for (i = 0; i < ts_buffer_idx; i ++)
    // {
    //     printk ("%lld\n", ts_buffer[i]);
    // }
    // free_pages (ts_buffer, PAGE_ORDER);
    // ts_buffer = 0;

    printk ("=================end===================\n");
    return 0;
}

/* </Siqi> */

static long kvm_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	struct kvm_fpu *fpu = NULL;
	struct kvm_sregs *kvm_sregs = NULL;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	if (unlikely(_IOC_TYPE(ioctl) != KVMIO))
		return -EINVAL;

#if defined(CONFIG_S390) || defined(CONFIG_PPC)
	/*
	 * Special cases: vcpu ioctls that are asynchronous to vcpu execution,
	 * so vcpu_load() would break it.
	 */
	if (ioctl == KVM_S390_INTERRUPT || ioctl == KVM_INTERRUPT)
		return kvm_arch_vcpu_ioctl(filp, ioctl, arg);
#endif


	vcpu_load(vcpu);
	switch (ioctl) {
    /* <Siqi> */
    case KVM_IMEE_STOP:
        printk ("imee stopping... %X\n", KVM_IMEE_RUN);
        r = kvm_imee_stop ();
        break;
    case KVM_IMEE_SETUP:
        r = kvm_imee_get_guest_context (vcpu, argp);
        DBG ("imee setup ... %X\n", KVM_IMEE_SETUP);
        break;
    case KVM_IMEE_RUN:
        r = start_guest_intercept (vcpu);
        if (r < 0) break;
		r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
        break;
    /* </Siqi> */
	case KVM_RUN:
		r = -EINVAL;
		if (arg)
			goto out;
		r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
		trace_kvm_userspace_exit(vcpu->run->exit_reason, r);
		break;
	case KVM_GET_REGS: {
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
		if (!kvm_regs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_regs(vcpu, kvm_regs);
		if (r)
			goto out_free1;
		r = -EFAULT;
		if (copy_to_user(argp, kvm_regs, sizeof(struct kvm_regs)))
			goto out_free1;
		r = 0;
out_free1:
		kfree(kvm_regs);
		break;
	}
	case KVM_SET_REGS: {
		struct kvm_regs *kvm_regs;

		r = -ENOMEM;
		kvm_regs = kzalloc(sizeof(struct kvm_regs), GFP_KERNEL);
		if (!kvm_regs)
			goto out;
		r = -EFAULT;
		if (copy_from_user(kvm_regs, argp, sizeof(struct kvm_regs)))
			goto out_free2;
		r = kvm_arch_vcpu_ioctl_set_regs(vcpu, kvm_regs);
		if (r)
			goto out_free2;
		r = 0;
out_free2:
		kfree(kvm_regs);
		break;
	}
	case KVM_GET_SREGS: {
		kvm_sregs = kzalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!kvm_sregs)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, kvm_sregs);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, kvm_sregs, sizeof(struct kvm_sregs)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_SREGS: {
		kvm_sregs = kmalloc(sizeof(struct kvm_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!kvm_sregs)
			goto out;
		r = -EFAULT;
		if (copy_from_user(kvm_sregs, argp, sizeof(struct kvm_sregs)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, kvm_sregs);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_GET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &mp_state, sizeof mp_state))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_MP_STATE: {
		struct kvm_mp_state mp_state;

		r = -EFAULT;
		if (copy_from_user(&mp_state, argp, sizeof mp_state))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_TRANSLATE: {
		struct kvm_translation tr;

		r = -EFAULT;
		if (copy_from_user(&tr, argp, sizeof tr))
			goto out;
		r = kvm_arch_vcpu_ioctl_translate(vcpu, &tr);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &tr, sizeof tr))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_GUEST_DEBUG: {
		struct kvm_guest_debug dbg;

		r = -EFAULT;
		if (copy_from_user(&dbg, argp, sizeof dbg))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset, *p;

		p = NULL;
		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof kvm_sigmask))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof sigset)
				goto out;
			r = -EFAULT;
			if (copy_from_user(&sigset, sigmask_arg->sigset,
					   sizeof sigset))
				goto out;
			p = &sigset;
		}
		r = kvm_vcpu_ioctl_set_sigmask(vcpu, p);
		break;
	}
	case KVM_GET_FPU: {
		fpu = kzalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
			goto out;
		r = kvm_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, fpu, sizeof(struct kvm_fpu)))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_FPU: {
		fpu = kmalloc(sizeof(struct kvm_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
			goto out;
		r = -EFAULT;
		if (copy_from_user(fpu, argp, sizeof(struct kvm_fpu)))
			goto out;
		r = kvm_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
		if (r)
			goto out;
		r = 0;
		break;
	}
	default:
		r = kvm_arch_vcpu_ioctl(filp, ioctl, arg);
	}
out:
	vcpu_put(vcpu);
	kfree(fpu);
	kfree(kvm_sregs);
	return r;
}

#ifdef CONFIG_COMPAT
static long kvm_vcpu_compat_ioctl(struct file *filp,
				  unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = compat_ptr(arg);
	int r;

	if (vcpu->kvm->mm != current->mm)
		return -EIO;

	switch (ioctl) {
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask __user *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		compat_sigset_t csigset;
		sigset_t sigset;

		if (argp) {
			r = -EFAULT;
			if (copy_from_user(&kvm_sigmask, argp,
					   sizeof kvm_sigmask))
				goto out;
			r = -EINVAL;
			if (kvm_sigmask.len != sizeof csigset)
				goto out;
			r = -EFAULT;
			if (copy_from_user(&csigset, sigmask_arg->sigset,
					   sizeof csigset))
				goto out;
		}
		sigset_from_compat(&sigset, &csigset);
		r = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		break;
	}
	default:
		r = kvm_vcpu_ioctl(filp, ioctl, arg);
	}

out:
	return r;
}
#endif

static long kvm_vm_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_CREATE_VCPU:
		r = kvm_vm_ioctl_create_vcpu(kvm, arg);
		if (r < 0)
			goto out;
		break;
	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region kvm_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&kvm_userspace_mem, argp,
						sizeof kvm_userspace_mem))
			goto out;

		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem, 1);
		if (r)
			goto out;
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof log))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		if (r)
			goto out;
		break;
	}
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof zone))
			goto out;
		r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof zone))
			goto out;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
		if (r)
			goto out;
		r = 0;
		break;
	}
#endif
	case KVM_IRQFD: {
		struct kvm_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
			goto out;
		r = kvm_irqfd(kvm, data.fd, data.gsi, data.flags);
		break;
	}
	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
			goto out;
		r = kvm_ioeventfd(kvm, &data);
		break;
	}
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_SET_BOOT_CPU_ID:
		r = 0;
		mutex_lock(&kvm->lock);
		if (atomic_read(&kvm->online_vcpus) != 0)
			r = -EBUSY;
		else
			kvm->bsp_vcpu_id = arg;
		mutex_unlock(&kvm->lock);
		break;
#endif
	default:
		r = kvm_arch_vm_ioctl(filp, ioctl, arg);
		if (r == -ENOTTY)
			r = kvm_vm_ioctl_assigned_device(kvm, ioctl, arg);
	}
out:
	return r;
}

#ifdef CONFIG_COMPAT
struct compat_kvm_dirty_log {
	__u32 slot;
	__u32 padding1;
	union {
		compat_uptr_t dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

static long kvm_vm_compat_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	int r;

	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_GET_DIRTY_LOG: {
		struct compat_kvm_dirty_log compat_log;
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&compat_log, (void __user *)arg,
				   sizeof(compat_log)))
			goto out;
		log.slot	 = compat_log.slot;
		log.padding1	 = compat_log.padding1;
		log.padding2	 = compat_log.padding2;
		log.dirty_bitmap = compat_ptr(compat_log.dirty_bitmap);

		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		if (r)
			goto out;
		break;
	}
	default:
		r = kvm_vm_ioctl(filp, ioctl, arg);
	}

out:
	return r;
}
#endif

static int kvm_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page[1];
	unsigned long addr;
	int npages;
	gfn_t gfn = vmf->pgoff;
	struct kvm *kvm = vma->vm_file->private_data;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return VM_FAULT_SIGBUS;

	npages = get_user_pages(current, current->mm, addr, 1, 1, 0, page,
				NULL);
	if (unlikely(npages != 1))
		return VM_FAULT_SIGBUS;

	vmf->page = page[0];
	return 0;
}

static const struct vm_operations_struct kvm_vm_vm_ops = {
	.fault = kvm_vm_fault,
};

static int kvm_vm_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_vm_vm_ops;
	return 0;
}

static struct file_operations kvm_vm_fops = {
	.release        = kvm_vm_release,
	.unlocked_ioctl = kvm_vm_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = kvm_vm_compat_ioctl,
#endif
	.mmap           = kvm_vm_mmap,
	.llseek		= noop_llseek,
};

static int kvm_dev_ioctl_create_vm(void)
{
	int r;
	struct kvm *kvm;

	kvm = kvm_create_vm();
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	r = kvm_coalesced_mmio_init(kvm);
	if (r < 0) {
		kvm_put_kvm(kvm);
		return r;
	}
#endif
	r = anon_inode_getfd("kvm-vm", &kvm_vm_fops, kvm, O_RDWR);
	if (r < 0)
		kvm_put_kvm(kvm);

	return r;
}

static long kvm_dev_ioctl_check_extension_generic(long arg)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_CAP_SET_BOOT_CPU_ID:
#endif
	case KVM_CAP_INTERNAL_ERROR_DATA:
		return 1;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	case KVM_CAP_IRQ_ROUTING:
		return KVM_MAX_IRQ_ROUTES;
#endif
	default:
		break;
	}
	return kvm_dev_ioctl_check_extension(arg);
}

static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;

	switch (ioctl) {
	case KVM_GET_API_VERSION:
		r = -EINVAL;
		if (arg)
			goto out;
		r = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM:
		r = -EINVAL;
		if (arg)
			goto out;
		r = kvm_dev_ioctl_create_vm();
		break;
	case KVM_CHECK_EXTENSION:
		r = kvm_dev_ioctl_check_extension_generic(arg);
		break;
	case KVM_GET_VCPU_MMAP_SIZE:
		r = -EINVAL;
		if (arg)
			goto out;
		r = PAGE_SIZE;     /* struct kvm_run */
#ifdef CONFIG_X86
		r += PAGE_SIZE;    /* pio data page */
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
		r += PAGE_SIZE;    /* coalesced mmio ring page */
#endif
		break;
	case KVM_TRACE_ENABLE:
	case KVM_TRACE_PAUSE:
	case KVM_TRACE_DISABLE:
		r = -EOPNOTSUPP;
		break;
	default:
		return kvm_arch_dev_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}

static struct file_operations kvm_chardev_ops = {
	.unlocked_ioctl = kvm_dev_ioctl,
	.compat_ioctl   = kvm_dev_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice kvm_dev = {
	KVM_MINOR,
	"kvm",
	&kvm_chardev_ops,
};

static void hardware_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;

	cpumask_set_cpu(cpu, cpus_hardware_enabled);

	r = kvm_arch_hardware_enable(NULL);

	if (r) {
		cpumask_clear_cpu(cpu, cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		printk(KERN_INFO "kvm: enabling virtualization on "
				 "CPU%d failed\n", cpu);
	}
}

static void hardware_enable(void *junk)
{
	raw_spin_lock(&kvm_lock);
	hardware_enable_nolock(junk);
	raw_spin_unlock(&kvm_lock);
}

static void hardware_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
		return;
	cpumask_clear_cpu(cpu, cpus_hardware_enabled);
	kvm_arch_hardware_disable(NULL);
}

static void hardware_disable(void *junk)
{
	raw_spin_lock(&kvm_lock);
	hardware_disable_nolock(junk);
	raw_spin_unlock(&kvm_lock);
}

static void hardware_disable_all_nolock(void)
{
	BUG_ON(!kvm_usage_count);

	kvm_usage_count--;
	if (!kvm_usage_count)
		on_each_cpu(hardware_disable_nolock, NULL, 1);
}

static void hardware_disable_all(void)
{
	raw_spin_lock(&kvm_lock);
	hardware_disable_all_nolock();
	raw_spin_unlock(&kvm_lock);
}

static int hardware_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&kvm_lock);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		atomic_set(&hardware_enable_failed, 0);
		on_each_cpu(hardware_enable_nolock, NULL, 1);

		if (atomic_read(&hardware_enable_failed)) {
			hardware_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&kvm_lock);

	return r;
}

static int kvm_cpu_hotplug(struct notifier_block *notifier, unsigned long val,
			   void *v)
{
	int cpu = (long)v;

	if (!kvm_usage_count)
		return NOTIFY_OK;

	val &= ~CPU_TASKS_FROZEN;
	switch (val) {
	case CPU_DYING:
		printk(KERN_INFO "kvm: disabling virtualization on CPU%d\n",
		       cpu);
		hardware_disable(NULL);
		break;
	case CPU_STARTING:
		printk(KERN_INFO "kvm: enabling virtualization on CPU%d\n",
		       cpu);
		hardware_enable(NULL);
		break;
	}
	return NOTIFY_OK;
}


asmlinkage void kvm_spurious_fault(void)
{
	/* Fault while not rebooting.  We want the trace. */
	BUG();
}
EXPORT_SYMBOL_GPL(kvm_spurious_fault);

static int kvm_reboot(struct notifier_block *notifier, unsigned long val,
		      void *v)
{
	/*
	 * Some (well, at least mine) BIOSes hang on reboot if
	 * in vmx root mode.
	 *
	 * And Intel TXT required VMX off for all cpu when system shutdown.
	 */
	printk(KERN_INFO "kvm: exiting hardware virtualization\n");
	kvm_rebooting = true;
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	return NOTIFY_OK;
}

static struct notifier_block kvm_reboot_notifier = {
	.notifier_call = kvm_reboot,
	.priority = 0,
};

static void kvm_io_bus_destroy(struct kvm_io_bus *bus)
{
	int i;

	for (i = 0; i < bus->dev_count; i++) {
		struct kvm_io_device *pos = bus->range[i].dev;

		kvm_iodevice_destructor(pos);
	}
	kfree(bus);
}

int kvm_io_bus_sort_cmp(const void *p1, const void *p2)
{
	const struct kvm_io_range *r1 = p1;
	const struct kvm_io_range *r2 = p2;

	if (r1->addr < r2->addr)
		return -1;
	if (r1->addr + r1->len > r2->addr + r2->len)
		return 1;
	return 0;
}

int kvm_io_bus_insert_dev(struct kvm_io_bus *bus, struct kvm_io_device *dev,
			  gpa_t addr, int len)
{
	if (bus->dev_count == NR_IOBUS_DEVS)
		return -ENOSPC;

	bus->range[bus->dev_count++] = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
		.dev = dev,
	};

	sort(bus->range, bus->dev_count, sizeof(struct kvm_io_range),
		kvm_io_bus_sort_cmp, NULL);

	return 0;
}

int kvm_io_bus_get_first_dev(struct kvm_io_bus *bus,
			     gpa_t addr, int len)
{
	struct kvm_io_range *range, key;
	int off;

	key = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	range = bsearch(&key, bus->range, bus->dev_count,
			sizeof(struct kvm_io_range), kvm_io_bus_sort_cmp);
	if (range == NULL)
		return -ENOENT;

	off = range - bus->range;

	while (off > 0 && kvm_io_bus_sort_cmp(&key, &bus->range[off-1]) == 0)
		off--;

	return off;
}

/* kvm_io_bus_write - called under kvm->slots_lock */
int kvm_io_bus_write(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val)
{
	int idx;
	struct kvm_io_bus *bus;
	struct kvm_io_range range;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(kvm->buses[bus_idx], &kvm->srcu);
	idx = kvm_io_bus_get_first_dev(bus, addr, len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_sort_cmp(&range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_write(bus->range[idx].dev, addr, len, val))
			return 0;
		idx++;
	}

	return -EOPNOTSUPP;
}

/* kvm_io_bus_read - called under kvm->slots_lock */
int kvm_io_bus_read(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
		    int len, void *val)
{
	int idx;
	struct kvm_io_bus *bus;
	struct kvm_io_range range;

	range = (struct kvm_io_range) {
		.addr = addr,
		.len = len,
	};

	bus = srcu_dereference(kvm->buses[bus_idx], &kvm->srcu);
	idx = kvm_io_bus_get_first_dev(bus, addr, len);
	if (idx < 0)
		return -EOPNOTSUPP;

	while (idx < bus->dev_count &&
		kvm_io_bus_sort_cmp(&range, &bus->range[idx]) == 0) {
		if (!kvm_iodevice_read(bus->range[idx].dev, addr, len, val))
			return 0;
		idx++;
	}

	return -EOPNOTSUPP;
}

/* Caller must hold slots_lock. */
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
			    int len, struct kvm_io_device *dev)
{
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm->buses[bus_idx];
	if (bus->dev_count > NR_IOBUS_DEVS-1)
		return -ENOSPC;

	new_bus = kzalloc(sizeof(struct kvm_io_bus), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;
	memcpy(new_bus, bus, sizeof(struct kvm_io_bus));
	kvm_io_bus_insert_dev(new_bus, dev, addr, len);
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);

	return 0;
}

/* Caller must hold slots_lock. */
int kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			      struct kvm_io_device *dev)
{
	int i, r;
	struct kvm_io_bus *new_bus, *bus;

	new_bus = kzalloc(sizeof(struct kvm_io_bus), GFP_KERNEL);
	if (!new_bus)
		return -ENOMEM;

	bus = kvm->buses[bus_idx];
	memcpy(new_bus, bus, sizeof(struct kvm_io_bus));

	r = -ENOENT;
	for (i = 0; i < new_bus->dev_count; i++)
		if (new_bus->range[i].dev == dev) {
			r = 0;
			new_bus->dev_count--;
			new_bus->range[i] = new_bus->range[new_bus->dev_count];
			sort(new_bus->range, new_bus->dev_count,
			     sizeof(struct kvm_io_range),
			     kvm_io_bus_sort_cmp, NULL);
			break;
		}

	if (r) {
		kfree(new_bus);
		return r;
	}

	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
	kfree(bus);
	return r;
}

static struct notifier_block kvm_cpu_notifier = {
	.notifier_call = kvm_cpu_hotplug,
};

static int vm_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;

	*val = 0;
	raw_spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		*val += *(u32 *)((void *)kvm + offset);
	raw_spin_unlock(&kvm_lock);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vm_stat_fops, vm_stat_get, NULL, "%llu\n");

static int vcpu_stat_get(void *_offset, u64 *val)
{
	unsigned offset = (long)_offset;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	int i;

	*val = 0;
	raw_spin_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		kvm_for_each_vcpu(i, vcpu, kvm)
			*val += *(u32 *)((void *)vcpu + offset);

	raw_spin_unlock(&kvm_lock);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(vcpu_stat_fops, vcpu_stat_get, NULL, "%llu\n");

static const struct file_operations *stat_fops[] = {
	[KVM_STAT_VCPU] = &vcpu_stat_fops,
	[KVM_STAT_VM]   = &vm_stat_fops,
};

static void kvm_init_debug(void)
{
	struct kvm_stats_debugfs_item *p;

	kvm_debugfs_dir = debugfs_create_dir("kvm", NULL);
	for (p = debugfs_entries; p->name; ++p)
		p->dentry = debugfs_create_file(p->name, 0444, kvm_debugfs_dir,
						(void *)(long)p->offset,
						stat_fops[p->kind]);
}

static void kvm_exit_debug(void)
{
	struct kvm_stats_debugfs_item *p;

	for (p = debugfs_entries; p->name; ++p)
		debugfs_remove(p->dentry);
	debugfs_remove(kvm_debugfs_dir);
}

static int kvm_suspend(void)
{
	if (kvm_usage_count)
		hardware_disable_nolock(NULL);
	return 0;
}

static void kvm_resume(void)
{
	if (kvm_usage_count) {
		WARN_ON(raw_spin_is_locked(&kvm_lock));
		hardware_enable_nolock(NULL);
	}
}

static struct syscore_ops kvm_syscore_ops = {
	.suspend = kvm_suspend,
	.resume = kvm_resume,
};

struct page *bad_page;
pfn_t bad_pfn;

static inline
struct kvm_vcpu *preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct kvm_vcpu, preempt_notifier);
}

static void kvm_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	kvm_arch_vcpu_load(vcpu, cpu);
}

static void kvm_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct kvm_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	kvm_arch_vcpu_put(vcpu);
}

int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align,
		  struct module *module)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);
	if (r)
		goto out_fail;

	bad_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (bad_page == NULL) {
		r = -ENOMEM;
		goto out;
	}

	bad_pfn = page_to_pfn(bad_page);

	hwpoison_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (hwpoison_page == NULL) {
		r = -ENOMEM;
		goto out_free_0;
	}

	hwpoison_pfn = page_to_pfn(hwpoison_page);

	fault_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (fault_page == NULL) {
		r = -ENOMEM;
		goto out_free_0;
	}

	fault_pfn = page_to_pfn(fault_page);

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}

	r = kvm_arch_hardware_setup();
	if (r < 0)
		goto out_free_0a;

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu,
				kvm_arch_check_processor_compat,
				&r, 1);
		if (r < 0)
			goto out_free_1;
	}

	r = register_cpu_notifier(&kvm_cpu_notifier);
	if (r)
		goto out_free_2;
	register_reboot_notifier(&kvm_reboot_notifier);

	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	if (!vcpu_align)
		vcpu_align = __alignof__(struct kvm_vcpu);
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size, vcpu_align,
					   0, NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_3;
	}

	r = kvm_async_pf_init();
	if (r)
		goto out_free;

	kvm_chardev_ops.owner = module;
	kvm_vm_fops.owner = module;
	kvm_vcpu_fops.owner = module;

	r = misc_register(&kvm_dev);
	if (r) {
		printk(KERN_ERR "kvm: misc device register failed\n");
		goto out_unreg;
	}

	register_syscore_ops(&kvm_syscore_ops);

	kvm_preempt_ops.sched_in = kvm_sched_in;
	kvm_preempt_ops.sched_out = kvm_sched_out;

	kvm_init_debug();

	return 0;

out_unreg:
	kvm_async_pf_deinit();
out_free:
	kmem_cache_destroy(kvm_vcpu_cache);
out_free_3:
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
out_free_2:
out_free_1:
	kvm_arch_hardware_unsetup();
out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);
out_free_0:
	if (fault_page)
		__free_page(fault_page);
	if (hwpoison_page)
		__free_page(hwpoison_page);
	__free_page(bad_page);
out:
	kvm_arch_exit();
out_fail:
	return r;
}
EXPORT_SYMBOL_GPL(kvm_init);

void kvm_exit(void)
{
	kvm_exit_debug();
	misc_deregister(&kvm_dev);
	kmem_cache_destroy(kvm_vcpu_cache);
	kvm_async_pf_deinit();
	unregister_syscore_ops(&kvm_syscore_ops);
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	free_cpumask_var(cpus_hardware_enabled);
	__free_page(hwpoison_page);
	__free_page(bad_page);
}
EXPORT_SYMBOL_GPL(kvm_exit);
