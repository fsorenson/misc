/*
	Frank Sorenson <sorenson@redhat.com> 2018

	bz1656674.c - reproduce the conditions in Red Hat bugzilla 1656674
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>

#define LOOPS 10000UL

struct probe_data {
	struct kprobe probe;
	unsigned long count;
	char *name;
	unsigned long delay;
	char *loc;
};


int generic_count_handler(struct kprobe *p, struct pt_regs *regs);

#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)

#define ___PASTE(a,b)           a##b
#define ___PASTE3(a,b,c)        a##b##c
#define ___PASTE4(a,b,c,d)      a##b##c##d

#define __PASTE(a,b)            ___PASTE(a,b)
#define __PASTE3(a,b,c)         ___PASTE3(a,b,c)
#define __PASTE4(a,b,c,d)       ___PASTE4(a,b,c,d)



#define ADD_PROBE_ENTRY(func, probe_func, off, delay_cycles) { \
	.probe = { \
		.symbol_name = __XSTR(probe_func), \
		.pre_handler = generic_count_handler, \
		.offset = off, \
	}, \
	.name = __XSTR(func), \
	.loc = __XSTR(probe_func) "+" __XSTR(off) "", \
	.delay = delay_cycles, \
	.count = 0, \
}
//	.loc = __PASTE4(__XSTR(probe_func), +, off, ""), \

#define COUNTER_ENTRY_MASQ(func, probe_func, off) \
	ADD_PROBE_ENTRY(func, probe_func, off, 0)

#define COUNTER_ENTRY(func) \
	ADD_PROBE_ENTRY(func, func, 0, 0)

#define GARBAGE_GARBAGE \
	.probe = { \
		.symbol_name = __XSTR(func), \
		.pre_handler = generic_count_handler, \
	}, \
	.name = __XSTR(func), \
	.count = 0 \
}

//#define 



//	COUNTER_ENTRY_MASQ(nfs_grow_file, nfs_updatepage, 423),

static struct probe_data probes[] = {
	ADD_PROBE_ENTRY(nfs_grow_file, nfs_updatepage, 423, 100000),
	ADD_PROBE_ENTRY(nfs_readpage_async, nfs_readpage_async, 0, 100000),

	ADD_PROBE_ENTRY(nfs_write_error_remove_page, nfs_do_writepage, 363, 0),

	COUNTER_ENTRY(nfs_context_set_write_error),

/*
        @<nfs_do_writepage+519>
                int     error
                struct nfs_open_context*        ctx
        @<nfs_commit_release_pages+260>
                int     error
                struct nfs_open_context*        ctx
        @<nfs_write_completion+325>
                int     error
                struct nfs_open_context*        ctx

*/



	COUNTER_ENTRY_MASQ(nfs_set_page_writeback, nfs_do_writepage, 104),
	COUNTER_ENTRY(nfs_updatepage),
	COUNTER_ENTRY(nfs_lock_and_join_requests),
	COUNTER_ENTRY(nfs_do_writepage),
	COUNTER_ENTRY(nfs_pageio_add_request),

	COUNTER_ENTRY(nfs_pageio_cond_complete),

	COUNTER_ENTRY_MASQ(nfs_page_async_flush, nfs_do_writepage, 66), 

	COUNTER_ENTRY_MASQ(nfs_writepage_setup, nfs_updatepage, 170),
	COUNTER_ENTRY_MASQ(nfs_setup_write_request, nfs_updatepage, 170),

};

int generic_count_handler(struct kprobe *p, struct pt_regs *regs) {
	struct probe_data *my_data = container_of(p, struct probe_data, probe);
	my_data->count++;

	if (my_data->delay) {
		unsigned long delay = my_data->delay;
		while (delay-- > 0)
			nop();
	}
	return 0;
}

void output_counts(void) {
	int i;

	for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++)
		printk("%s count: %lu\n", probes[i].name, probes[i].count);
}
void unregister_probes(void) {
	int i;

	for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++)
		unregister_kprobe(&probes[i].probe);
}

int func_counts_init(void) {
	int i;
	int ret;

	for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++) {
		ret = register_kprobe(&probes[i].probe);
		if (ret == 0)
			printk("registered counter for '%s' (%s)\n", probes[i].name, probes[i].loc);
		else
			printk("error registering counter for '%s': %d\n", probes[i].name, ret);

	}

	printk("func_counts module installed\n");
	return 0;
}
void func_counts_exit(void) {
	output_counts();
	unregister_probes();
	printk("func_counts module exiting\n");
}
 
module_init(func_counts_init);
module_exit(func_counts_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to count function hits with bz1656674");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
