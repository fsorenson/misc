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

/*
  PROBE_ADDR is the address of the first instruction after returning
  from radix_tree_gang_lookup_slot() in the function find_get_pages()

  There may be a better way to obtain this address, however:

# echo "dis find_get_pages | grep radix_tree_gang_lookup_slot -A1" | crash -s --minimal
NOTE: minimal mode commands: log, dis, rd, sym, eval, set, extend and exit

0xffffffff81127296 <find_get_pages+54>:	callq  0xffffffff81295500 <radix_tree_gang_lookup_slot>
0xffffffff8112729b <find_get_pages+59>:	test   %eax,%eax

  the address is 0xffffffff8112729b

*/

#define PROBE_ADDR 0xffffffffc0947f0f
#define LOOPS 10000UL

static struct jprobe bz1656674_probe;
static struct kprobe nfs_grow_file_probe;
static struct kprobe nfs_write_error_remove_page_probe;
static struct kretprobe nfs_write_error_remove_page_retprobe;


static unsigned long grow_hit = 0;
static unsigned long nfs_write_eror_remove_hit = 0;
static unsigned long nfs_write_eror_remove_ret_hit = 0;
static atomic_t nfs_write_error_count; 


void bz1656674_burn_cycles(void) {
	unsigned long l = LOOPS;

	while (l--)
		nop();

	jprobe_return();
}
int bz1656674_pre_handler(struct kprobe *p, struct pt_regs *regs) {
	struct page *pg = (struct page *)regs->dx;
	int countdown = 10000;

	while (pg->mapping && countdown-- > 0) {
		nop();
	}
	return 0;
}
int nfs_grow_file_pre_handler(struct kprobe *p, struct pt_regs *regs) {
	struct page *pg = (struct page *)regs->di;
	unsigned int offset = regs->si;
	unsigned int count = regs->dx;

	int countdown = 10000;
	grow_hit++;

	while (pg->mapping && countdown-- > 0) {
		nop();
	}
	return 0;
}

// one arg: (struct nfs_page *req)
int nfs_write_error_remove_page_pre_handler(struct kprobe *p, struct pt_regs *regs) {
	struct nfs_page *req = (struct nfs_page *)regs->di;

	nfs_write_eror_remove_hit++;
	atomic_inc(&nfs_write_error_count);

	return 0;
}
int nfs_write_error_remove_page_retprobe_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	int countdown = 10000;

	nfs_write_eror_remove_ret_hit++;
	atomic_dec(&nfs_write_error_count);

	while (countdown-- > 0)
		nop();

	return 0;
}



int bz1656674_init(void) {
	nfs_grow_file_probe.symbol_name = "nfs_grow_file";
	nfs_grow_file_probe.pre_handler = nfs_grow_file_pre_handler;
	register_kprobe(&nfs_grow_file_probe);

	atomic_set(&nfs_write_error_count, 0);
	nfs_write_error_remove_page_probe.symbol_name = "nfs_write_error_remove_page";
	nfs_write_error_remove_page_probe.pre_handler = nfs_write_error_remove_page_pre_handler;
	register_kprobe(&nfs_write_error_remove_page_probe);


	nfs_write_error_remove_page_retprobe.handler = nfs_write_error_remove_page_retprobe_handler;
	nfs_write_error_remove_page_retprobe.maxactive = 3;
	nfs_write_error_remove_page_retprobe.kp.symbol_name = "nfs_write_error_remove_page";
	register_kretprobe(&nfs_write_error_remove_page_retprobe);


	bz1656674_probe.kp.addr = (kprobe_opcode_t *)PROBE_ADDR;
	bz1656674_probe.kp.pre_handler = bz1656674_pre_handler;
//	bz1656674_probe.entry = (kprobe_opcode_t *)bz1656674_burn_cycles;
//	register_jprobe(&bz1656674_probe);

	printk("bz1656674 module installed\n");
	return 0;
}
void bz1656674_exit(void) {
//	unregister_jprobe(&bz1656674_probe);
	unregister_kprobe(&nfs_grow_file_probe);
	unregister_kprobe(&nfs_write_error_remove_page_probe);
	unregister_kretprobe(&nfs_write_error_remove_page_retprobe);

	printk("grow_hit occurred %lu times\n", grow_hit);
	printk("nfs_write_eror_remove_hit %lu times\n", nfs_write_eror_remove_hit);
	printk("nfs_write_eror_remove_ret_hit %lu times\n", nfs_write_eror_remove_ret_hit);
	printk("bz1656674 module removed\n");
}
 
module_init(bz1656674_init);
module_exit(bz1656674_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to help replicate Red Hat bz1656674");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
