/*
	Frank Sorenson <sorenson@redhat.com> 2017

	bz988988.c - reproduce the conditions in Red Hat bugzilla 988988
		by burning cycles in find_get_pages to widen the window in
		which another process might also invalidate pages
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

#define PROBE_ADDR 0xffffffff8112729b
#define LOOPS 10000UL

static struct jprobe bz988988_probe;

void bz988988_burn_cycles(void) {
	unsigned long l = LOOPS;

	while (l--)
		nop();

	jprobe_return();
}
int bz988988_init(void) {
	bz988988_probe.kp.addr = (kprobe_opcode_t *)PROBE_ADDR;
	bz988988_probe.entry = (kprobe_opcode_t *)bz988988_burn_cycles;
	register_jprobe(&bz988988_probe);
	printk("bz988988 module installed\n");
	return 0;
}
void bz988988_exit(void) {
	unregister_jprobe(&bz988988_probe);
	printk("bz988988 module removed\n");
}
 
module_init(bz988988_init);
module_exit(bz988988_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to help replicate Red Hat bz988988");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
