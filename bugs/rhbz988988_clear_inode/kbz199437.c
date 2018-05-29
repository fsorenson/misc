/*
	Frank Sorenson <sorenson@redhat.com> 2018

	kernel.org bz 199437
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

static struct jprobe kbz_199437_probe;

void kbz_199437_burn_cycles(void) {
	unsigned long l = LOOPS;

	while (l--)
		nop();

	jprobe_return();
}
int kbz_199437_init(void) {
	kbz_199437_probe.kp.addr = (kprobe_opcode_t *)PROBE_ADDR;
	kbz_199437_probe.entry = (kprobe_opcode_t *)kbz_199437_burn_cycles;
	register_jprobe(&kbz_199437_probe);
	printk("kbz_199437 module installed\n");
	return 0;
}
void kbz_199437_exit(void) {
	unregister_jprobe(&kbz_199437_probe);
	printk("kbz_199437 module removed\n");
}
 
module_init(kbz_199437_init);
module_exit(kbz_199437_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to help replicate kernel.org kbz_199437");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
