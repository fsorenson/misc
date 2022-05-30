/*
	Frank Sorenson <sorenson@redhat.com> 2017

	bz.c - reproduce the conditions in Red Hat bugzilla 1400159
		by burning cycles in __journal_remove_journal_head to widen
		the window in which another process might do Stuff (TM)
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>

/*
  PROBE_ADDR is the address of the first instruction of
    __journal_remove_journal_head inside jbd2_journal_put_journal_head

  There may be a better way to obtain this address, however:

  in the kernel source, for this particular kernel...
2507 void jbd2_journal_put_journal_head(struct journal_head *jh)
2508 {
2509         struct buffer_head *bh = jh2bh(jh);
2510 
2511         jbd_lock_bh_journal_head(bh);
2512         J_ASSERT_JH(jh, jh->b_jcount > 0);
2513         --jh->b_jcount;
2514         if (!jh->b_jcount) {
2515                 __journal_remove_journal_head(bh);
2516                 jbd_unlock_bh_journal_head(bh);


2477 static void __journal_remove_journal_head(struct buffer_head *bh)
2478 {
2479         struct journal_head *jh = bh2jh(bh);
2480 
2481         J_ASSERT_JH(jh, jh->b_jcount >= 0);
2482         J_ASSERT_JH(jh, jh->b_transaction == NULL);
2483         J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
2484         J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);

__journal_remove_journal_head is static, and pulled directly into jbd2_journal_put_journal_head
find the location in jbd2_journal_put_journal_head where the __journal_remove_journal_head
  code got placed

0xffffffffa0436aae <jbd2_journal_put_journal_head+46>:  mov    %eax,0x8(%rdi)
/usr/src/debug/kernel-3.10.0-327.10.1.el7/linux-3.10.0-327.10.1.el7.x86_64/fs/jbd2/journal.c: 2514
0xffffffffa0436ab1 <jbd2_journal_put_journal_head+49>:  je     0xffffffffa0436ac0 <jbd2_journal_put_journal_head+64>
...
/usr/src/debug/kernel-3.10.0-327.10.1.el7/linux-3.10.0-327.10.1.el7.x86_64/fs/jbd2/journal.c: 2477
0xffffffffa0436ac0 <jbd2_journal_put_journal_head+64>:  mov    0x40(%rbx),%r12
/usr/src/debug/kernel-3.10.0-327.10.1.el7/linux-3.10.0-327.10.1.el7.x86_64/fs/jbd2/journal.c: 2481
0xffffffffa0436ac4 <jbd2_journal_put_journal_head+68>:  mov    0x8(%r12),%edx
0xffffffffa0436ac9 <jbd2_journal_put_journal_head+73>:  test   %edx,%edx
0xffffffffa0436acb <jbd2_journal_put_journal_head+75>:  js     0xffffffffa0436b6b <jbd2_journal_put_journal_head+235>
/usr/src/debug/kernel-3.10.0-327.10.1.el7/linux-3.10.0-327.10.1.el7.x86_64/fs/jbd2/journal.c: 2482


  so we want to break in at 0xffffffffa0436ac0

*/

#define PROBE_ADDR 0xffffffffa0436ab1
#define LOOPS 10000UL

static unsigned long long times_hit = 0;

static struct jprobe bz1400159_probe;

void bz1400159_burn_cycles(void) {
	unsigned long l = LOOPS;

	times_hit++;

	while (l--)
		nop();

	jprobe_return();
}
int bz1400159_init(void) {
	bz1400159_probe.kp.addr = (kprobe_opcode_t *)PROBE_ADDR;
	bz1400159_probe.entry = (kprobe_opcode_t *)bz1400159_burn_cycles;
	register_jprobe(&bz1400159_probe);
	printk("bz1400159 module installed\n");
	return 0;
}
void bz1400159_exit(void) {
	unregister_jprobe(&bz1400159_probe);
	printk("bz1400159 module removed; probe hit %llu times\n", times_hit);
}
 
module_init(bz1400159_init);
module_exit(bz1400159_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to help replicate Red Hat bz1400159");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
