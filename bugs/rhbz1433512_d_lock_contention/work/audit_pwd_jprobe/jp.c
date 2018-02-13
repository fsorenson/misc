#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>

static struct dentry *dentry_of_death;

static int my_list_len(struct list_head *h) {
	int len = 0;
	struct dentry *d;

	list_for_each_entry(d, h, d_lru) {
		len ++;
	}
	return len;
}

void my_shrink_dentry_list(struct list_head *h) {
//	int offset = offsetof(struct dentry, d_lru);
	struct dentry *dentry = container_of(h->next, struct dentry, d_lru);
//	struct dentry *dentry = (struct dentry *)((char *)h - offset);
	struct super_block *sb = dentry->d_sb;

	printk("'%s' in shrink_dentry_list (dentry=%p, sb=%p, %s), len is %d\n", current->comm, dentry, sb, sb->s_id, my_list_len(h));
	jprobe_return();
}
 
static struct jprobe my_probe;
 
int myinit(void) {
	my_probe.kp.addr = (kprobe_opcode_t *)0xffffffffa1414e50;
	my_probe.entry = (kprobe_opcode_t *)my_shrink_dentry_list;
	register_jprobe(&my_probe);
	printk("jprobe module installed\n");
	return 0;
}
 
void myexit(void) {
	unregister_jprobe(&my_probe);
	printk("module removed\n");
}
 
module_init(myinit);
module_exit(myexit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to probe part of dentry shrinker");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
