/*
	Frank Sorenson <sorenson@redhat.com>
	2019
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>
#include <uapi/linux/unistd.h>

#define MODULE_NAME "mount_hook"

static unsigned long **sctable;
asmlinkage long (*real_sys_mount)(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);

static bool resolve_path = true;

int make_rw(unsigned long addr) {
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	if(pte->pte & ~_PAGE_RW)
		pte->pte |= _PAGE_RW;

	return 0;
}
int make_ro(unsigned long addr) {
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	pte->pte &= ~_PAGE_RW;

	return 0;
}

asmlinkage long mount_hook(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data) {
	char kdev_name[256];
	char kdir_name[256];
	char ktype[32];
	long ret;

	if (copy_from_user(kdev_name, dev_name, 256) != 0)
		return -EFAULT;
	if (copy_from_user(kdir_name, dir_name, 256) != 0)
		return -EFAULT;
	if (copy_from_user(ktype, type, 32) != 0)
		return -EFAULT;

	printk(MODULE_NAME ":  sys_mount - mounting '%s' of type '%s' on '%s'\n", kdev_name, ktype, kdir_name);
	ret = real_sys_mount(dev_name, dir_name, type, flags, data);

	if (ret) {
		printk(MODULE_NAME ":  received error while mounting '%s' of type '%s' on '%s': %ld\n", kdev_name, ktype, kdir_name, ret);
	} else {
		printk(MODULE_NAME ":  successfully mounted '%s' of type '%s' on '%s'\n", kdev_name, ktype, kdir_name);

		if (resolve_path && dir_name[0] == '/') { /* absolute path */
			struct path path;
			printk(MODULE_NAME ":  resolving full path\n");
			if ((kern_path(dir_name, 0, &path) == 0)) {
				char *tmp = (char*)__get_free_page(GFP_TEMPORARY);
				char *pathname;
				int len;
				if (tmp) {
					pathname = d_path(&path, tmp, PAGE_SIZE);
					len = PTR_ERR(pathname);
					if (IS_ERR(pathname))
						goto out_free_page;
					len = tmp + PAGE_SIZE - 1 - pathname;

					printk(MODULE_NAME ":  full path: %s\n", pathname);
					path_put(&path);
out_free_page:
					free_page((unsigned long)tmp);
				}
			}
		}
	}
	printk(MODULE_NAME ":  mount returning %ld\n", ret);
	return ret;
}

int mount_hook_init(void) {
	printk("mount_hook: module initializing\n");

	sctable = (unsigned long**)kallsyms_lookup_name("sys_call_table");
	if (!sctable) {
		printk("mount_hook: could not find address for sys_call_table.  Exiting\n");
		return -1;
	}
	real_sys_mount = (typeof(real_sys_mount))sctable[__NR_mount];
	if (!real_sys_mount) {
		printk("mount_hook: could not find address for sys_mount.  Exiting\n");
		return -1;
	}

	printk(MODULE_NAME ":  sys_call_table: %p\n", sctable);
	printk(MODULE_NAME ":  __NR_mount: %d\n", __NR_mount);
	printk(MODULE_NAME ":  &sys_call_table[%d]: %p\n", __NR_mount, &sctable[__NR_mount]);
	printk(MODULE_NAME ":  sys_call_table[%d]: 0x%p\n", __NR_mount, sctable[__NR_mount]);
	printk(MODULE_NAME ":  sys_mount: %p\n", real_sys_mount);

	make_rw((unsigned long)sctable);
	sctable[__NR_mount] = (unsigned long *)mount_hook;
	make_ro((unsigned long)sctable);

	return 0;
}
void mount_hook_exit(void) {
	make_rw((unsigned long)sctable);
	sctable[__NR_mount] = (unsigned long *)real_sys_mount;
	make_ro((unsigned long)sctable);

	printk("mount_hook: module exiting\n");
}

module_init(mount_hook_init);
module_exit(mount_hook_exit);
 
module_param(resolve_path, bool, 0644);
MODULE_PARM_DESC(resolve_path, "fully resolve the mount path");

MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to hook mount syscall");
MODULE_LICENSE("GPL");
