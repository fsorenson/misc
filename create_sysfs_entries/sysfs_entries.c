#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>

#define MODULE_NAME "sysfs_entries"
#define SYSFS_DIR "sysfs_entries"
#define MAX_NAME_LEN 15
#define MAX_ENTRIES (9999999U)

static struct kobject *sysfs_entries_dir = 0;
static struct kobj_attribute entry_attribute;
static char *generic_entry = "sysfs_entry";
static unsigned int num_entries = 100;

static ssize_t entry_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	strcpy(buf, generic_entry);
	return sizeof(generic_entry);
}

static int __init sysfs_entries_init (void) {
	int error = -ENOMEM;
	unsigned int i = 0;
	char tmp_entry[MAX_NAME_LEN];

	num_entries = min(num_entries, MAX_ENTRIES);
	if (! num_entries) {
		printk(KERN_WARNING MODULE_NAME ": no sysfs entries to create ... module exiting\n");
		error = -EINVAL;
		goto out;
	}

        if (!(sysfs_entries_dir = kobject_create_and_add(SYSFS_DIR, kernel_kobj))) {
		printk(KERN_WARNING MODULE_NAME ": failed to allocate kobject\n");
		goto out;
	}

	entry_attribute = (struct kobj_attribute){ .attr = { .name = generic_entry, .mode = 0444 },
		.show = entry_show };

	for (i = 0 ; i < num_entries ; i++) {
		snprintf(tmp_entry, MAX_NAME_LEN, "entry_%07u", i);

		entry_attribute.attr.name = tmp_entry;
		if ((error = sysfs_create_file(sysfs_entries_dir, &entry_attribute.attr))) {
			printk(KERN_WARNING MODULE_NAME ": failed to allocate memory for entry %d\n", i);
			goto out;
		}
	}

	entry_attribute.attr.name = generic_entry;
	error = 0;
	printk(KERN_WARNING MODULE_NAME ": module initialized successfully, after creating %d entries\n", num_entries);

out:
	if (error && sysfs_entries_dir)
		kobject_put(sysfs_entries_dir);

	return error;
}

static void __exit sysfs_entries_exit (void) {
	kobject_put(sysfs_entries_dir);

	printk(KERN_WARNING MODULE_NAME ": module exiting\n");
}

module_param(num_entries, uint, 0444);
MODULE_PARM_DESC(num_entries, "Number of entries to create.  Default: 100");

module_init(sysfs_entries_init);
module_exit(sysfs_entries_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frank Sorenson <sorenson@redhat.com");
