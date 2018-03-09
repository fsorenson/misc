/*
	Frank Sorenson <sorenson@redhat.com> 2018

	proclocks2.c - new /proc/locks2
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/lglock.h>

#include "nfsd_state.h"


#ifndef FL_OFDLCK
#define FL_OFDLCK 1024
#endif

#define IS_OFDLCK(fl)   (fl->fl_flags & FL_OFDLCK)
#ifndef IS_REMOTELCK
#define IS_REMOTELCK(fl)	(fl->fl_pid <= 0)
#endif

#define IS_POSIX(fl)    (fl->fl_flags & FL_POSIX)
#define IS_FLOCK(fl)    (fl->fl_flags & FL_FLOCK)
#define IS_LEASE(fl)    (fl->fl_flags & (FL_LEASE|FL_DELEG|FL_LAYOUT))

static bool lease_breaking(struct file_lock *fl) {
	return fl->fl_flags & (FL_UNLOCK_PENDING | FL_DOWNGRADE_PENDING);
}



struct lglock *proclocks2_file_lock_lglock;
spinlock_t *proclocks2_blocked_lock_lock;
struct hlist_head *proclocks2_file_lock_list;
struct lock_manager_operations_extend *proclocks2_nfsd_posix_mng_ops;


struct locks_iterator {
	int	li_cpu;
	loff_t	li_pos;
};

pid_t locks_translate_pid(struct file_lock *fl, struct pid_namespace *ns) {
	pid_t vnr;
	struct pid *pid;

	if (IS_OFDLCK(fl))
		return -1;
	if (IS_REMOTELCK(fl))
		return fl->fl_pid;
	rcu_read_lock();
	pid = find_pid_ns(fl->fl_pid, &init_pid_ns);
	vnr = pid_nr_ns(pid, ns);
	rcu_read_unlock();
	return vnr;
}

static void proclocks2_show_nfsd_lease_lockinfo(struct seq_file *f, struct file_lock *fl) {

}

static void proclocks2_show_nfsd_posix_lockinfo(struct seq_file *f, struct file_lock *fl) {
	struct nfs4_lockowner *lo = (struct nfs4_lockowner *)fl->fl_owner;
	struct nfs4_stateowner *so;
	struct nfs4_client *cl;
	char *cl_name;

	if (!lo)
		return;
	so = &lo->lo_owner;
	if (!so)
		return;
	cl = so->so_client;
	if (!cl)
		return;

	cl_name = cl->cl_name.data;
	if (!cl_name)
		return;
	seq_printf(f, "  (struct nfs4_lockowner *)%p\n", lo);
	seq_printf(f, "  (struct nfs4_stateowner *)%p, count %d: %s\n",
		so, so->so_count.counter, so->so_is_open_owner ? "openowner" : "lockowner");
	seq_printf(f, "  (struct nfs4_client *)%p name (len %u): %s\n",
		cl, cl->cl_name.len, cl_name);


/*
                print("\t(struct nfs4_lockowner *)0x{:016x}".format(nfs4_lockowner), end='')
                print(", '{}'".format(cl_name))
                print("\t** TODO: lockowners **")
*/

//	lmops = fl->fl_lmops;
//	inode = file->f_inode;
//	}
}
static void proclocks2_show_lm_info(struct seq_file *f, struct file_lock *fl) {
	struct file *file = fl->fl_file;
//	struct dentry *dentry;
//	struct inode *inode;
	struct lock_manager_operations *fl_lmops;

	if (!file)
		return;

//		dentry = file->f_path->f_dentry;
//		if (!dentry)
//			return;
//	}
	fl_lmops = fl->fl_lmops;

	if (fl_lmops == (struct lock_manager_operations *)proclocks2_nfsd_posix_mng_ops) {
		proclocks2_show_nfsd_posix_lockinfo(f, fl);
/*
		struct nfs_open_context *oc;

		oc = (struct nfs_open_context *)file->private_data
		if (!oc)
			return;
		// cred = oc.cred
		// show_cred(cred)
*/
	}
}

static void proclocks2_get_status(struct seq_file *f, struct file_lock *fl,
		loff_t id, char *pfx) {
	struct inode *inode = NULL;
	unsigned int fl_pid;
//	struct pid_namespace *proc_pidns = file_inode(f->file)->i_sb->s_fs_info;

//	fl_pid = locks_translate_pid(fl, proc_pidns);
	/*
	 * If there isn't a fl_pid don't display who is waiting on
	 * the lock if we are called from locks_show, or if we are
	 * called from __show_fd_info - skip lock entirely
	 */
	if (fl->fl_nspid)
		fl_pid = pid_vnr(fl->fl_nspid);
	else
		fl_pid = fl->fl_pid;

	if (fl->fl_file != NULL)
		inode = locks_inode(fl->fl_file);

	seq_printf(f, "%lld:%s ", id, pfx);
	if (IS_POSIX(fl)) {
		if (fl->fl_flags & FL_ACCESS)
			seq_printf(f, "ACCESS");
		else if (IS_OFDLCK(fl))
			seq_printf(f, "OFDLCK");
		else
			seq_printf(f, "POSIX ");

		seq_printf(f, " %s ",
			     (inode == NULL) ? "*NOINODE*" :
			     mandatory_lock(inode) ? "MANDATORY" : "ADVISORY ");
	} else if (IS_FLOCK(fl)) {
		if (fl->fl_type & LOCK_MAND) {
			seq_printf(f, "FLOCK  MSNFS     ");
		} else {
			seq_printf(f, "FLOCK  ADVISORY  ");
		}
	} else if (IS_LEASE(fl)) {
		seq_printf(f, "LEASE  ");
		if (lease_breaking(fl))
			seq_printf(f, "BREAKING  ");
		else if (fl->fl_file)
			seq_printf(f, "ACTIVE    ");
		else
			seq_printf(f, "BREAKER   ");
	} else {
		seq_printf(f, "UNKNOWN UNKNOWN  ");
	}
	if (fl->fl_type & LOCK_MAND) {
		seq_printf(f, "%s ",
			       (fl->fl_type & LOCK_READ)
			       ? (fl->fl_type & LOCK_WRITE) ? "RW   " : "READ "
			       : (fl->fl_type & LOCK_WRITE) ? "WRITE" : "NONE ");
	} else {
		seq_printf(f, "%s ",
			       (lease_breaking(fl))
			       ? (fl->fl_type == F_UNLCK) ? "UNLCK" : "READ "
			       : (fl->fl_type == F_WRLCK) ? "WRITE" : "READ ");
	}
	if (inode) {
#ifdef WE_CAN_BREAK_LSLK_NOW
		seq_printf(f, "%d %s:%ld ", fl_pid,
				inode->i_sb->s_id, inode->i_ino);
#else
		/* userspace relies on this representation of dev_t ;-( */
		seq_printf(f, "%d %02x:%02x:%ld ", fl_pid,
				MAJOR(inode->i_sb->s_dev),
				MINOR(inode->i_sb->s_dev), inode->i_ino);
#endif
	} else {
		seq_printf(f, "%d <none>:0 ", fl_pid);
	}
	if (IS_POSIX(fl)) {
		if (fl->fl_end == OFFSET_MAX)
			seq_printf(f, "%Ld EOF\n", fl->fl_start);
		else
			seq_printf(f, "%Ld %Ld\n", fl->fl_start, fl->fl_end);
	} else {
		seq_printf(f, "0 EOF\n");
	}

//	seq_printf(f, "    file_lock: %p\n", fl);
	if (inode) {
//		proclocks2_show_lm_info(f, nfs_fs_type);
		proclocks2_show_lm_info(f, fl);
	}

}

static int proclocks2_show(struct seq_file *f, void *v) {
	struct locks_iterator *iter = f->private;
	struct file_lock *fl, *bfl;
//	struct pid_namespace *proc_pidns = file_inode(f->file)->i_sb->s_fs_info;

	fl = hlist_entry(v, struct file_lock, fl_link);

//	if (locks_translate_pid(fl, proc_pidns) == 0)
//		return 0;
	proclocks2_get_status(f, fl, iter->li_pos, "");
	list_for_each_entry(bfl, &fl->fl_block, fl_block)
		proclocks2_get_status(f, bfl, iter->li_pos, " ->");

	return 0;
}

static void *proclocks2_start(struct seq_file *f, loff_t *pos) __acquires(blocked_lock_lock) {
	struct locks_iterator *iter = f->private;

	iter->li_pos = *pos + 1;
	lg_global_lock(proclocks2_file_lock_lglock);
	spin_lock(proclocks2_blocked_lock_lock);
	return seq_hlist_start_percpu(proclocks2_file_lock_list, &iter->li_cpu, *pos);
}

static void *proclocks2_next(struct seq_file *f, void *v, loff_t *pos) {
	struct locks_iterator *iter = f->private;

	++iter->li_pos;
	return seq_hlist_next_percpu(v, proclocks2_file_lock_list, &iter->li_cpu, pos);
}

static void proclocks2_stop(struct seq_file *f, void *v) __releases(blocked_lock_lock) {
	spin_unlock(proclocks2_blocked_lock_lock);
	lg_global_unlock(proclocks2_file_lock_lglock);
}

static const struct seq_operations proclocks2_seq_operations = {
	.start		= proclocks2_start,
	.next		= proclocks2_next,
	.stop		= proclocks2_stop,
	.show		= proclocks2_show,
};

static int proclocks2_open(struct inode *inode, struct file *filp) {
	return seq_open_private(filp, &proclocks2_seq_operations,
		sizeof(struct locks_iterator));
}

static const struct file_operations proclocks2_operations = {
	.open		= proclocks2_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

static int proclocks2_init(void) {
	proc_create("locks2", 0, NULL, &proclocks2_operations);


	proclocks2_file_lock_lglock = (struct lglock *)kallsyms_lookup_name("file_lock_lglock");
	proclocks2_blocked_lock_lock = (spinlock_t *)kallsyms_lookup_name("blocked_lock_lock");
	proclocks2_file_lock_list = (struct hlist_head *)kallsyms_lookup_name("file_lock_list");
	proclocks2_nfsd_posix_mng_ops = (struct lock_manager_operations_extend *)kallsyms_lookup_name("nfsd_posix_mng_ops");

	printk("nfsd_posix_mng_ops = %p", proclocks2_nfsd_posix_mng_ops);


	printk("proclocks2 module installed\n");
	return 0;
}
void proclocks2_exit(void) {
	remove_proc_entry("locks2", NULL);
	printk("proclocks2 module removed\n");
}
 
module_init(proclocks2_init);
module_exit(proclocks2_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to show file locks");
MODULE_LICENSE("GPL");
//MODULE_LICENSE("GPL v2");
