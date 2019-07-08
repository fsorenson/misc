/*
	Frank Sorenson <sorenson@redhat.com> 2019

	bz1723537.c - reproduce the conditions in Red Hat bugzilla 1723537
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>

#include <linux/sunrpc/xprt.h>

#define MODULE_NAME "bz1723537"

#define ORIG_svc_conn_age_period (60 * 6 * HZ)
#define NEW_svc_conn_age_period (2 * 1 * HZ)

#define ORIG_XS_IDLE_DISC_TO (60 * 5 * HZ)
#define NEW_XS_IDLE_DISC_TO (NEW_svc_conn_age_period * 5)

#define DEBUG 0


#define output(args...) do { \
	printk(KERN_WARNING MODULE_NAME ": " args); \
} while (0)

#define debug_output(args...) do { \
	if (DEBUG) \
		output(args); \
} while (0)

#define STR(_x) #_x
#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)

#define LITERAL_32bit(_x) (_x & 0xff), ((_x >> 8) & 0xff), ((_x >> 16) & 0xff), ((_x >> 24) & 0xff)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

struct sar_struct {
	int len;
	unsigned char *needle;	/* bytes of instruction */
	unsigned char *replacement; /* bytes of replacement instruction */
	char *opcode_string;	/* descriptive string */
	char *function;		/* function name */
	int search_start;	/* bytes into the function to begin searching */
	int search_len;		/* maximum number of bytes to search */
	void *func_addr;	/* stored address of the function, when found */
	void *addr;		/* address of instructions to replace or replaced */
	int replaced;
};
static struct sar_struct sars[] = {
/*
svc_age_temp_xprts() {
...
        mod_timer(&serv->sv_temptimer, jiffies + svc_conn_age_period * HZ);

// 3.10.0-862.9.1.x86_64
0xffffffffc04177e4 <svc_age_temp_xprts+0x94>:   add    $0x57e40,%rsi
0xffffffffc04177eb <svc_age_temp_xprts+0x9b>:   callq  0xffffffffb32a4a50 <mod_timer>

	opcode:
		add    $0x57e40,%rsi

	works with:
		3.10.0-862.9.1.x86_64
		3.10.0-957.10.1.el7.x86_64
		5.1.0-fs1+
*/
	{
		.opcode_string = "'add $" STR(ORIG_svc_conn_age_period) ",%rsi' => 'add $" STR(NEW_svc_conn_age_period) ",%rsi'",
		.needle = (char []){ 0x48, 0x81, 0xc6, LITERAL_32bit(ORIG_svc_conn_age_period) },
		.replacement = (char[]){ 0x48, 0x81, 0xc6, LITERAL_32bit(NEW_svc_conn_age_period) },
		.len = 7,
		.function = "svc_age_temp_xprts",
		.search_start = 0,
		.search_len = 1000,
	},
/*
svc_recv -> svc_handle_xprt -> svc_add_new_temp_xprt
                setup_timer(&serv->sv_temptimer, svc_age_temp_xprts,
                            (unsigned long)serv);
                mod_timer(&serv->sv_temptimer,
                          jiffies + svc_conn_age_period * HZ);

0xffffffffc0451592 <svc_recv+2866>:     add    $0x57e40,%rsi
0xffffffffc0451599 <svc_recv+2873>:     mov    %rax,%rdi

	opcode:
		add    $0x57e40,%rsi

	opcode works with:
		3.10.0-862.9.1.x86_64
		3.10.0-957.10.1.el7.x86_64
		5.1.0-fs1+
*/
	{
		.opcode_string = "'add $" STR(ORIG_svc_conn_age_period) ",%rsi' => 'add $" STR(NEW_svc_conn_age_period) ",%rsi'",
		.needle = (char []){ 0x48, 0x81, 0xc6, LITERAL_32bit(ORIG_svc_conn_age_period) },
		.replacement = (char[]){ 0x48, 0x81, 0xc6, LITERAL_32bit(NEW_svc_conn_age_period) },
		.len = 7,
		.function = "svc_recv",
		.search_start = 2500,
		.search_len = 1000,
	},

/* client idle timeout: XS_IDLE_DISC_TO
static struct rpc_xprt *xs_setup_local(struct xprt_create *args)
        xprt->idle_timeout = XS_IDLE_DISC_TO;

static struct rpc_xprt *xs_setup_udp(struct xprt_create *args)
        xprt->idle_timeout = XS_IDLE_DISC_TO;

static struct rpc_xprt *xs_setup_tcp(struct xprt_create *args)
        xprt->idle_timeout = XS_IDLE_DISC_TO;

// 3.10.0-862.9.1.x86_64
0xffffffffc03fd5a8 <xs_setup_tcp+0x78>: movq   $0x493e0,0x4c0(%rax)
0xffffffffc03fd5b3 <xs_setup_tcp+0x83>: xor    %edx,%edx

	opcode (all 3 functions):
		movq   $0x493e0,0x4c0(%rax)
                48 c7 80 c0 04 00 00 e0 93 04 00

	opcode works with:
		3.10.0-862.9.1.x86_64
		3.10.0-957.10.1.el7.x86_64
*/
/* 5.1.0-fs1+
0xffffffffc0719276 <xs_setup_local+182>:        lea    0x8(%rbx),%rdi
0xffffffffc071927a <xs_setup_local+186>:        movq   $0x493e0,0x3b0(%rbx)

0xffffffffc0718ee2 <xs_setup_udp+178>:  lea    0x8(%rbx),%rdi
0xffffffffc0718ee6 <xs_setup_udp+182>:  movq   $0x493e0,0x3b0(%rbx)

0xffffffffc0718b20 <xs_setup_tcp+208>:  lea    0x8(%rbx),%rdi
0xffffffffc0718b24 <xs_setup_tcp+212>:  movq   $0x493e0,0x3b0(%rbx)

opcode sequence:
		48 c7 83 b0 03 00 00 e0 93 04 00
*/
#if 0
/* earlier kernels with 11-byte character sequences */
#define XS_SETUP_opcode_string "'movq $" STR(ORIG_XS_IDLE_DISC_TO) ",0x4c0(%rax)' => 'movq $" STR(NEW_XS_IDLE_DISC_TO) ",0x4c0(%rax)'"
#define XS_SETUP_needle (char []){ 0x48, 0xc7, 0x80, 0xc0, 0x04, 0x00, 0x00, LITERAL_32bit(ORIG_XS_IDLE_DISC_TO) }
#define XS_SETUP_replacement (char[]){ 0x48, 0xc7, 0x80, 0xc0, 0x04, 0x00, 0x00, LITERAL_32bit(NEW_XS_IDLE_DISC_TO) }
#define XS_SETUP_len 11
#endif

/* use 6-byte character sequence to accommodate RHEL7 and newer kernels */
#define XS_SETUP_opcode_string "'movq $" STR(ORIG_XS_IDLE_DISC_TO) ",0x???(%r??)' => 'movq $" STR(NEW_XS_IDLE_DISC_TO) ",0x???(%r??)'"
#define XS_SETUP_needle (char []){ 0x00, 0x00, LITERAL_32bit(ORIG_XS_IDLE_DISC_TO) }
#define XS_SETUP_replacement (char[]){ 0x00, 0x00, LITERAL_32bit(NEW_XS_IDLE_DISC_TO) }
#define XS_SETUP_len 6
	{
		.opcode_string = XS_SETUP_opcode_string,
		.needle = XS_SETUP_needle,
		.replacement = XS_SETUP_replacement,
		.len = XS_SETUP_len,
		.function = "xs_setup_local",
		.search_start = 50,
		.search_len = 200,
	},
	{
		.opcode_string = XS_SETUP_opcode_string,
		.needle = XS_SETUP_needle,
		.replacement = XS_SETUP_replacement,
		.len = XS_SETUP_len,
		.function = "xs_setup_udp",
		.search_start = 50,
		.search_len = 200,
	},
	{
		.opcode_string = XS_SETUP_opcode_string,
		.needle = XS_SETUP_needle,
		.replacement = XS_SETUP_replacement,
		.len = XS_SETUP_len,
		.function = "xs_setup_tcp",
		.search_start = 50,
		.search_len = 200,
	},
};
#define NUM_SARS (ARRAY_SIZE(sars))

typedef int (*relevant_func_t)(void);
int generic_probe_handler(struct kprobe *p, struct pt_regs *regs);
int xprt_unlock_connect_handler(struct kprobe *p, struct pt_regs *regs);
/* some generic probes */
struct probe_data {
	struct kprobe probe;
	kprobe_pre_handler_t action;	/* additional action to take */
	unsigned long count;		/* count of probe hits */
	relevant_func_t relevant;	/* function to determine relevance - return 0 to skip, 1 to continue */
	char *name;			/* string name of function */
	unsigned long delay;		/* cycles to delay */
	char *loc;			/* string description of probe location */
	int log_probe;			/* report probe hits */
};

#define FULL_ADD_PROBE_ENTRY(_func, _probe_func, _off, _action_handler, _log_probe, _delay_cycles, _relevant) { \
        .probe = { \
                .symbol_name = __XSTR(_probe_func), \
                .pre_handler = generic_probe_handler, \
                .offset = _off, \
        }, \
	.action = _action_handler, \
        .name = __XSTR(_func), \
        .loc = __XSTR(_probe_func) "+" __XSTR(off) "", \
	.log_probe = _log_probe, \
        .delay = _delay_cycles, \
        .count = 0, \
	.relevant = _relevant, \
}

#define ADD_PROBE_ENTRY_SIMPLE(_func, _probe_func, _off, _log_probe, _delay_cycles) \
	FULL_ADD_PROBE_ENTRY(_func, _probe_func, _off, NULL, _log_probe, _delay_cycles, 0) /* relevant = 0 */
#define ADD_PROBE_ENTRY_RELEVANT(_func, _probe_func, _off, _log_probe, _delay_cycles, _relevant) \
	FULL_ADD_PROBE_ENTRY(_func, _probe_func, _off, NULL, _log_probe, _delay_cycles, _relevant)
#define COUNTER_ENTRY_MASQ(_func, _probe_func, _off) \
        ADD_PROBE_ENTRY_SIMPLE(_func, _probe_func, _off, 0, 0)
#define COUNTER_ENTRY(_func) \
        ADD_PROBE_ENTRY_SIMPLE(_func, _func, 0, 0, 0)

int xprt_release_relevant_func(void) {
	if (!strcmp(current->comm, "ls"))
		return 0;
	return 1;
}

static struct probe_data probes[] = {
	FULL_ADD_PROBE_ENTRY(xprt_unlock_connect, xprt_unlock_connect, 0, xprt_unlock_connect_handler, 0, 0, NULL),
};

unsigned char *search_mem(unsigned char *haystack, unsigned char *needle, int haystack_len, int needle_len) {
	unsigned char *p;

	for (p = haystack ; p < haystack + haystack_len - needle_len ; p++) {
		if (! memcmp(p, needle, needle_len))
			return p;
	}
	return NULL;
}
#define NUM_PAGES(addr, len) (((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1)

static int (*bz1723537_set_memory_rw)(unsigned long addr, int numpages) = 0;
static int (*bz1723537_set_memory_ro)(unsigned long addr, int numpages) = 0;
void change_perms(void *addr, unsigned long len, int rw) {
	unsigned long aligned_addr = (unsigned long)addr & PAGE_MASK;
	int num_pages = NUM_PAGES((unsigned long)addr, len);

	if (len < 1)
		return;

	debug_output("%sfutzing permissions for %d page(s) at %p",
		rw ? "" : "un", num_pages, (void *)aligned_addr);

	if (rw)
		bz1723537_set_memory_rw(aligned_addr, num_pages);
	else
		bz1723537_set_memory_ro(aligned_addr, num_pages);

}
void futz_perms(void *addr, unsigned long len) {
	change_perms(addr, len, 1);
}
void unfutz_perms(void *addr, unsigned long len) {
	change_perms(addr, len, 0);
}
int sars_do_replacements(int forward) {
	char *needle, *replacement;
	struct sar_struct *sar;
	int bytes_replaced = 0;
	char *p;
	int i, insn_i;

	for (i = 0 ; i < NUM_SARS ; i++) {
		sar = &sars[i];
		p = sar->addr;
		if (forward) {
			needle = sar->needle;
			replacement = sar->replacement;
		} else {
//			if (!sar->replaced) /* don't replace back to original if we already are */
//				continue;
			needle = sar->replacement;
			replacement = sar->needle;
		}
		futz_perms(p, sar->len);
		for (insn_i = 0 ; insn_i < sar->len ; insn_i++) {
			if ((p[insn_i] == needle[insn_i]) && (needle[insn_i] != replacement[insn_i])) {
				p[insn_i] = replacement[insn_i];
				bytes_replaced++;
			}
		}
		unfutz_perms(p, sar->len);
	}
	if (bytes_replaced)
		sar->replaced = 1;
	return bytes_replaced;
}
int _sars_find_addr(struct sar_struct *sar, unsigned char *needle) {
	void *start_addr;

	sar->func_addr = (void *)kallsyms_lookup_name(sar->function);
	start_addr = sar->func_addr + sar->search_start;
	sar->addr = search_mem(start_addr, needle, sar->search_len, sar->len);

	if (sar->addr == 0) {
		output("Could not find opcode '%s' in function '%s' for replacement\n",
			sar->opcode_string, sar->function);
	} else {
		output("Located bytes for opcode '%s' in function '%s'\n",
			sar->opcode_string, sar->function);
	}

	return (sar->addr != 0);
}

int sars_find_addr(struct sar_struct *sar) {
	return _sars_find_addr(sar, sar->needle);
}
int sars_find_addr_reverse(struct sar_struct *sar) {
	return _sars_find_addr(sar, sar->replacement);
}

int sars_find_addrs(void) {
	int found_addrs = 0;
	int ret;
	int i;

	for (i = 0 ; i < NUM_SARS ; i++) {
		if (!(ret = sars_find_addr(&sars[i])))
			ret = sars_find_addr_reverse(&sars[i]);

		found_addrs += ret;
	}
	return found_addrs;
}
int search_and_replace(void) {
	int ret;
	int i;

	if ((ret = sars_find_addrs()) != NUM_SARS) {
		output("unable to locate %d replacement location(s)\n", (int)(NUM_SARS - ret));
		return -1;
	}
	ret = sars_do_replacements(1);
	debug_output("changed %d bytes\n", ret);

	/* output some data that makes us look cool */
	for (i = 0 ; i < NUM_SARS ; i++) {
		output("replacement %d: function %s (%p) offset 0x%08lx (%p)\n",
			i, sars[i].function, sars[i].func_addr, sars[i].addr - sars[i].func_addr, sars[i].addr);
		output("\t%s\n", sars[i].opcode_string);
	}

	return 0;
}

int generic_probe_handler(struct kprobe *p, struct pt_regs *regs) {
        struct probe_data *my_data = container_of(p, struct probe_data, probe);

	if (my_data->relevant && !my_data->relevant())
		return 0;

	if (my_data->action)
		my_data->action(p, regs);

        my_data->count++;

	if (my_data->log_probe)
		output("%s hit probe at '%s' (%lu)\n", current->comm, my_data->name, my_data->count);

        if (my_data->delay) {
                unsigned long delay = my_data->delay;
                while (delay-- > 0)
                        nop();
        }
        return 0;
}

//void xprt_unlock_connect(struct rpc_xprt *, void *);
int xprt_unlock_connect_handler(struct kprobe *p, struct pt_regs *regs) {
//	struct probe_data *my_data = container_of(p, struct probe_data, probe);
	struct rpc_xprt *xprt = (struct rpc_xprt *)regs->si;

	xprt->idle_timeout = NEW_XS_IDLE_DISC_TO;

	return 0;
}

void output_probe_counts(void) {
        int i;

        for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++)
                output("%s count: %lu\n", probes[i].name, probes[i].count);
}
void unregister_probes(void) {
        int i;

        for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++)
                unregister_kprobe(&probes[i].probe);
}

int bz1723537_init(void) {
	int ret, i;

	if (kallsyms_lookup_name("sunrpc_init_net") == 0) {
		output("unable to determine that sunrpc module is installed\n");
		return -1;
	}
	if ((bz1723537_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw")) == 0) {
		output("unable to find address of 'set_memory_rw'\n");
		return -1;
	}
	if ((bz1723537_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro")) == 0) {
		output("unable to find address of 'set_memory_ro'\n");
		return -1;
	}

	if ((ret = search_and_replace()) != 0) {
		output("error finding and replacing instructions; unloading\n");
		return -1;
	}

	/* */
	for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++) {
		if ((ret = register_kprobe(&probes[i].probe)) == 0)
			output("registered probe/counter for '%s' (%s)\n", probes[i].name, probes[i].loc);
		else
			output("error registering probe/counter for '%s': %d\n", probes[i].name, ret);
	}

	output("bz1723537 module installed\n");
	return 0;
}
void bz1723537_exit(void) {
	output_probe_counts();
	unregister_probes();

	sars_do_replacements(0);

	output("bz1723537 module removed\n");
}
 
module_init(bz1723537_init);
module_exit(bz1723537_exit);
 
/*Kernel module Comments*/
MODULE_AUTHOR("Frank Sorenson");
MODULE_DESCRIPTION("Module to help replicate Red Hat bz1723537");
MODULE_LICENSE("GPL");
