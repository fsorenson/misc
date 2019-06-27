/*
	Frank Sorenson <sorenson@redhat.com> 2019

	bz1723537.c - reproduce the conditions in Red Hat bugzilla 1723537
		server component to change timeout
*/

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/pagemap.h>

#define MODULE_NAME "bz1723537_mod"
#define ORIG_svc_conn_age_period (60 * 6 * HZ)
#define NEW_svc_conn_age_period (60 * 1 * HZ)

#define ORIG_XS_IDLE_DISC_TO (60 * 5 * HZ)
#define NEW_XS_IDLE_DISC_TO (65 * HZ)

#define STR(_x) #_x
#define ___STR(x...)    #x
#define __STR(x...)     ___STR(x)
#define __XSTR(s)       __STR(s)

#define LITERAL_32bit(_x) (_x & 0xff), ((_x >> 8) & 0xff), ((_x >> 16) & 0xff), ((_x >> 24) & 0xff)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))


struct sar_struct {
	int len;
	unsigned char *needle;
	unsigned char *replacement;
	char *opcode_string;
	char *function;
	int search_start;
	int search_len;
	void *func_addr;
	void *addr;
	int replaced;
};
static struct sar_struct sars[] = {
/*
0xffffffffc04177cb <svc_age_temp_xprts+0x7b>:   mov    (%rbx),%r12
0xffffffffc04177ce <svc_age_temp_xprts+0x7e>:   jne    0xffffffffc041784f <svc_age_temp_xprts+0xff>
0xffffffffc04177d0 <svc_age_temp_xprts+0x80>:   mov    -0x30(%rbp),%rdi
0xffffffffc04177d4 <svc_age_temp_xprts+0x84>:   callq  0xffffffffb39166c0 <_raw_spin_unlock_bh>
0xffffffffc04177d9 <svc_age_temp_xprts+0x89>:   mov    -0xc4c77e0(%rip),%rsi        # 0xffffffffb3f50000
0xffffffffc04177e0 <svc_age_temp_xprts+0x90>:   lea    0x50(%r13),%rdi
0xffffffffc04177e4 <svc_age_temp_xprts+0x94>:   add    $0x57e40,%rsi
0xffffffffc04177eb <svc_age_temp_xprts+0x9b>:   callq  0xffffffffb32a4a50 <mod_timer>
*/
	{ // 3.10.0-862.9.1.x86_64
		.opcode_string = "'add $" STR(ORIG_svc_conn_age_period) ",%rsi' => 'add $" STR(NEW_svc_conn_age_period) ",%rsi'",
//		.needle = (char []){ 0x48, 0x81, 0xee, 0xc0, 0x27, 0x09, 0x00 },
		.needle = (char []){ 0x48, 0x81, 0xc6, LITERAL_32bit(ORIG_svc_conn_age_period) },
		.replacement = (char[]){ 0x48, 0x81, 0xc6, LITERAL_32bit(NEW_svc_conn_age_period) },
		.len = 7,
		.function = "svc_age_temp_xprts",
		.search_start = 100,
		.search_len = 200,
	},
/*
0xffffffffc03fd574 <xs_setup_tcp+0x44>: movl   $0x1,0xc0(%rax)
0xffffffffc03fd57e <xs_setup_tcp+0x4e>: lea    0x648(%rbx),%rdi
0xffffffffc03fd585 <xs_setup_tcp+0x55>: movq   $0x7fffffff,0xb8(%rax)
0xffffffffc03fd590 <xs_setup_tcp+0x60>: movq   $0xea60,0x430(%rax)
0xffffffffc03fd59b <xs_setup_tcp+0x6b>: xor    %ecx,%ecx
0xffffffffc03fd59d <xs_setup_tcp+0x6d>: movq   $0xbb8,0x438(%rax)
0xffffffffc03fd5a8 <xs_setup_tcp+0x78>: movq   $0x493e0,0x4c0(%rax)
0xffffffffc03fd5b3 <xs_setup_tcp+0x83>: xor    %edx,%edx
*/ // 3.10.0-862.9.1.x86_64
	{
		.opcode_string = "'movq $" STR(ORIG_XS_IDLE_DISC_TO) ",0x4c0(%rax)' => 'movq $" STR(NEW_XS_IDLE_DISC_TO) ",0x4c0(%rax)'",
//		.needle = (char []){ 0x48, 0x81, 0xee, 0xc0, 0x27, 0x09, 0x00 },
		.needle = (char []){ 0x48, 0xc7, 0x80, 0xc0, 0x04, 0x00, 0x00, LITERAL_32bit(ORIG_XS_IDLE_DISC_TO) },

		.replacement = (char[]){ 0x48, 0xc7, 0x80, 0xc0, 0x04, 0x00, 0x00, LITERAL_32bit(NEW_XS_IDLE_DISC_TO) },
		.len = 11,
		.function = "xs_setup_tcp",
		.search_start = 100,
		.search_len = 200,
	},

};
#define NUM_SARS (ARRAY_SIZE(sars))

#define output(args...) do { \
	printk(KERN_WARNING MODULE_NAME ": " args); \
} while (0)



//#define PROBE_ADDR 0xffffffffc1448d1a
#define PROBE_ADDR 0xffffffffc1448d13
#define LOOPS 1000000000UL


int generic_count_handler(struct kprobe *p, struct pt_regs *regs);
/* some generic probes */
struct probe_data {
	struct kprobe probe;
	unsigned long count;
	char *name;
	unsigned long delay;
	char *loc;
	int log_probe;
};

#define ADD_PROBE_ENTRY(func, probe_func, off, _log_probe, _delay_cycles) { \
        .probe = { \
                .symbol_name = __XSTR(probe_func), \
                .pre_handler = generic_count_handler, \
                .offset = off, \
        }, \
        .name = __XSTR(func), \
        .loc = __XSTR(probe_func) "+" __XSTR(off) "", \
	.log_probe = _log_probe, \
        .delay = _delay_cycles, \
        .count = 0, \
}

#define COUNTER_ENTRY_MASQ(func, probe_func, off) \
        ADD_PROBE_ENTRY(func, probe_func, off, 0, 0)

#define COUNTER_ENTRY(func) \
        ADD_PROBE_ENTRY(func, func, 0, 0, 0)


unsigned char *kinda_memstr(char *haystack, char *needle, unsigned int haystack_len, unsigned int needle_len) {
	unsigned long max_p = haystack_len - needle_len;
	unsigned long p;

	for (p = 0 ; p < max_p ; p ++) {
		if (! memcmp(haystack + p, needle, needle_len))
			return haystack + p;
	}
	return 0;
}

unsigned char *search_mem(unsigned char *haystack, unsigned char *needle, int haystack_len, int needle_len) {
	unsigned char *p;

	for (p = haystack ; p < haystack + haystack_len - needle_len ; p++) {
		if (! memcmp(p, needle, needle_len))
			return p;
	}
	return NULL;
}
#define NUM_PAGES(addr, len) (((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1)

int set_memory_rw(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
void change_perms(void *addr, unsigned long len, int rw) {
	unsigned long aligned_addr = (unsigned long)addr & PAGE_MASK;
	int num_pages = NUM_PAGES((unsigned long)addr, len);

	if (len < 1)
		return;

	output("%sfutzing permissions for %d page(s) at %p",
		rw ? "" : "un", num_pages, (void *)aligned_addr);

	if (rw)
		set_memory_rw(aligned_addr, num_pages);
	else
		set_memory_ro(aligned_addr, num_pages);

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
int sars_find_addr(struct sar_struct *sar) {
	void *start_addr;

	sar->func_addr = (void *)kallsyms_lookup_name(sar->function);
	start_addr = sar->func_addr + sar->search_start;
	sar->addr = search_mem(start_addr, sar->needle, sar->search_len, sar->len);

	if (sar->addr == 0) {
		output("Could not find opcode '%s' in function '%s' for replacement\n",
			sar->opcode_string, sar->function);
	} else {
		output("Located bytes for opcode '%s' in function '%s'\n",
			sar->opcode_string, sar->function);
	}

	return (sar->addr != 0);
}
int sars_find_addr_reverse(struct sar_struct *sar) {
	void *start_addr;

	sar->func_addr = (void *)kallsyms_lookup_name(sar->function);
	start_addr = sar->func_addr + sar->search_start;
	sar->addr = search_mem(start_addr, sar->replacement, sar->search_len, sar->len);

	if (sar->addr == 0) {
		output("Could not find already-modified opcode '%s' in function '%s' for replacement\n",
			sar->opcode_string, sar->function);
	} else {
		output("Located already-modified bytes for opcode '%s' in function '%s'\n",
			sar->opcode_string, sar->function);
	}

	return (sar->addr != 0);
}

int sars_find_addrs(void) {
	int found_addrs = 0;
	int ret;
	int i;

	for (i = 0 ; i < NUM_SARS ; i++) {
		ret = sars_find_addr(&sars[i]);
		if (!ret) {
			ret = sars_find_addr_reverse(&sars[i]);
		}

		found_addrs += ret;
	}
	return found_addrs;
}
int find_and_replace(void) {
	int ret;
	int i;

	ret = sars_find_addrs();
	if (ret != NUM_SARS) {
		output("unable to locate %d replacement location(s)\n", (int)(NUM_SARS - ret));
		return -1;
	}
	ret = sars_do_replacements(1);
	output("changed %d bytes\n", ret);

	/* output some data that makes us look cool */
	for (i = 0 ; i < NUM_SARS ; i++) {
		output("replacement %d: function %s (%p) offset 0x%08lx (%p)\n",
			i, sars[i].function, sars[i].func_addr, sars[i].addr - sars[i].func_addr, sars[i].addr);
	}

	return 0;
}


//#define ADD_PROBE_ENTRY(func, probe_func, off, _log_probe, _delay_cycles)
static struct probe_data probes[] = {
	ADD_PROBE_ENTRY(xprt_release, xprt_release, 0xf5, 1, 100000), // 0xee or 0xf5

//	ADD_PROBE_ENTRY(smb2_reconnect_server, smb2_reconnect_server, 0, 1, 0),
//	ADD_PROBE_ENTRY(smb2_reconnect, smb2_reconnect, 0, 1, 0),
//	ADD_PROBE_ENTRY(cifs_prune_tlinks, cifs_prune_tlinks, 0, 1, 0),
//	ADD_PROBE_ENTRY(cifs_free_ipc, cifs_free_ipc, 0, 1, 0),
//	ADD_PROBE_ENTRY(cifs_put_tcon, cifs_put_tcon, 0, 1, 500000),
//	ADD_PROBE_ENTRY(tconInfoFree, tconInfoFree, 0, 1, 5000000),
//	ADD_PROBE_ENTRY(smb2_select_sectype, smb2_select_sectype, 0, 1, 5000000),
};

static void burn_cycles(unsigned long l) {
	while (l--)
		nop();
}

int generic_count_handler(struct kprobe *p, struct pt_regs *regs) {
        struct probe_data *my_data = container_of(p, struct probe_data, probe);
        my_data->count++;

	if (my_data->log_probe)
		output("hit probe at '%s' (%lu)\n", my_data->name, my_data->count);

        if (my_data->delay) {
                unsigned long delay = my_data->delay;
                while (delay-- > 0)
                        nop();
        }
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

void bz1723537_burn_cycles(void) {
	output("burning cycles\n");
	burn_cycles(LOOPS);
	output("completed burning cycles\n");

	jprobe_return();
}
int delay_callback_handler(struct kprobe *p, struct pt_regs *regs) {
	output("burning cycles\n");
	burn_cycles(LOOPS);
	output("completed burning cycles\n");
	return 0;
}


/* find the location at which to burn cycles */
void *find_probe_addr(void) {

	return 0;
}

int bz1723537_init(void) {
	int ret, i;

//	bz1723537_probe.kp.addr = (kprobe_opcode_t *)PROBE_ADDR;
//	bz1723537_probe.entry = (kprobe_opcode_t *)bz1723537_burn_cycles;
//	register_jprobe(&bz1723537_probe);

	if (kallsyms_lookup_name("sunrpc_init_net") == 0) {
		output("unable to determine that sunrpc module is installed\n");
		return -1;
	}

	ret = find_and_replace();
	if (ret != 0) {
		output("error finding and replacing values; unloading\n");
		return -1;
	}

	/* */
	for (i = 0 ; i < sizeof(probes)/sizeof(struct probe_data) ; i++) {
		ret = register_kprobe(&probes[i].probe);
		if (ret == 0)
			output("registered counter for '%s' (%s)\n", probes[i].name, probes[i].loc);
		else
			output("error registering counter for '%s': %d\n", probes[i].name, ret);
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
//MODULE_LICENSE("GPL v2");
