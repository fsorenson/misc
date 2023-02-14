#!/usr/bin/env python

from __future__ import print_function
import gdb

try:
	saved_do_pruning = do_pruning
except:
	saved_do_pruning = False

do_pruning = True
prune_list = {}

# #defines from include/automount.h
LKP = { "FAIL" : 0x0001,
	"INDIRECT" : 0x0002,
	"DIRECT" : 0x0004,
	"MULTI" : 0x0008,
	"NOMATCH" : 0x0010,
	"MATCH" : 0x0020,
	"NEXT" : 0x0040,
	"MOUNT" : 0x0080,
	"WILD" : 0x0100,
	"LOOKUP" : 0x0200,
	"GHOST" : 0x0400,
	"REREAD" : 0x0800,
	"NORMAL" : 0x1000,
	"DISTINCT" : 0x2000,
	"ERR_MOUNT" : 0x4000,
	"NOTSUP" : 0x8000,
}
MNT_LIST_FLAGS = {
	"ALL"		: 0x0001,
	"REAL"		: 0x0002,
	"AUTOFS"	: 0x0004,
	"INDIRECT"	: 0x0008,
	"DIRECT"	: 0x0010,
	"OFFSET"	: 0x0020,
	"AMD_MOUNT"	: 0x0040,
	"MOUNTED"	: 0x0080,
}

autofs_point_def = '''
[sorenson@bearskin autofs]$ grep -r 'struct autofs_point {' -A40 -h
struct autofs_point {
	pthread_t thid;
	char *path;			/* Mount point name */
	size_t len;			/* Length of mount point name */
	mode_t mode;			/* Mount point mode */
	char *pref;			/* amd prefix */
	int pipefd;			/* File descriptor for pipe */
	int kpipefd;			/* Kernel end descriptor for pipe */
	int ioctlfd;			/* File descriptor for ioctls */
	int logpri_fifo;		/* FIFO used for changing log levels */
	dev_t dev;			/* "Device" number assigned by kernel */
	struct master_mapent *entry;	/* Master map entry for this mount */
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_timeout;		/* Indirect mount expire timeout */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	time_t negative_timeout;	/* timeout in secs for failed mounts */
	unsigned int flags;		/* autofs mount flags */
	unsigned int logopt;		/* Per map logging */
	pthread_t exp_thread;		/* Thread that is expiring */
	pthread_t readmap_thread;	/* Thread that is reading maps */
	enum states state;		/* Current state */
	int state_pipe[2];		/* State change router pipe */
	struct autofs_point *parent;	/* Owner of mounts list for submount */
	struct list_head mounts;	/* List of autofs mounts at current level */
	unsigned int submount;		/* Is this a submount */
	unsigned int submnt_count;	/* Number of submounts */
	struct list_head submounts;	/* List of child submounts */
	struct list_head amdmounts;	/* List of non submount amd mounts */
	unsigned int shutdown;		/* Shutdown notification */
'''

def construct_prune_key(struct_name, addr):
	try:
		prune_key = "{}.0x{:016x}".format(struct_name, addr)
	except:
		prune_key = ""
	return prune_key

def check_prune(struct_name, addr):
	global prune_list

	if not do_pruning:
		return False

	prune_key = construct_prune_key(struct_name, addr)
#	prune_key = "{}.0x{:016x}".format(struct_name, addr)
#	print("prune_key: {}".format(prune_key))
	try:
		prune_this = prune_list[prune_key]
	except:
		prune_this = False
		prune_list[prune_key] = True
	return prune_this


def ind(ilvl):
	if ilvl == 0:
		return ""
	s = "{:" + "{}".format(ilvl * 4) + "}"
	return s.format("")

def to_int(val):
	sval = str(val)
	start = sval.find('0x')

	if start != -1:
		end = sval.find(':')

		if end == -1:
			end = sval.find('\n')

			if end == -1:
				return int(sval[start:], 16)
			else:
				return int(sval[start:end], 16)
		else:
			return int(sval[start:end], 16)
	elif sval.startswith('unsigned int'):
		return int(sval[len('unsigned int'):])
	else:
		return int(sval)


def offsetof(struct_name, member_name):
#	expr = '(size_t)&((({} *)0)->{}) - (size_t)(({} *)0)'.format(struct_name, member_name, struct_name)
#	return to_int(gdb.parse_and_eval(expr))
	return to_int(gdb.parse_and_eval('(size_t)&((({} *)0)->{}) - (size_t)(({} *)0)'.format(struct_name, member_name, struct_name)))

def container_of(_ptr, _type, _member):
#	thing1 = "({} *)((void *)({}) - ((size_t)&((({} *)0)->{}) - (size_t)(({} *)0))	)".format(_type, _ptr, _type, _member, _type)
#	print("container_of expression: {}".format(thing1))
#	return gdb.parse_and_eval(thing1)
	return gdb.parse_and_eval("({} *)((void *)({}) - ((size_t)&((({} *)0)->{}) - (size_t)(({} *)0))  )".format(_type, _ptr, _type, _member, _type))


#	thing = "((
#	      ((_type *)((void *)(_ptr) - offsetof(_type, _memb)))

#gdb.Value(0).cast(gdb.lookup_type({}).pointer())

def sizeof(type_name):
	return to_int(gdb.parse_and_eval('sizeof({})'.format(type_name)))
def array_size(a):
	r = a.type.range()
	return (r[1] - r[0] + 1)


def struct_ptr__member_ptr(var, member):
#	thing = '&((({}){})->{})'.format(var.type, var, member)
#	return gdb.parse_and_eval(thing)
	return gdb.parse_and_eval('&((({}){})->{})'.format(var.type, var, member))

def list_entry(_ptr, _type, _member):
	try:
		return container_of(_ptr, _type, _member)
	except:
		return None

def list_empty(head):
#	print("type of 'head': {}, type of head['next']: {}".format(head.type, head['next'].type))
	if head['next'] == head:
		return True
	return False

def __master_list_empty(master):
#	return list_empty(master['mounts'])
	return list_empty(struct_ptr__member_ptr(master, "mounts"))
#	return &master['mounts']

NULL = 0

def IS_MM(me):
	# newer autofs has me->mm_root
	try:
		if me['mm_root'] == 0:
			return False
		return True
	except:
		pass

	if me['multi']:
#		and not me['multi'] == me:
		return True
	return False

def IS_MM_ROOT(me):
	try:
		if me['mm_root'] == struct_ptr__member_ptr(me, "mm_root"):
			return True
		return False
	except:
		pass

	if me['multi'] == me:
		return True
	return False



def autofs_hash(key, size): # const char *key, unsigned int size
	s = key.string()

	hashval = 0;
	while len(s):
		hashval = (hashval + (int(ord(s[0:1]) & 0xff))) & 0xffffffff
		s = s[1:]
		hashval = (hashval + (hashval << 10)) & 0xffffffff
		hashval = (hashval ^ (hashval >> 6)) & 0xffffffff

	hashval = (hashval + (hashval << 3)) & 0xffffffff
	hashval = (hashval ^ (hashval >> 11)) & 0xffffffff
	hashval = (hashval + (hashval << 15)) & 0xffffffff

#	print("hashval: {}, size: {}".format(hashval, size))
	return hashval % size

def cache_lookup_first(mc): # struct mapent_cache *mc
	me = NULL

	for i in range(0, mc['size'] - 1):
		me = mc['hash'][i]

		if not me:
			continue

#		while not me == NULL:
		while me:
			if IS_MM(me) and not IS_MM_ROOT(me):
				me = me['next']
				continue
			return me
	return NULL

def cache_lookup_next(mc, me): #struct mapent_cache *mc, struct mapent *me
	if not me:
		return NULL

	this = me['next']
	while this:
		if IS_MM(this) and not IS_MM_ROOT(this):
			this = this['next']
			continue
		return this
	hashval = autofs_hash(me['key'], mc['size']) + 1
	if hashval < mc['size']:
		for i in range(hashval, mc['size'] - 1):
			this = mc['hash'][i]
			if not this:
				continue
			while (this):
#				print("this: ({}){}".format(this.type, this))
				if IS_MM(this) and not IS_MM_ROOT(this):
					this = this['next']
					continue
				return this
	return NULL

def show_mapent(me, ilvl=0):
	print("{}({}){} - ".format(ind(ilvl), me.type, me))

	if check_prune("mapent", me):
		return
	# anything else to do here?



# this appears to just be a repeat of the other stuff
def show_mapent_cache(mc, ilvl=0):
	print("{}mapent cache...".format(ind(ilvl)))
	print("{}({}){}".format(ind(ilvl+1), mc.type, mc))
	print("{}size: {}".format(ind(ilvl+1), mc['size']))
	ap = mc['ap']
	print("{}({}){} - {}".format(ind(ilvl+1), ap.type, ap, ap['path'].string()))

	for i in range(0, mc['size'] - 1):
		if not mc['hash'][i]:
			continue
		this_ent = gdb.parse_and_eval("(struct mapent *){}".format(mc['hash'][i]))
#		print("            hash[{}]: {}".format(i, mc['hash'][i]))
		print("{}hash[{}]:".format(ind(ilvl+1), i))
#		print("{}hash[{}]: ({}){}".format(ind(ilvl+1), i, this_ent.type, this_ent))
		while this_ent:
#			print("{}({}){} - ".format(ind(ilvl+1), this_ent.type, this_ent))
			show_mapent(this_ent, ilvl=ilvl+1)

			this_ent = this_ent['next']

	print("end of mapent cache...")

#        source = this['maps']
#        while source:

#type = struct mapent_cache {
#	pthread_rwlock_t rwlock;
#	unsigned int size;
#	pthread_mutex_t ino_index_mutex;
#	struct list_head *ino_index;
#	struct autofs_point *ap;
#	struct map_source *map;
#	struct mapent **hash;

def addr2sym(addr):
	try:
		block = gdb.block_for_pc(addr)
		while block and not block.function:
			block = block.superblock

		return block.function.print_name
	except:
		return "UNKNOWN"

def sym2addr(sym):
	try:
		return gdb.parse_and_eval(sym).address
	except:
		pass
	return "UNKNOWN"
def sym2addr_global(sym):
	try:
		return gdb.lookup_global_symbol(sym).value().address
	except:
		pass
	return "UNKNOWN"


def map_source_get_lookup(source):
	try:
		if source and source['lookup']:
			return source['lookup']
	except:
		pass
	return 0


# dlsym handle
def show_link_map(lm, ilvl=0): # struct link_map *lm
	try:
		lm = gdb.parse_and_eval("(struct link_map *){}".format(lm))
		print("{}({}){}".format(ind(ilvl), lm.type, lm))
		print("{}({}){} - {}".format(ind(ilvl), lm.type, lm, lm['l_name'].string()))
		print("{} l_origin: {}".format(ind(ilvl), lm['l_origin'].string()))
	except:
		pass





	foo = '''
type = struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[77];
    const Elf64_Phdr *l_phdr;
    Elf64_Addr l_entry;
    Elf64_Half l_phnum;
    Elf64_Half l_ldnum;
    struct r_scope_elem l_searchlist;
    struct r_scope_elem l_symbolic_searchlist;
    struct link_map *l_loader;
    struct r_found_version *l_versions;
    unsigned int l_nversions;
    Elf_Symndx l_nbuckets;
    Elf32_Word l_gnu_bitmask_idxbits;
    Elf32_Word l_gnu_shift;
    const Elf64_Addr *l_gnu_bitmask;
    union {
        const Elf32_Word *l_gnu_buckets;
        const Elf_Symndx *l_chain;
    };
    union {
        const Elf32_Word *l_gnu_chain_zero;
        const Elf_Symndx *l_buckets;
    };
    unsigned int l_direct_opencount;
    enum {lt_executable, lt_library, lt_loaded} l_type : 2;
    unsigned int l_relocated : 1;
    unsigned int l_init_called : 1;
    unsigned int l_global : 1;
    unsigned int l_reserved : 2;
    unsigned int l_phdr_allocated : 1;
    unsigned int l_soname_added : 1;
    unsigned int l_faked : 1;
    unsigned int l_need_tls_init : 1;
    unsigned int l_auditing : 1;
    unsigned int l_audit_any_plt : 1;
    unsigned int l_removed : 1;
    unsigned int l_contiguous : 1;
    unsigned int l_symbolic_in_local_scope : 1;
    unsigned int l_free_initfini : 1;
    _Bool l_nodelete_active;
    _Bool l_nodelete_pending;
    enum {lc_unknown, lc_none, lc_ibt, lc_shstk = 4, lc_ibt_and_shstk = 6} l_cet : 3;
    struct r_search_path_struct l_rpath_dirs;
    struct reloc_result *l_reloc_result;
    Elf64_Versym *l_versyms;
    const char *l_origin;
    Elf64_Addr l_map_start;
    Elf64_Addr l_map_end;
    Elf64_Addr l_text_end;
    struct r_scope_elem *l_scope_mem[4];
    size_t l_scope_max;
    struct r_scope_elem **l_scope;
    struct r_scope_elem *l_local_scope[2];
    struct r_file_id l_file_id;
    struct r_search_path_struct l_runpath_dirs;
    struct link_map **l_initfini;
    struct link_map_reldeps *l_reldeps;
    unsigned int l_reldepsmax;
    unsigned int l_used;
    Elf64_Word l_feature_1;
    Elf64_Word l_flags_1;
    Elf64_Word l_flags;
    int l_idx;
    struct link_map_machine l_mach;
    struct {
        const Elf64_Sym *sym;
        int type_class;
        struct link_map *value;
        const Elf64_Sym *ret;
    } l_lookup_cache;
    void *l_tls_initimage;
    size_t l_tls_initimage_size;
    size_t l_tls_blocksize;
    size_t l_tls_align;
    size_t l_tls_firstbyte_offset;
    ptrdiff_t l_tls_offset;
    size_t l_tls_modid;
    size_t l_tls_dtor_count;
    Elf64_Addr l_relro_addr;
    size_t l_relro_size;
    unsigned long long l_serial;
    struct auditstate l_audit[];
'''


def show_parse_mod(parse, ilvl=0): # struct parse_mod *parse
	if not parse:
		return
	print("{}parse_init: {}".format(ind(ilvl), addr2sym(parse['parse_init'].address)))
	print("{}parse_reinit: {}".format(ind(ilvl), addr2sym(parse['parse_reinit'])))
	print("{}parse_mount: {}".format(ind(ilvl), addr2sym(parse['parse_mount'])))
	print("{}parse_done: {}".format(ind(ilvl), addr2sym(parse['parse_done'])))
	print("{}dlhandle: 0x{:016x}, context: 0x{:016x}".format(ind(ilvl), parse['dlhandle'].address, parse['context'].address))
#	show_link_map(parse['dlhandle'].address, ilvl=ilvl+1)

def show_lookup_mod(lookup, ilvl=0): # struct lookup_mod *lookup
	print("{}({}){}".format(ind(ilvl), lookup.type, lookup))
	if not lookup or check_prune("lookup_mod", int(lookup)):
		return

#	if source['lookup']:
	print("{}map_source lookup: ({}){} - type: {}".format(ind(ilvl), lookup.type, lookup, lookup['type'].string()))
	for member in [ "lookup_init", "lookup_reinit", "lookup_read_master", "lookup_read_map", "lookup_mount", "lookup_done" ]:
		lmbr = lookup[member]
		lmbr_name = addr2sym(int(lmbr.address.dereference()))
		other_thing = addr2sym(int(lookup[member]))



#		func_addr = int(lookup[member].address.dereference())
		func_addr = int(lookup[member])
		func_block = gdb.block_for_pc(func_addr)
		func_name = addr2sym(int(lookup[member]))

		gdbfunc = func_block.function
		func_filename = gdbfunc.symtab.filename
		func_full_filename = gdbfunc.symtab.fullname()


		print("{}.{}: <0x{:016x}> {} - {} - {} line {}  ({})".format(
			ind(ilvl), member, func_addr, func_block.function.name, func_block.function.type, func_block.function.symtab.filename, func_block.function.line, func_block.function.symtab.fullname()))


#  function name: lookup_mount - in lookup_file.c line 1131 (full name /home/sos/3337612/root/usr/src/debug/autofs-5.1.4-82.el8.x86_64/modules/lookup_file.c), objfile <gdb.Objfile filename=/home/sos/3337612/root/usr/lib/debug/usr/lib64/autofs/lookup_file.so-5.1.4-82.el8.x86_64.debug>
#    lookup_mount - int (struct autofs_point *, const char *, int, void *)
#    lookup_mount
#other thing: lookup_mount
#        lookup_mount: (lookup_mount_t)0x7f1fd6393dd0 <lookup_mount at lookup_file.c:1132>
#        lookup_mount: (lookup_mount_t)139774714789328 (lookup_mount)  line lookup_mount
#  address: 0x00007f1fd6393dd0
#  addr2sym: lookup_mount
#		print("  function name: {} - in {} line {} (full name {}), objfile {}".format(func_name, func_filename, gdbfunc.line, func_full_filename, gdbfunc.symtab.objfile))
#		print("    {} - {}".format(gdbfunc.name, gdbfunc.type))
#		print("    {}".format(gdbfunc.linkage_name))

#(gdb) python block = gdb.block_for_pc(0x7f1fd6393460)
#(gdb) python print(block)
#<gdb.Block object at 0x7f68e03c11a0>
#(gdb) python print(block.function)
#lookup_init
#(gdb) python print(block.function.print_name)
#lookup_init

#(gdb) python print(block.function.symtab.fullname)
#<built-in method fullname of gdb.Symtab object at 0x7f30f87e7030>
#(gdb) python print(block.function.symtab.fullname())
#/home/sos/3337612/root/usr/src/debug/autofs-5.1.4-82.el8.x86_64/modules/lookup_file.c


# lookup_mount: (lookup_mount_t)0x7f1fd6393dd0 <lookup_mount at lookup_file.c:1132>
#  address: 0x00007f1fd6393dd0
#  addr2sym: lookup_mount
#other thing: lookup_done
#        lookup_done: (lookup_done_t)0x7f1fd6394d80 <lookup_done at lookup_file.c:1322>
#  address: 0x00007f1fd6394d80
#  addr2sym: lookup_done

#		print("other thing: {}".format(other_thing))
#		func_type = lookup[member].type
#		func_addr = int(lookup[member].address.dereference())
#		func_name = addr2sym(int(lookup[member]))
#		func_line = addr2sym(func_addr)


#		print("{}{}: ({}){}".format(ind(ilvl), member, lmbr.type, lmbr))
#		print("{}{}: ({}){} ({})  line {}".format(ind(ilvl), member, func_type, func_addr, func_name, func_line))

#		print("  address: 0x{:016x}".format(int(lmbr.address.dereference())))
#		print("  addr2sym: {}".format(addr2sym(int(lmbr.address.dereference()))))

#		print(gdb.block_for_pc(int(addr2sym(lmbr))))
#		print("{}{}: {}".format(ind(ilvl), member, addr2sym(lookup[member])))

#	show_link_map(lookup['dlhandle'].address, ilvl=ilvl+1)



def print_map_info(source, ilvl=0): # struct map_source *source
	print("{}({}){} - type: {}, format: {}, name: {}"
		.format(ind(ilvl), source.type, source, source['type'].string(), source['format'].string(), source['name'].string()))


#		print("source thing is type: {}, format: {}, name: {} - instance thingy is type: {}, format: {}, name: {}".format(
#			source['type'].string(), source['format'].string(), source['name'].string(),
#			instance['type'].string(), instance['format'].string(), instance['name'].string()))


#    char *type;
#    char *format;
#    char *name;
#    time_t exp_timeout;
#    time_t age;
#    unsigned int master_line;
#    struct mapent_cache *mc;
#    unsigned int stale;
#    unsigned int recurse;
#    unsigned int depth;
#    struct lookup_mod *lookup;
#    int argc;
#    const char **argv;


	if check_prune("map_source_map_info", int(source)):
		return

	argc = source['argc']
#	print("source: ({}){}".format(source.type, source))
#	print("source['argv']: ({}){}".format(source['argv'].type, source['argv']))

#	multi = (source['type'] and (source['type'] == "multi")
#	if not source['type'] == NULL:
#		print("it's not null")
#		st = source['type']
#		print("st: ({}){} - {}".format(st.type, st, st.string()))
#		if source['type'].string() == "multi":
#			print("it's multi")
	if (not source['type'] == NULL) and source['type'].string() == "multi":
		multi = True
	else:
		multi = False


	map_num = 1
	for i in range(argc):
		if source['argv'][i] and not source['argv'][i].string()[:1] == '-':
			if not multi:
				print("{}map: {}".format(ind(ilvl+1), source['argv'][i].string()))
			else:
				print("{}map[{}]: {}".format(ind(ilvl+1), map_num, source['argv'][i].map()))

			i += 1

		if i >= argc:
			break

		if source['argv'][i].string() == "--":
			continue

		if source['argv'][i]:
			need_newline = False

			if not multi:
				print("{}arguments:".format(ind(ilvl+1)), end='')
			else:
				print("{}arguments[{}]:".format(ind(ilvl+1), map_num), end='')

			for j in range(i, source['argc'] - 1):
				if source['argv'][j].string == "--":
					break
				print(" {}".format(source['argv'][j]), end='')
				i += 1
				need_newline = True

			if need_newline:
				print("")

		if multi:
			map_num += 1


	show_lookup_mod(map_source_get_lookup(source), ilvl=ilvl)





def find_last_list_entry(head, search):
	if head == search:
		return 0
	else:
		while not head['next'] == search:
			head = head['next']
		return head

def list_source_instance(source, instance, ilvl=0):
	if not source or not instance:
		print("{}none".format(ind(ilvl)))
	else:
		print("source thing is type: {}, format: {}, name: {} - instance thingy is type: {}, format: {}, name: {}".format(
			source['type'].string(), source['format'].string(), source['name'].string(),
			instance['type'].string(), instance['format'].string(), instance['name'].string()))

		if not instance['type'].string() == "file":
			print("{}{}".format(ind(ilvl), instance['type']))
		else:
			if source['argv'] and not source['argv'][0].string()[:1] == '/':
				print("{}files ".format(ind(ilvl)), end="")
			else:
				print("{}{} ".format(ind(ilvl), instance['type']))



def list_source_instances_v0(source, instance):
	print("in NEW list_source_instances")
	if not source or not instance:
		print("none")
		return

	if instance['next']:
		list_source_instances(source, instances['next'])

	if not instance['type'] == "file":
		print("{}".format(instance['type'].string()), end='')
	else:
		if source['argv'] and not source['argv'][0].string()[:1] == "/":
			print("files ", end="")
		else:
			print("{} ".format(instance['type'].string()))


def list_source_instances(source, instance, ilvl=0):
	print("{}in NEW list_source_instances".format(ind(ilvl)))
	if not source or not instance:
		print("{}none".format(ind(ilvl)))
		return

	ptr = instance
	end_ptr = 0

	this_entry = find_last_list_entry(ptr, end_ptr)
	while 42:
		print("{}({}){}".format(ind(ilvl), this_entry.type, this_entry))
#		print("    list_entry: 0x{:016x}".format(this_entry))
		print("{}list_entry: {}".format(ind(ilvl+1), this_entry))
#		print("current list entry: 0x{:016x} (current->next: 0x{:016x}".format(this_entry, this_entry['next']))
		print("{}current list entry: {} (current->next: ({}){}".format(ind(ilvl+1), this_entry, this_entry['next'].type, this_entry['next']))

		list_source_instance(source, this_entry, ilvl=ilvl+1)
		end_ptr = this_entry

		this_entry = find_last_list_entry(ptr, end_ptr)
		if not this_entry:
			break


def show_submount(sub, ilvl=0):
	if sub:
#		if sub['ap']:
#			ap_str = "\n{}({}){}".format(ind(ilvl+1), sub['ap'].type, sub['ap'])
#		else:
#			ap_str = ""
		ap_str = ""
		print("{}submount ({}){} - path: {}{}".format(ind(ilvl), sub.type, sub, sub['mp'].string(), ap_str))

#		print("sub is: ({}){}".format(sub.type, sub))

		addr = gdb.parse_and_eval("(unsigned long long){}".format(sub))
#		if check_prune("submount", int(sub.address.dereference())):

#		pkey = construct_prune_key("submount", int(addr))
#		print("prune_key: {}".format(pkey))


		if sub['ap']:
			show_autofs_point(sub['ap'], ilvl=ilvl+1)

		if check_prune("submount", int(addr)):
			return





def list_len(head):
	count = 0
	ptr = head

	while ptr:
		count += 1
		try:
			ptr = ptr['next']
		except:
			break
		if ptr == head:
			break
	return count

def list_len_debug(head):
	try:

		print("list_len called with head ({})0x{:016x}".format(head.type, int(head)))
	except:
		print("exception printing the list_len head: {}".format(head))
#		print("head.type is {}".format(head.type))
#		print("head.address: {}".format(head.address))
#		print("head.dereference: {}".format(head.address))
#		print("head.dereference: {}".format(head.dereference()))
#		print("head: {}".format(head))
		pass

	count = 0
	ptr = head
	while ptr:
		try:
			print("list entry 0x{:016x} has next: 0x{:016x}".format(int(ptr), int(ptr['next'])))
		except Exception as e:
			print("list entry error: {}".format(e))
			print("list entry 0x{:016x} - error reading memory".format(ptr))
			pass

		count +=1
		try:
			ptr = ptr['next']
		except Exception as e:
			print("list entry error: {}".format(e))
			print("list_entry 0x{:016x} - error reading next".format(ptr))
			break
		if ptr == head:
			break
#	if ptr == head:
#		return
	return count



def show_submounts(head, ilvl=0):
	if not head:
		return

	p = head['next']
	while not p == head:
		sub = list_entry(p, "struct mnt_list", "submount")
#		print("show_submounts with p: {}, sub: {}".format(p, sub))
#		print("struct mnt_list->next is offset 0xc8")

		p = p['next']

#		show_submount(sub, ilvl=ilvl+1)
		show_submount(sub, ilvl=ilvl)

#		print("{}submount at ({}){} - path: {}".format(ind(ilvl), this.type, this, this['mp'].string()))
#		ap = this['ap']
#		print("{}autofs_point: ({}){}".format(ind(ilvl), ap.type, ap))

#		if ap:
#			next_level = struct_ptr__member_ptr(ap, "submounts")
#			show_submounts(next_level, ilvl=ilvl)


def show_amdmount(amd, ilvl=0):
	if check_prune("amdmount", int(amd)):
		return

	if amd:
		if amd['ap']:
#			ap = amd['ap']
			ap_str = "\n{}({}){}".format(ind(ilvl+1), amd['ap'].type, amd['ap'])
		else:
			ap_str = ""
		print("{}amdmount ({}){} - path: {}{}".format(ind(ilvl), amd.type, amd, amd['mp'].string(), ap_str))

		if amd['ap']:
			next_level = struct_ptr__member_ptr(amd['ap'], "amdmounts")
			show_amdmounts(next_level, ilvl=ilvl)

def show_amdmounts(head, ilvl=0):
	if not head:
		return

	p = head['next']
	while not p == head:
		amd = list_entry(p, "struct mnt_list", "amdmount")
		p = p['next']
		show_amdmount(amd, ilvl=ilvl+1)


def show_map_source(source, ilvl=0):
#	print("{}({}){}".format(ind(ilvl), source.type, source))


	print("{}({}){} - type: {}, format: {}, name: {}"
		.format(ind(ilvl), source.type, source, source['type'].string(), source['format'].string(), source['name'].string()))


	if check_prune("map_source", int(source)):
		return

#	print("{}{} - source: ({}){}".format(ind(ilvl), count, source.type, source))
	print("{} - source: ({}){}".format(ind(ilvl), source.type, source))
	if source['type']:
		print("{}type: {}".format(ind(ilvl), source['type'].string()), end="")
		if source['format']:
			print(", format: {}".format(source['format'].string()), end="")
		print("")
	else:
		print("{}instance type(s): ".format(ind(ilvl)), end="")
		list_source_instances(source, source['instance'], ilvl=ilvl+1)
		print("")
	if source['argc'] >= 1:
		print_map_info(source, ilvl=ilvl+1)
#		if count and ap['type'] == LKP['INDIRECT']:
#			print("{}duplicate indirect map entry will be ignored at run time".format(ind(ilvl)))

	print("")

	if source['lookup']:
		lookup = source['lookup']
		print("{}lookup: ({}){} - lookup type: {}".format(ind(ilvl), lookup.type, lookup, lookup['type'].string()))
		if lookup['type'].string() == "file":

			try:
				context = lookup['context']
#					print("mapname: {}, opts_argc: {}, last_read: {}".format(lookup['mapname'].string(), lookup['opts_args'], lookup['last_read']))
				print("{}mapname: {}".format(ind(ilvl), context['mapname']))
			except:
				pass

	me = cache_lookup_first(source['mc'])
	if not me:
		print("{}no keys found in map".format(ind(ilvl)))
	else:
#		first_me = me
		while me:
			print("{}({}){}".format(ind(ilvl), me.type, me))
			print("{}{} | {}".format(ind(ilvl+1), me['key'].string(), me['mapent'].string()))

			if me['source']:
				show_map_source(me['source'], ilvl=ilvl+1)
#			if me['lookup']:
#				print("mapent lookup: ({}){}".format(me['lookup'].type, me['lookup'].string()))

#			show_mapent_cache(me['mc']) # apparently, just a repeat of the above stuff

			me = cache_lookup_next(source['mc'], me)
			if not me:
				break
			print("")

		print("")
#		print("    cached entries:")
#		show_mapent_cache(first_me['mc']) # apparently, just a repeat of the above stuff



def show_map_sources(sources, ilvl=0):
	if not sources:
		return

	source = sources
	count = 1
	while source:
		print("showing map source...")
		show_map_source(source, ilvl=ilvl)


		source = source['next']

		if not source:
			break


		foo = '''
		if not this['maps']:
			print("{}no map sources found".format(ind(ilvl)))
			continue


		source = this['maps']
		while source:
			print("{}{} - source: ({}){}".format(ind(ilvl), count, source.type, source))
			if source['type']:
#				print("      type: {}, format: {}".format(source['type'].string(), source['format'].string()))
				print("{}type: {}".format(ind(ilvl), source['type'].string()), end="")
				if source['format']:
					print(", format: {}".format(source['format'].string), end="")
				print("")
			else:
				print("{}instance type(s): ".format(ind(ilvl)), end="")
				list_source_instances(source, source['instance'], ilvl=ilvl+1)
				print("")

#type = 0x7fb9ec000b80 "file",
#  dlhandle = 0x7fb9ec000c50,
#  context = 0x7fb93c001ff0

#			if (source->argc >= 1) {
#				print_map_info(source);
#				if (count && ap->type == LKP_INDIRECT)
#					printf("  duplicate indirect map entry"
#						" will be ignored at run time\n");
#			}
			if source['argc'] >= 1:
				print_map_info(source, ilvl=ilvl+1)
				if count and ap['type'] == LKP['INDIRECT']:
					print("{}duplicate indirect map entry will be ignored at run time".format(ind(ilvl)))


			print("")

			if source['lookup']:
				lookup = source['lookup']
				print("{}lookup: ({}){} - lookup type: {}".format(ind(ilvl), lookup.type, lookup, lookup['type'].string()))
				if lookup['type'].string() == "file":
# struct lookup_context {
#	const char *mapname;
#	int opts_argc;
#	const char **opts_argv;
#	time_t last_read;
#	struct parse_mod *parse;
					try:
						context = lookup['context']
#						print("mapname: {}, opts_argc: {}, last_read: {}".format(lookup['mapname'].string(), lookup['opts_args'], lookup['last_read']))
						print("{}mapname: {}".format(ind(ilvl), context['mapname']))
					except:
						pass


			me = cache_lookup_first(source['mc'])
			if not me:
				print("{}no keys found in map".format(ind(ilvl)))
			else:
#				first_me = me
#				while (42):
				while (me):
					print("{}({}){}".format(ind(ilvl), me.type, me))
					print("{}{} | {}".format(ind(ilvl+1), me['key'].string(), me['mapent'].string()))

#					show_mapent_cache(me['mc']) # apparently, just a repeat of the above stuff

					me = cache_lookup_next(source['mc'], me)
					if not me:
						break
					print("")

				print("")
#				print("    cached entries:")
#				show_mapent_cache(first_me['mc']) # apparently, just a repeat of the above stuff
			'''

		count += 1
		source = source['next']
		# don't think we need to do anything with this
		# lookup_close_lookup(ap)




def master_show_mounts(master, ilvl=0):
	print("{}autofs dump map information".format(ind(ilvl)))
	print("{}===========================".format(ind(ilvl)))

	print("{}global options: ".format(ind(ilvl)), end="")
	global_options = gdb.parse_and_eval("global_options")
	if not global_options:
		print("none configured")
	else:
		print("{}".format(global_options))
		print("{}autofs_gbl_sec is probably optimized out".format(ind(ilvl)))
#	print("global options: {}".format(global_options))

#	print("master: ({}){}".format(master.type, master))


	if __master_list_empty(master):
		print("{}no master map entries found".format(ind(ilvl)))
		return false

	head = struct_ptr__member_ptr(master, "mounts")
	p = head['next']

	while not p == head:
		count = 0

		this = list_entry(p, "struct master_mapent", "list")

		p = p['next']

		print("{}({}){} - path: {}, age: {}".format(ind(ilvl), this.type, this, this['path'].string(), this['age']))


		ap = this['ap']

		print("{}Mount point: ({}){} - {}".format(ind(ilvl), ap.type, ap, ap['path'].string()))
		print("{}source(s):".format(ind(ilvl)))
		show_map_sources(this['maps'], ilvl=ilvl)

		# (ap->type == LKP_INDIRECT)
        #                ap->flags |= MOUNT_FLAG_GHOST;

		# skip the lookup_nss_read_map -- we just want to look at the cache as-is
		# perhaps try to output info on what we would actually have looked up

		show_autofs_point(ap, ilvl=ilvl+1)
#		print("{}{} submounts".format(ind(ilvl), ap['submnt_count']))
#		show_submounts(struct_ptr__member_ptr(ap, "submounts"), ilvl=ilvl+1)
#		print("")

#		print("{}amdmounts".format(ind(ilvl)))
#		show_amdmounts(struct_ptr__member_ptr(ap, "amdmounts"), ilvl=ilvl+1)
#		print("")




def print_master(master_list, ilvl=0):
#	lineno = 0

#	master = gdb.parse_and_eval("master")
#	print("master: 0x{:016x} - {}".format(master, master))

#	master_list = gdb.parse_and_eval("master_list")

	master_show_mounts(master_list, ilvl=ilvl+1)
#    expr = '(size_t)&((({} *)0)->{}) - (size_t)(({} *)0)'.format(struct_name, member_name, struct_name)

	# the remainder of the work for 'automount -m' is simply freeing the allocated memory


def print_master_list(master_list, ilvl=0):
	print("{}master_list: ({}){} - {}".format(ind(ilvl), master_list.type, master_list, master_list['name'].string()))
	print("")
	print_master(master_list, ilvl=ilvl)


def get_list_from_head(head):
	ret = []
	p = head['next']
	while p:
		ret.append(p)
		p = p['next']
		if p == head:
			break
	return ret


def show_autofs_point(ap, ilvl=0):
	print("shoing autofs_point: ({}){}".format(ap.type, ap))
	try:
		try:
			ap_path = ap['path']

#			print("{}ap: ({}){} - mount point: ".format(ind(ilvl), ap.type, ap, ap['path'].string()))
#			print("{}ap: ({}){} - mount point: {}".format(ind(ilvl), ap.type, ap, ap_path.type))
#			print("{}ap: ({}){} - mount point: {}".format(ind(ilvl), ap.type, 0, ap_path.type))
			print("{}({}){}".format(ind(ilvl), ap.type, ap))
#		next_level = struct_ptr__member_ptr(ap, "submounts")
#		show_submounts(next_level, ilvl=ilvl)
		except Exception as e:
			print("error getting path?: {}".format(e))
			pass


		try:
			submount_count_var = ap['submount_count']
		except:
			submount_count_var = -1
			pass


#		print("getting list len")
		try:
#			smc_debug = list_len_debug(struct_ptr__member_ptr(ap, 'submounts'))
			smc = list_len(struct_ptr__member_ptr(ap, 'submounts'))

#			print("smc: {}, smc_debug: {}".format(smc, smc_debug))

		except Exception as e:
#			print("failed getting the list length for ((struct autofs_point *)0x{:016x})->submounts: {}".format(ap, e))
			print("failed getting the list length for ((struct autofs_point *){})->submounts: {}".format(ap, e))
			smc = 0
			pass


		try:
#			if submount_count_var >= 0:
#				print("{}submounts: list length: {}, counter: {}".format(ind(ilvl), smc, submount_count_var))
#			else:
#				print("{}submounts: list length: {}".format(ind(ilvl), smc))

			if smc:
#				print("showing submounts")
				show_submounts(struct_ptr__member_ptr(ap, "submounts"), ilvl=ilvl+1)

				print("")
		except Exception as e:
			print("error trying to list submounts: {}".format(e))
			pass


		return
		try:
			amc = list_len(struct_ptr__member_ptr(ap, "amdmounts"))
			print("{}amdmount count - list len: {:d}".format(ind(ilvl), amc))

#			print("{}amdmounts".format(ind(ilvl)))
			show_amdmounts(struct_ptr__member_ptr(ap, "amdmounts"), ilvl=ilvl+1)
			print("")
		except:
			pass

	except Exception as e:
		print("{}error reading from autofs_point at {}: {}".format(ind(ilvl), ap, e))


def print_mnt_list(mnt, ilvl=0):
	print("{}({}){} - mountpoint {}".format(ind(ilvl), mnt.type, mnt, mnt['mp'].string()))

	if check_prune("mnt_list", mnt):
		return

	flags = []
	for k in MNT_LIST_FLAGS:
		if MNT_LIST_FLAGS[k] & mnt['flags']:
			flags.append(k)

	print("{}flags: {}".format(ind(ilvl), "|".join(flags)))


	show_autofs_point(mnt['ap'], ilvl=ilvl+1)

	amd_mountinfo = []
	if mnt['ext_mp']:
		amd_mountinfo.append("ext_mp: {}".format(mnt['ext_mp'].string()))
	if mnt['amd_pref']:
		amd_mountinfo.append("amd_pref: {}".format(mnt['amd_pref'].string()))
	if mnt['amd_type']:
		amd_mountinfo.append("amd_type: {}".format(mnt['amd_type'].string()))
	if mnt['amd_opts']:
		amd_mountinfo.append("amd_opts: {}".format(mnt['amd_opts'].string()))





	amd_mount_list_head = struct_ptr__member_ptr(mnt, "amdmount")
	amd_mount_list = get_list_from_head(amd_mount_list_head)

	if len(amd_mountinfo) > 0 and len(amd_mount_list) > 0:
		print("{}amd mount list info: {} - {} mounts".format(ind(ilvl), ", ".join(amd_mountinfo), len(amd_mount_list)))
	else:
		print("{}amd mount list info: {} - {} mounts".format(ind(ilvl), ", ".join(amd_mountinfo), len(amd_mount_list)))
	if len(amd_mount_list):
		ml = []
		for m in amd_mount_list:
			print("    {}".format(m))
		print("{}amd mount list: {}".format(ind(ilvl), amd_mount_list))


def print_ext_mounts_hash(ilvl=0):
	ext_mounts_hash = gdb.parse_and_eval("ext_mounts_hash")
	size = array_size(ext_mounts_hash)

	print("{}ext_mounts_hash: ({}){} - size: {}".format(ind(ilvl),
		ext_mounts_hash.type, gdb.parse_and_eval("&ext_mounts_hash"), size))

	for i in range(0, size - 1):
		try:
			hashent = ext_mounts_hash[i]['first']
#			obj = gdb.parse_and_eval("&ext_mounts_hash[{}]['first']->mount".format(i))
#			obj = gdb.parse_and_eval("&ext_mounts_hash[{}]->first->mount".format(i))
#			obj = gdb.parse_and_eval("


			p = gdb.parse_and_eval("&ext_mounts_hash[{}]->first".format(i))
			if not p:
				continue

#			while 

#							->mount".format(i))

#			obj2 = 0
		except:
			try:
				p = gdb.parse_and_eval("(&ext_mounts_hash[{}])->next".format(i))
				if not p:
					continue

				hashent = p
#				while p:
#					em = list_entry(p, "struct ext_mount", "mount")
#					p = p['next']
#
#					print("{}p: em: ({}){}".format(ind(ilvl), em.type, em))

#				continue
			except Exception as e:
				pass
#				obj2 = struct_ptr__member_ptr(hashent, "mount")
			except Exception as e:
				continue

		if not hashent:
			continue

		print("{}hash bucket {}, list head: {}".format(ind(ilvl), i, hashent))
#		print("{}obj: ({}){}".format(ind(ilvl), obj.type, obj))
#		print("{}obj2: ({}){}".format(ind(ilvl), obj2.type, obj2))

#		print("")

#((({}){})->{})

#&((({}){})->{})'.format(var.type, var, member))
#gdb.error: A syntax error in expression, near `)->mount)'.


		while hashent:
#			try:
#				print("trying to get container of {}->{}".format("struct ext_mount", "mount"))

#				offset = offsetof("struct ext_mount", "mount")
#				print("offset: {}".format(offset))

#				print("  thing is '{}'".format(hashent))

#				print("address should be 0x{:016x}".format(hashent.value - offset))
#			except:
#				print("error while trying to get the offset/address")

			this = list_entry(hashent, "struct ext_mount", "mount")

#			print("hashent: {} - struct ext_mount: {}".format(hashent, this))


			print("  hash entry: ({}){} - mountpoint: {}, umount: {}".format(
				this.type, this, this['mp'].string() if this['mp'] else "",
				this['umount'].string() if this['umount'] else ""))
# [0x0] unsigned int ref;
# [0x8] char *mp;
#[0x10] char *umount;
#[0x20] struct hlist_node mount;

			hashent = hashent['next']


def print_mnts_hash(ilvl=0):
	try:
		mnts_hash = gdb.parse_and_eval("mnts_hash")
	except:
		print("Unable to find 'mnts_hash'\n\n")
		return
	size = array_size(mnts_hash)
	print("{}mnts_hash: ({}){}".format(ind(ilvl), mnts_hash.type, gdb.parse_and_eval("&mnts_hash")))
#		gdb.parse_and_eval("mnts_hash"), gdb.parse_and_eval("sizeof(mnts_hash)"), array_size("mnts_hash")))

	if check_prune("mnts_hash", "0"):
		return

	for i in range(0, size - 1):
		hashent = mnts_hash[i]['first']
		if not hashent:
			continue
		while hashent:
			this = list_entry(hashent, "struct mnt_list", "hash")
#			this2 = gdb.parse_and_eval("(struct mnt_list *){}".format(this))

			print("{}hash entry {}: ({}){} - {}".format(ind(ilvl+1), i, this.type, this, this['mp'].string()))
			print("{}age: {}".format(ind(ilvl+2), this['age']))
			print_mnt_list(this, ilvl=ilvl+1)
			print("")

#			ap = this['ap']
#			try:
#				print("    ap: ({}){} - mount point: ".format(ap.type, ap, ap['path'].string()))
#			except:
#				print("error reading from autofs_point at {}".format(ap))


#type = struct mnt_list {
#    char *mp;
#    size_t len;
#    unsigned int flags;
#    struct hlist_node hash;
#    unsigned int ref;
#    struct list_head mount;
#    struct list_head expire;
#    struct autofs_point *ap;
#    struct list_head submount;
#    struct list_head submount_work;
#    char *ext_mp;
#    char *amd_pref;
#    char *amd_type;
#    char *amd_opts;
#    unsigned int amd_cache_opts;
#    struct list_head amdmount;
#    struct tree_node node;
#    struct mnt_list *next;

			hashent = hashent['next']

#    struct mapent *next;
#    struct list_head ino_index;
#    struct mapent_cache *mc;
#    struct map_source *source;
#    struct tree_node *mm_root;
#    struct tree_node *mm_parent;
#    struct tree_node node;
#    struct list_head work;
#    char *key;
#    size_t len;
#    char *mapent;
#    struct stack *stack;
#    time_t age;
#    time_t status;
#    int flags;
#    int ioctlfd;
#    dev_t dev;
#    ino_t ino;


#(gdb) py print("{}".format(gdb.parse_and_eval("sizeof(mnts_hash)/sizeof(mnts_hash[0])")))




def main():

	master_list = gdb.parse_and_eval("(struct master *)master_list")

	print_master_list(master_list, ilvl=0)

#	print_mnts_hash(ilvl=0)

	print_ext_mounts_hash()

main()
do_pruning = saved_do_pruning


# vim: sw=4 ts=4 noexpandtab
