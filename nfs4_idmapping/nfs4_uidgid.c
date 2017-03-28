#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
//#include <nfs4_idmap.h>
#include <nfsidmap.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>


static void dbg_printf_internal(const char *fmt, ...) {
	va_list vp;

	va_start(vp, fmt);
	printf(fmt, vp);
	va_end(vp);
}

#define dbg_printf(print_lvl, selected_lvl, args...) do { \
	if (selected_lvl >= print_lvl) \
		dbg_printf_internal(args); \
} while (0)

#define min(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})
#define max(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})

#define get_optional() ({ \
	char *ptr = optarg ? optarg : argv[optind]; \
	if (optarg || argv[optind]) \
		optind++; \
	ptr; \
})

//#define LOOKUP_NAME 1
//#define LOOKUP_ID 2

#define FALLBACK_BUFSIZE 4096

struct config {
	char *config_file;

	char *lookup_user_string;
	char *current_user_string;

	char *lookup_group_string;
	char *current_group_string;

	char *domain_string;
	char *default_domain_string;

	size_t pw_size_max;
	size_t gr_size_max;

	uid_t lookup_uid;
	uid_t current_uid;

	gid_t lookup_gid;
	gid_t current_gid;

	int verbosity;

	bool lookup_user;
	bool lookup_group;
};

static void get_default_domain(struct config *config) {
	char buf[max(NFS4_MAX_DOMAIN_LEN, 256)];

	nfs4_get_default_domain(NULL, buf, sizeof(buf));
	config->default_domain_string = strdup(buf);
	dbg_printf(1, config->verbosity, "found default domain as '%s'\n",
		config->default_domain_string);
}

char *get_current_user_info(struct config *config) {
	struct passwd passwd;
	struct passwd *result;
	char *buf;
	int ret;

	buf = malloc(config->pw_size_max);

	config->current_uid = getuid();
	ret = getpwuid_r(config->current_uid, &passwd, buf, config->pw_size_max, &result);
	if (ret) {
		printf("error occurred getting passwd info from uid %d\n", config->current_uid);
	} else if (!result) {
		printf("no username matching uid %d found\n", config->current_uid);
	} else
		config->current_user_string = strdup(result->pw_name);
	free(buf);
	return config->current_user_string;
}

void get_current_group_info(struct config *config) {
	struct group group;
	struct group *result;
	char *buf;
	int ret;

	buf = malloc(config->gr_size_max);

	config->current_gid = getgid();
	ret = getgrgid_r(config->current_gid, &group, buf, config->gr_size_max, &result);
	if (ret) {
		printf("error occurred getting group info from gid %d\n", config->current_gid);
	} else if (!result) {
		printf("no group matching gid %d found\n", config->current_gid);
	} else
		config->current_group_string = strdup(result->gr_name);
	free(buf);
}


#if 0
	if (! config->default_domain_string)
		get_default_domain(config);



		asprintf(&config->lookup_user_string, "%d@%s", config->current_uid,
			config->domain_string ? config->domain_string : config->default_domain_string);
		return;
	} else if (! result) {
		asprintf(&config->lookup_user_string, "%d@%s", config->current_uid,
			config->domain_string ? config->domain_string : config->default_domain_string);
		return;
	}

	asprintf(&config->lookup_user_string, "%s@%s", result->pw_name,
		config->domain_string ? config->domain_string : config->default_domain_string);
}
#endif

//void get_current_groupname(struct config *config) {
//	gid_t gid = getgid();
//	asprintf(&config->lookup_group_string, "%d", gid);
//}

void show_local_user_info(struct config *config, const char *type, const char *mapped_name, uid_t uid) {
	struct passwd passwd;
	struct passwd *result;
	char *local_username;
	char *buf;
	int ret;

	buf = malloc(config->pw_size_max);
	ret = getpwuid_r(uid, &passwd, buf, config->pw_size_max, &result);

	if (ret || (! result))
		local_username = "<UNKNOWN>";
	else
		local_username = result->pw_name;

	printf("this system would map nfsv4 %s '%s' to uid %d, local user '%s'\n",
		type, mapped_name, uid, local_username);
	free(buf);
}
int lookup_username_to_uid_old(struct config *config, char *username) {
	uid_t uid;
	int ret;

	dbg_printf(1, config->verbosity, "calling nfs4_name_to_uid with username '%s', config->domain_string='%s'\n",
		username, config->domain_string);

	if ((ret = nfs4_name_to_uid(username, &uid)) != 0) {
		if (ret == -ENOENT)
			printf("nfs4_username_to_uid was unable to map username '%s' to a uid\n", username);
		else {
			printf("error calling name_to_uid for '%s': %s\n", username, strerror(-ret));
			return 1;
		}
	} else
		show_local_user_info(config, "username", username, uid);
	return 0;
}

int do_lookup_to_uid(struct config *config, char *str, const char *type, typeof(nfs4_name_to_uid) *fn) {
	uid_t uid;
	int ret;

	dbg_printf(1, config->verbosity, "calling nfs4_%s_to_uid with '%s', config->domain_string='%s'\n",
		type, str, config->domain_string);

	if ((ret = fn(str, &uid)) != 0) {
		if (ret == -ENOENT)
			printf("unable to map %s '%s' to a uid\n", type, str);
		else {
			printf("error calling nfs4_%s_to_uid for '%s': %s\n", type, str, strerror(-ret));
			return 1;
		}
	} else
		show_local_user_info(config, type, str, uid);
	return 0;
}
int lookup_username_to_uid(struct config *config, char *username) {
//	return lookup_username_to_uid_old(config, username);
	return do_lookup_to_uid(config, username, "name", &nfs4_name_to_uid);
}
int lookup_owner_to_uid(struct config *config, char *owner) {
	return do_lookup_to_uid(config, owner, "owner", &nfs4_owner_to_uid);
}
//lookup_username_to_uid
//(struct config *config, char *str, const char *type, typeof(nfs4_name_to_uid) *fn) {
//int lookup_username_to_uid(struct config *config, char *username) {


//int lookup_uid_to_username(struct config *config, uid_t uid) {
int lookup_from_uid(struct config *config, uid_t uid) {
	char buf[1024];
	int ret;

	dbg_printf(1, config->verbosity, "calling nfs4_uid_to_name with uid=%d, config->domain_string='%s', buf=%p\n",
		uid, config->domain_string, buf);

	if ((ret = nfs4_uid_to_name(uid, config->domain_string, buf, 1024)) != 0) {
		if (ret == -ENOENT)
			printf("nfs4_uid_to_name was unable to map uid %d to an nfsv4 username\n", uid);
		else {
			printf("nfs4_uid_to_name returned %d: %s\n", ret, ret < 0 ? strerror(-ret) : "unknown error");
			return 1;
		}
	} else
		printf("this system would map uid %d to nfsv4 username '%s'\n", uid, buf);

	if ((ret = nfs4_uid_to_owner(uid, config->domain_string, buf, 1024)) != 0) {
		if (ret == -ENOENT)
			printf("nfs4_uid_to_owner was unable to map uid %d to an nfsv4 owner\n", uid);
		else {
			printf("nfs4_uid_to_owner returned %d: %s\n", ret, ret < 0 ? strerror(-ret) : "unknown error");
			return 1;
		}
	} else
		printf("this system would map uid %d to nfsv4 owner '%s'\n", uid, buf);
	return 0;
}

void do_lookup_group(struct config *config) {
	gid_t gid;
	int ret;

	if ((ret = nfs4_name_to_gid(config->lookup_group_string, &gid)) != 0) {
		printf("error calling name_to_gid for '%s': %s\n", config->lookup_group_string, strerror(-ret));
	} else {
		printf("gid for '%s' is %d\n", config->lookup_group_string, gid);
	}
}


static bool all_digits(const char *str) {
	int i = 0;
	while (str[i]) {
		if (!isdigit(str[i]))
			return false;
		i++;
	}
	return true;
}
static bool string_has_domain(const char *str) {
	int len = strlen(str);
	char *ptr = strchr(str, '@');

	if (ptr == NULL || ptr > str + len)
		return false;
	return true;
}

void do_user_lookups(struct config *config) {
	char *ptr;
	uid_t uid;

	/* lookup_user_string could contain:
		USER@DOMAIN
		USER
		uid@DOMAIN
		uid
		<nothing>
	*/

	if (! config->lookup_user_string) {
		/* just lookup the current uid => nfsv4 name */
		lookup_from_uid(config, config->current_uid);
		return;
	}
	if (all_digits(config->lookup_user_string)) {
		uid = strtol(config->lookup_user_string, &ptr, 10);
		if (uid == LONG_MIN || uid == LONG_MAX) {
			if (errno != ERANGE) {
				return;
			} else { /* hmm */
			}
		}
		lookup_from_uid(config, uid);
//		lookup_uid_to_username(config, uid);
//		lookup_uid_to_owner(config, uid);
		return;
	}
	if (config->lookup_user_string) {
		/* if a string is given, it should either have '@domain', or we should try to add one */
		ptr = config->lookup_user_string;

		if (! string_has_domain(config->lookup_user_string)) { /* no domain in the string */
			if (config->domain_string) { /* domain was given */
				dbg_printf(1, config->verbosity, "Adding given domain '%s' to the supplied string '%s'\n",
					config->domain_string, config->lookup_user_string);
				asprintf(&ptr, "%s@%s", config->lookup_user_string, config->domain_string);
			} else { /* no domain given */
				dbg_printf(1, config->verbosity, "Adding default domain to the supplied string '%s'\n",
					config->lookup_user_string);
				get_default_domain(config);
				asprintf(&ptr, "%s@%s", config->lookup_user_string, config->default_domain_string);
			}
		}

		lookup_username_to_uid(config, ptr);
		lookup_owner_to_uid(config, ptr);

		if (ptr != config->lookup_user_string)
			free(ptr);


#if 0
look up group?: FALSE
	error calling name_to_uid for 'sorenson': Invalid argument
	this system would map nfsv4 owner 'sorenson' to uid 99, local user 'nobody'
	[sorenson@hut tmp]$ ./nfs4_uidgid sorenson -d sorenson.redhat.com
	more opts:
		look up user?: TRUE
		look up group?: FALSE
		error calling name_to_uid for 'sorenson': Invalid argument
		this system would map nfsv4 owner 'sorenson' to uid 99, local user 'nobody'
		[sorenson@hut tmp]$ ./nfs4_uidgid sorenson@sorenson.redhat.com
		more opts:
			look up user?: TRUE
			look up group?: FALSE
			this system would map nfsv4 username 'sorenson@sorenson.redhat.com' to uid 1000, local user 'sorenson'
			this system would map nfsv4 owner 'sorenson@sorenson.redhat.com' to uid 1000, local user 'sorenson'
#endif


//		if (! string_has_domain(config->lookup_user_string)) {
//
//		if (config->
//get_default_domain
//
	} else {
		lookup_username_to_uid(config, config->current_user_string);
	}

#if 0
	} else if (ptr != NULL) {
		/* ###@DOMAIN perhaps? */
		if (ptr[0] == '@')
			string_has_domain = true;
	}

	if (ptr != NULL && config->domain_string != NULL) {
		if (ptr[0] == '\0') {
//			return;
		} else {
			if (strcmp(config->domain_string, ptr)) { /* domain is the same */
			} else {
				printf("is domain '%s' or '%s'?\n", config->domain_string, ptr);
				return;
			}
		}
	} // else if (ptr != NULL && domain_string == NULL 
#endif

#if 0
int nfs4_gid_to_name(gid_t gid, char *domain, char *name, size_t len);
int nfs4_gid_to_owner(gid_t gid, char *domain, char *name, size_t len);

int nfs4_name_to_uid(char *name, uid_t *uid);
int nfs4_name_to_gid(char *name, gid_t *gid);

int nfs4_owner_to_uid(char *name, uid_t *uid);
int nfs4_owner_to_gid(char *name, gid_t *gid);
#endif

}

void do_group_lookups(struct config *config) {
}

void do_lookups(struct config *config) {

	if (!config->domain_string) {

	}
	if (!config->lookup_user && !config->lookup_group) {
		/* neither user/uid nor group/gid specified */
		config->lookup_user = true;
		config->lookup_group = true;
	}
	if (config->lookup_user && !config->lookup_user_string)
		get_current_user_info(config);
	if (config->lookup_group && !config->lookup_group_string)
		get_current_group_info(config);

	if (config->lookup_user)
		do_user_lookups(config);
	if (config->lookup_group)
		do_group_lookups(config);
}

void setup(struct config *config) {
	nfs4_set_debug(config->verbosity, dbg_printf_internal);
	nfs4_init_name_mapping(config->config_file);

	if ((config->pw_size_max = sysconf(_SC_GETPW_R_SIZE_MAX)) < 0)
		config->pw_size_max = FALLBACK_BUFSIZE;
	if ((config->gr_size_max = sysconf(_SC_GETGR_R_SIZE_MAX)) < 0)
		config->gr_size_max = FALLBACK_BUFSIZE;
}

void parse_opts(struct config *config, int argc, char *argv[]) {
	static struct option long_options[] = {
		{ "user",	optional_argument, NULL, 'u' },
		{ "group",	optional_argument, NULL, 'g' },
		{ "domain",	required_argument, NULL, 'd' },
		{ "config",	required_argument, NULL, 'c' },
		{ "verbose",	no_argument, NULL, 'v' },
		{ 0, 0, 0, 0 }
	};
	char *ptr;
	int opt;

	while (1) {
		opt = getopt_long(argc, argv, "u::g::d:c:v", long_options, &optind);
		if (opt == -1)
			break;
		dbg_printf(2, config->verbosity, "selected '%c' (0x%hhx), optopt='%c' optind=%d, argv[optind]='%s', optarg='%s'\n",
			opt, opt, optopt, optind, argv[optind], optarg);
		switch (opt) {
			case 0:
				printf("option '%s'", long_options[optind].name);
				if (optarg)
					printf(" with arg '%s'", optarg);
				printf("\n");
				break;
			case 'u':
				ptr = get_optional();

				if (config->lookup_user) {
					if (config->lookup_user_string && ptr) {
						if (strcmp(config->lookup_user_string, ptr))
							printf("user lookup already set for '%s', can't set again to '%s'\n",
								config->lookup_user_string, ptr);
						else
							printf("user lookup already set for '%s'\n",
								config->lookup_user_string);
					} else if (ptr) {
						config->lookup_user_string = strdup(ptr);
						dbg_printf(1, config->verbosity, "looking up user name/uid '%s'\n",
							config->lookup_user_string);
					} else
						printf("user lookup already set for user name/uid '%s'\n",
							config->lookup_user_string);
				} else {
					config->lookup_user = true;
					if (ptr) {
						config->lookup_user_string = strdup(ptr);
						dbg_printf(1, config->verbosity, "looking up user name/uid '%s'\n",
							config->lookup_user_string);
					} else
						dbg_printf(1, config->verbosity, "looking up user name/uid for current user\n");
				}
				break;
			case 'g':
				ptr = get_optional();
				if (config->lookup_group) {
					if (config->lookup_group_string && ptr) {
						if (strcmp(config->lookup_group_string, ptr))
							printf("group lookup already set for '%s', can set again to '%s'\n",
								config->lookup_group_string, ptr);
						else
							printf("user lookup already set for '%s'\n",
								config->lookup_group_string);
					} else if (ptr) {
						config->lookup_group_string = strdup(ptr);
						dbg_printf(1, config->verbosity, "looking up group name/gid '%s'\n",
							config->lookup_group_string);
					} else
						printf("group lookup already set for group/gid '%s'\n",
							config->lookup_group_string);
				} else {
					config->lookup_group = true;
					if (ptr) {
						config->lookup_group_string = strdup(ptr);
						dbg_printf(1, config->verbosity, "looking up group name/gid '%s'\n",
							config->lookup_group_string);
					} else
						dbg_printf(1, config->verbosity, "looking up group/gid for current user\n");
				}
				break;
			case 'd':
				ptr = optarg ? optarg : argv[optind];
				if (config->domain_string && strcmp(config->domain_string, ptr))
					printf("domain already set to '%s', can't set again to '%s'\n",
						config->domain_string, ptr);
				else if (!config->domain_string) {
					config->domain_string = strdup(ptr);
					dbg_printf(1, config->verbosity, "lookup with domain '%s'\n", config->domain_string);
				}
				break;
			case 'c':
				ptr = optarg ? optarg : argv[optind];
				if (config->config_file && strcmp(config->config_file, ptr))
					printf("config file already set to '%s', not setting again to '%s'\n",
						config->config_file, ptr);
				else {
					config->config_file = strdup(ptr);
					dbg_printf(1, config->verbosity, "setting config file to '%s'\n", config->config_file);
				}
				break;
			case 'v':
				config->verbosity++;
				dbg_printf(1, config->verbosity, "increasing verbosity\n");
				break;
			case '?':
				printf("unknown\n");
				break;
			default:
				printf("unknown argument '%c'\n", opt);
				break;
		}
	}
	if (optind < argc) {
		int i;

		printf("more opts:\n");

		i = optind;
		while (i < argc) {
			printf("\topt: %s\n", argv[i++]);
		}
	}
//return 0;



	if (optind == argc - 1) {
		if (! config->lookup_user) {
			config->lookup_user = true;
			config->lookup_user_string = strdup(argv[optind]);
		}
//		if ((optind == argc - 1) && (! config->lookup_user && ! config->lookup_group))
	}
}

int main(int argc, char *argv[]) {
//	char buf[max(NFS4_MAX_DOMAIN_LEN, 256)];
//	char domain[NFS4_MAX_DOMAIN_LEN];

//	int opt, optind;
//	uid_t uid;
//	int ret;

	struct config config;

	memset(&config, 0, sizeof(config));
	parse_opts(&config, argc, argv);

//	printf("more opts:\n");

//	i = optind;
//	while (i < argc) {
//		printf("\topt: %s\n", argv[i++]);
//	}
//return 0;

//	for (i = 0 ; i < argc ; i ++) {
//		printf("\t%c%c%s\n", i < argc ? '*' : '-', i < optind ? '*' : '+',  argv[i]);
//	}
//	return 0;


	setup(&config);

	do_lookups(&config);


	return EXIT_SUCCESS;
}

