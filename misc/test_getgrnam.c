/*
	Frank Sorenson <sorenson@redhat.com>, 2021

	determine the size of a buffer required to contain the members of a group when calling 'getgrnam_r'
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define MAX_BUF_LEN 32768
#define BUF_INCR 32

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


struct grbuf {
	struct group grbuf;
	char buf[1];
};

void hexdump(const unsigned char *pre, const unsigned char *addr, size_t len) {
	size_t offset = 0;
	char buf[17];
	int i;

	if (pre == NULL)
		pre = (unsigned char *)"";
	while (offset < len) {
		int this_count = min(len - offset, 16);

		memcpy(buf, addr + offset, this_count);
		printf("%s%p: ", pre, addr + offset);
		for (i = 0 ; i < 16 ; i++) {
			if (i < this_count)
				printf("%02x ", buf[i]);
			else
				printf("   ");
			if (i == 7)
				printf("| ");
			if (i >= this_count)
				buf[i] = '\0';
			else if (! isprint(buf[i]))
				buf[i] = '.';
		}
		buf[i] = '\0';
		printf(" |%s|\n", buf);
		offset += this_count;
	}
}


int main(int argc, char *argv[]) {
	char *group_name = "dsrit";

	struct group *gr;
	struct grbuf *buf = NULL;
	size_t buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	int err, ret = EXIT_SUCCESS;

	if (argc == 2)
		group_name = argv[1];



	printf("_SC_GETGR_R_SIZE_MAX os %ld\n", sysconf(_SC_GETGR_R_SIZE_MAX));

	printf("searching for group '%s'\n", group_name);


#if 0
	struct grbuf *newbuf = NULL;
realloc_buf:
	if (buflen > MAX_BUF_LEN) { /* nope, sorry... it's just too large */
		printf("group is too large\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	if ((newbuf = realloc(buf, sizeof(*buf) + buflen)) == NULL) {
		printf("could not allocate memory\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	buf = newbuf;

	err = getgrnam_r(group_name, &buf->grbuf, buf->buf, buflen, &gr);
	if (err == EINTR)
		goto realloc_buf;

	if (!gr && err == ERANGE) {
		buflen += sysconf(_SC_GETGR_R_SIZE_MAX);
		goto realloc_buf;
	} else if (!gr) {
		if (err == 0)
		err = ENOENT;
		printf("could not find group_name '%s' ... error: %s\n", group_name, strerror(err));
		ret = EX(T_FAILURE;
		goto out;
	}
	
#else
	buf = malloc(sizeof(*buf) + buflen);
//	while (buf != NULL && ((err = getgrnam(group_name, &buf->grbuf, buf->buf, buflen, &gr)) == ERANGE)) {
	while (buf != NULL && ((err = getgrnam_r(group_name, &buf->grbuf, buf->buf, buflen, &gr)) == ERANGE)) {
		struct grbuf *newbuf;
		buflen += sysconf(_SC_GETGR_R_SIZE_MAX);
		newbuf = realloc(buf, sizeof(*buf) + buflen);
		if (newbuf == NULL) {
			printf("unable to allocate memory\n");
			goto out;
		}
		buf = newbuf;
	}

#endif

	printf("@%p - %p - struct group, struct size: %lu\n",
		&buf->grbuf, &buf->grbuf + sizeof(buf->grbuf),
		sizeof(buf->grbuf));
	printf("found group '%s' after buffer size %lu\n", group_name, buflen);
	printf("group name: %s @%p\n", buf->grbuf.gr_name, buf->grbuf.gr_name);
	printf("gid: %d\n", buf->grbuf.gr_gid);
	printf("group passwd: %s @%p\n", buf->grbuf.gr_passwd, buf->grbuf.gr_passwd);

	printf("sizeof(struct group): %lu\n", sizeof(struct group));

int char_count = 0;
int mbr_ptr_count = 0;
int mbr_NULL_count = 0;
int mbr_count = 0;

	while (42) {
		char *mbr = buf->grbuf.gr_mem[mbr_ptr_count];
		mbr_ptr_count++;
		if (mbr == NULL)
			break;
	}

	void *ptr_start_addr = &buf->grbuf.gr_mem[0];
	printf("found %d pointers, beginning at %p\n", mbr_ptr_count, ptr_start_addr);


	while (42) {
/* struct group:
char   *gr_name;       // group name
char   *gr_passwd;     // group password
gid_t   gr_gid;        // group ID
char  **gr_mem;        // group members
*/

//required size is sizeof(struct group) + size of a buffer

//        struct group grbuf;
//        char buf[1];
		char *mbr = buf->grbuf.gr_mem[mbr_count];
		mbr_ptr_count++;

		if (mbr == NULL) {
			printf("@%p NULL stop value (%p)\n", &buf->grbuf.gr_mem[mbr_count], buf->grbuf.gr_mem[mbr_count]);
			break;
		}

		int this_len = strlen(mbr);


		printf("@%p: group name @%p - member %d: '%s' - length: %d\n",
			&buf->grbuf.gr_mem[mbr_count], mbr, mbr_count, mbr, this_len);


//			printf("%d: pointer @%p, string @%p - %s (%d bytes)\n", mbr_count, &buf->grbuf.gr_mem[mbr_count],
//					mbr, mbr, this_len);
		char_count += this_len;

		mbr_count++;
		mbr_NULL_count++;

	}
	printf("sizeo(struct group): %lu\n", sizeof(struct group));
	printf("bytes in group name: %lu (+ 1 NULL)\n", strlen(buf->grbuf.gr_name));
	printf("bytes in group password: %lu (+ 1 NULL)\n", strlen(buf->grbuf.gr_passwd));

	printf("found %d members, total characters of strings: %d (+ %d NULL), member_pointer count: %d, member pointer bytes: %lu\n",
		mbr_count, char_count, mbr_NULL_count, mbr_ptr_count
		, sizeof(buf->grbuf.gr_mem[0]) * (mbr_count + 1));


	int estimated_bytes = sizeof(struct group)
		+ strlen(buf->grbuf.gr_name) + 1
		+ strlen(buf->grbuf.gr_passwd) + 1
		+ char_count + mbr_NULL_count
		+ mbr_ptr_count * sizeof(buf->grbuf.gr_mem[0]) /* size of each ptr */;

//			+ ((mbr_count + 1 /* member string pointers */) * sizeof(buf->grbuf.gr_mem[0]) /* size of each ptr */);

	printf("estimated bytes: %d (buffer size which worked: %lu\n", estimated_bytes, buflen);

	printf("sizeof *buf: %lu\n", sizeof(*buf));


out:
	if (buf)
		free(buf);

	return ret;
}

