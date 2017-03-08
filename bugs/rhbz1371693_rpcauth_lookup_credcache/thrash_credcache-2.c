/*
	Frank Sorenson <sorenson@redhat.com>, 2016

	Test program to fill the rpcauth credcache with a large number of
	creds, all with the same uid, but differing gids.

	The existing kernel code only hashes the creds in the cache based
	on the uid, and gid is not taken into account, so this results in
	hash chains disproportionately long for these uids, and causes
	very bad lookup performance.

	Once the cred hash function takes both uid and gid into account,
	the creds are well distributed within the cache, without very
	long individual hash chains.

	usage:  thrash_credcache-2.c  <path> <start_gid> <end_gid>
		start_gid and end_gid should be numeric, and are inclusive
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	char *path;
	gid_t start_gid, end_gid;
	gid_t i;
	struct stat st;

	if (argc != 4) {
		printf("usage: %s <path> <start_gid> <end_gid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	path = argv[1];
	start_gid = strtol(argv[2], NULL, 10);
	end_gid = strtol(argv[3], NULL, 10);

	printf("calling stat on '%s' with gids %u through %u\n", path, start_gid, end_gid);
	for (i = start_gid ; i < end_gid + 1 ; i ++) {
//		setfsgid(i);
		setregid(-1, i); /* setting egid also sets fsgid */
		stat(path, &st);
	}

	return EXIT_SUCCESS;
}
