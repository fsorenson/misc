#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


static unsigned long sdbm_hash(const char *str, unsigned long seed)
{
	unsigned long hash = seed;
	char c;

	while ((c = *str++))
		hash = c + (hash << 6) + (hash << 16) - hash;
	return hash;
}

static uint32_t inline hash(const char *key, unsigned int size)
{
        u_int32_t hashval;
        char *s = (char *) key;

        for (hashval = 0; *s != '\0';) {
                hashval += (unsigned char) *s++;
                hashval += (hashval << 10);
                hashval ^= (hashval >> 6);
        }

        hashval += (hashval << 3);
        hashval ^= (hashval >> 11);
        hashval += (hashval << 15);

        return hashval % size;
}



int main(int argc, char *argv[]) {
	char *paths[] = {
"repro/dir_a1/dir_a1b293/dir_a1b293c1/dir_a1b293c1d1/dir_a1b293c1d1e1/dir_a1b293c1d1e1f1/dir_a1b293c1d1e1f1g1/dir_a1b293c1d1e1f1g1h1/dir_a1b293c1d1e1f1g1h1i1/dir_a1b293c1d1e1f1g1h1i1j1/dir_a1b293c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b230/dir_a1b230c1/dir_a1b230c1d1/dir_a1b230c1d1e1/dir_a1b230c1d1e1f1/dir_a1b230c1d1e1f1g1/dir_a1b230c1d1e1f1g1h1/dir_a1b230c1d1e1f1g1h1i1/dir_a1b230c1d1e1f1g1h1i1j1/dir_a1b230c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b239/dir_a1b239c1/dir_a1b239c1d1/dir_a1b239c1d1e1/dir_a1b239c1d1e1f1/dir_a1b239c1d1e1f1g1/dir_a1b239c1d1e1f1g1h1/dir_a1b239c1d1e1f1g1h1i1/dir_a1b239c1d1e1f1g1h1i1j1/dir_a1b239c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b382/dir_a1b382c1/dir_a1b382c1d1/dir_a1b382c1d1e1/dir_a1b382c1d1e1f1/dir_a1b382c1d1e1f1g1/dir_a1b382c1d1e1f1g1h1/dir_a1b382c1d1e1f1g1h1i1/dir_a1b382c1d1e1f1g1h1i1j1/dir_a1b382c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b404/dir_a1b404c1/dir_a1b404c1d1/dir_a1b404c1d1e1/dir_a1b404c1d1e1f1/dir_a1b404c1d1e1f1g1/dir_a1b404c1d1e1f1g1h1/dir_a1b404c1d1e1f1g1h1i1/dir_a1b404c1d1e1f1g1h1i1j1/dir_a1b404c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b182/dir_a1b182c1/dir_a1b182c1d1/dir_a1b182c1d1e1/dir_a1b182c1d1e1f1/dir_a1b182c1d1e1f1g1/dir_a1b182c1d1e1f1g1h1/dir_a1b182c1d1e1f1g1h1i1/dir_a1b182c1d1e1f1g1h1i1j1/dir_a1b182c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b367/dir_a1b367c1/dir_a1b367c1d1/dir_a1b367c1d1e1/dir_a1b367c1d1e1f1/dir_a1b367c1d1e1f1g1/dir_a1b367c1d1e1f1g1h1/dir_a1b367c1d1e1f1g1h1i1/dir_a1b367c1d1e1f1g1h1i1j1/dir_a1b367c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b215/dir_a1b215c1/dir_a1b215c1d1/dir_a1b215c1d1e1/dir_a1b215c1d1e1f1/dir_a1b215c1d1e1f1g1/dir_a1b215c1d1e1f1g1h1/dir_a1b215c1d1e1f1g1h1i1/dir_a1b215c1d1e1f1g1h1i1j1/dir_a1b215c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b34/dir_a1b34c1/dir_a1b34c1d1/dir_a1b34c1d1e1/dir_a1b34c1d1e1f1/dir_a1b34c1d1e1f1g1/dir_a1b34c1d1e1f1g1h1/dir_a1b34c1d1e1f1g1h1i1/dir_a1b34c1d1e1f1g1h1i1j1/dir_a1b34c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b129/dir_a1b129c1/dir_a1b129c1d1/dir_a1b129c1d1e1/dir_a1b129c1d1e1f1/dir_a1b129c1d1e1f1g1/dir_a1b129c1d1e1f1g1h1/dir_a1b129c1d1e1f1g1h1i1/dir_a1b129c1d1e1f1g1h1i1j1/dir_a1b129c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b216/dir_a1b216c1/dir_a1b216c1d1/dir_a1b216c1d1e1/dir_a1b216c1d1e1f1/dir_a1b216c1d1e1f1g1/dir_a1b216c1d1e1f1g1h1/dir_a1b216c1d1e1f1g1h1i1/dir_a1b216c1d1e1f1g1h1i1j1/dir_a1b216c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b181/dir_a1b181c1/dir_a1b181c1d1/dir_a1b181c1d1e1/dir_a1b181c1d1e1f1/dir_a1b181c1d1e1f1g1/dir_a1b181c1d1e1f1g1h1/dir_a1b181c1d1e1f1g1h1i1/dir_a1b181c1d1e1f1g1h1i1j1/dir_a1b181c1d1e1f1g1h1i1j1k1",
"repro/dir_a1/dir_a1b202/dir_a1b202c1/dir_a1b202c1d1/dir_a1b202c1d1e1/dir_a1b202c1d1e1f1/dir_a1b202c1d1e1f1g1/dir_a1b202c1d1e1f1g1h1/dir_a1b202c1d1e1f1g1h1i1/dir_a1b202c1d1e1f1g1h1i1j1/dir_a1b202c1d1e1f1g1h1i1j1k1",
	};

	char *paths2[] = {
"/rhbz2139504/repro/dir_a1/dir_a1b230/dir_a1b230c1/dir_a1b230c1d1/dir_a1b230c1d1e1/dir_a1b230c1d1e1f1/dir_a1b230c1d1e1f1g1",
"/rhbz2139504/repro/dir_a1/dir_a1b239/dir_a1b239c1/dir_a1b239c1d1/dir_a1b239c1d1e1/dir_a1b239c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b382/dir_a1b382c1/dir_a1b382c1d1/dir_a1b382c1d1e1/dir_a1b382c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b404/dir_a1b404c1/dir_a1b404c1d1/dir_a1b404c1d1e1/dir_a1b404c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b182/dir_a1b182c1/dir_a1b182c1d1/dir_a1b182c1d1e1/dir_a1b182c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b367/dir_a1b367c1/dir_a1b367c1d1/dir_a1b367c1d1e1/dir_a1b367c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b215/dir_a1b215c1/dir_a1b215c1d1/dir_a1b215c1d1e1/dir_a1b215c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b34/dir_a1b34c1/dir_a1b34c1d1/dir_a1b34c1d1e1/dir_a1b34c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b129/dir_a1b129c1/dir_a1b129c1d1/dir_a1b129c1d1e1/dir_a1b129c1d1e1f1",
"/rhbz2139504/repro/dir_a1/dir_a1b216/dir_a1b216c1",
"/rhbz2139504/repro/dir_a1/dir_a1b181",
"/rhbz2139504/repro/dir_a1/dir_a1b181/dir_a1b181c1/dir_a1b181c1d1/dir_a1b181c1d1e1/dir_a1b181c1d1e1f1/dir_a1b181c1d1e1f1g1/dir_a1b181c1d1e1f1g1h1",
"/rhbz2139504/repro/dir_a1/dir_a1b202",
	};



	int i;
	unsigned long hval;
	uint32_t hval2;

	for (i = 0 ; i < sizeof(paths2)/sizeof(paths2[0]) ; i++) {
//		hval = sdbm_hash(paths2[i], 0);
//		printf("%d - hash: %ld - %s\n", i, hval, paths2[i]);

		



		hval2 = hash(paths2[i], 1024);
		printf("%d - hash: %u - %s\n", i, hval2, paths2[i]);
	}




	return EXIT_SUCCESS;
}

