#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define XDR_QUADLEN(l)          (((l) + 3) >> 2)

#define unlikely(x) (x)
#define likely(x) (x)

typedef unsigned int __be32;
struct page {};
struct kvec {};


struct xdr_buf {
        struct kvec     head[1],        /* RPC header + non-page data */
                        tail[1];        /* Appended after page data */

        struct page **  pages;          /* Array of pages */
        unsigned int    page_base,      /* Start of page data */
                        page_len,       /* Length of page data */
                        flags;          /* Flags for data disposition */
#define XDRBUF_READ             0x01            /* target of file read */
#define XDRBUF_WRITE            0x02            /* source of file write */

        unsigned int    buflen,         /* Total length of storage buffer */
                        len;            /* Length of XDR encoded message */
};

struct xdr_stream {
        __be32 *p;              /* start of available buffer */
        struct xdr_buf *buf;    /* XDR buffer to read/write */

        __be32 *end;            /* end of available buffer space */
        struct kvec *iov;       /* pointer to the current kvec */
        struct kvec scratch;    /* Scratch buffer */
        struct page **page_ptr; /* pointer to the current page */
        unsigned int nwords;    /* Remaining decode buffer length */
};


static bool xdr_set_next_buffer(struct xdr_stream *xdr)
{
	return 0;
}

struct nfs_entry {
	int len;
	int foo;
};



static __be32 * __xdr_inline_decode(struct xdr_stream *xdr, size_t nbytes)
{
        unsigned int nwords = XDR_QUADLEN(nbytes);
        __be32 *p = xdr->p;
        __be32 *q = p + nwords;

        if (unlikely(nwords > xdr->nwords || q > xdr->end || q < p))
                return NULL;
        xdr->p = q;
        xdr->nwords -= nwords;
        return p;
}

__be32 * xdr_copy_to_scratch(struct xdr_stream *xdr, size_t nbytes) {
	printf("%s: would copy %lu bytes\n", __func__, nbytes);
	return 0;
}

__be32 * xdr_inline_decode(struct xdr_stream *xdr, size_t nbytes)
{
        __be32 *p;

        if (nbytes == 0)
                return xdr->p;
        if (xdr->p == xdr->end && !xdr_set_next_buffer(xdr))
                return NULL;
        p = __xdr_inline_decode(xdr, nbytes);
        if (p != NULL)
                return p;
        return xdr_copy_to_scratch(xdr, nbytes);
}



int main(int argc, char *argv[]) {
	char buf[1000];
	char *p = buf;
	struct xdr_stream *xdr;
	int len = (1<<31) + 1;

	size_t foo;

//	struct nfs_entry e, *entry;

//	entry = &e;
//	entry->len = -1;

	xdr = (struct xdr_stream *)p;
	xdr->p = 0;
	xdr->end = xdr->p + 4096;

	__be32 *ret;

	ret = xdr_inline_decode(xdr, len);
	printf("ret = %ls\n", ret);


	printf("size_t is %ld bytes\n", sizeof(foo));
	printf("len = %d (%x)\n", len, len);
	foo = len;
	printf("foo = %lu (%lx)\n", foo, foo);




	return EXIT_SUCCESS;
}

