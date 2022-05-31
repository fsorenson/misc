#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef unsigned char __u8;

#define __packed __attribute__((packed))

// kernel/fs/smbfs_common/smb2pdu.h
struct smb2_hdr {
        __le32 ProtocolId;      /* 0xFE 'S' 'M' 'B' */
        __le16 StructureSize;   /* 64 */
        __le16 CreditCharge;    /* MBZ */
        __le32 Status;          /* Error from server */
        __le16 Command;
        __le16 CreditRequest;   /* CreditResponse */
        __le32 Flags;
        __le32 NextCommand;
        __le64 MessageId;
        union {
                struct {
                        __le32 ProcessId;
                        __le32  TreeId;
                } __packed SyncId;
                __le64  AsyncId;
        } __packed Id;
        __le64  SessionId;
        __u8   Signature[16];
} __packed;

/*
 * Size of the session key (crypto key encrypted with the password
 */
#define SMB2_NTLMV2_SESSKEY_SIZE        16
#define SMB2_SIGNATURE_SIZE             16
#define SMB2_HMACSHA256_SIZE            32
#define SMB2_CMACAES_SIZE               16
//#define SMB3_GCM128_CRYPTKEY_SIZE       16
//#define SMB3_GCM256_CRYPTKEY_SIZE       32



#define max(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})
#define SESSION_KEY_LEN 16

#define SMB30_LABEL_LEN 12
#define SMB30_CONTEXT_LEN 8

#define SMB311_LABEL_LEN 14
#define SMB311_CONTEXT_LEN 64

#define SMB3_LABEL_LEN max(SMB30_LABEL_LEN, SMB311_LABEL_LEN)
#define SMB3_CONTEXT_LEN max(SMB30_CONTEXT_LEN, SMB311_CONTEXT_LEN)

#define SIGNING_KD_LEN ( 4 + SMB3_LABEL_LEN  + 1 + SMB3_CONTEXT_LEN + 4)



int hexchr2bin(const char hex, char *out) {
	if (out == NULL)
		return 0;
	if (hex >= '0' && hex <= '9')
		*out = hex - '0';
	else if (hex >= 'a' && hex <= 'f')
		*out = hex - 'a' + 10;
	else if (hex >= 'A' && hex <= 'F')
		*out = hex - 'A' + 10;
	else
		return 0;
	return 1;
}


unsigned char *dehexlify_string(char *string, uint16_t *out_len) {
	unsigned char *buf = NULL;
	int len = strlen(string), i, j;

	if (len % 1) {
		printf("error: invalid hex string to decode (odd number of hex digits: %d)\n\t%s\n",
			len, string);
		goto out;
	}

	buf = malloc(len);
	memset(buf, 0, len);

	for (i = 0 , j = 0 ; i < len ; ) {
		char b1, b2;
		hexchr2bin(string[i++], &b1);
		if (i >= len) {
			printf("error: invalid hex string to decode (ran out of bytes))\n\t%s\n",
				string);
			goto out;
		}
		hexchr2bin(string[i++], &b2);

		buf[j++] = (b1 << 4) | b2;
		while (i < len && (string[i] == ':' || string[i] == ' '))
			i++;
	}
out:
	if (buf && j && j < len) {
		unsigned char *tmp = malloc(j);
		memcpy(tmp, buf, j);
		free(buf);
		buf = tmp;
	}
	*out_len = j;
	return buf;
}
void printhex(const uint8_t *buf, uint16_t len) {
	int i;
	for (i = 0 ; i < len ; i++)
		printf("%02x", buf[i] & 0xff);
}

#if 0
#define _DATA_BYTE_CONST(data, pos) \
    ((uint8_t)(((const uint8_t *)(data))[(pos)]))

#define _DATA_BYTE(data, pos) \
    (((uint8_t *)(data))[(pos)])

#define PUSH_LE_U8(data, pos, val) \
    (_DATA_BYTE(data, pos) = ((uint8_t)(val)))
#define PUSH_LE_I8(data, pos, val) \
    PUSH_LE_U8(data, pos, val)

#define PUSH_LE_U16(data, pos, val) \
    (PUSH_LE_U8((data), (pos), (uint8_t)((uint16_t)(val) & 0xff)), PUSH_LE_U8((data), (pos) + 1, (uint8_t)((uint16_t)(val) >> 8)))
#define PUSH_LE_I16(data, pos, val) \
    PUSH_LE_U16(data, pos, val)

#define PUSH_LE_U32(data, pos, val) \
    (PUSH_LE_U16((data), (pos), (uint16_t)((uint32_t)(val) & 0xffff)), PUSH_LE_U16((data), (pos) + 2, (uint16_t)((uint32_t)(val) >> 16)))
#define PUSH_LE_I32(data, pos, val) \
    PUSH_LE_U32(data, pos, val)

#define PUSH_LE_U64(data, pos, val) \
    (PUSH_LE_U32((data), (pos), (uint32_t)((uint64_t)(val) & 0xffffffff)), PUSH_LE_U32((data), (pos) + 4, (uint32_t)((uint64_t)(val) >> 32)))
#define PUSH_LE_I64(data, pos, val) \
    PUSH_LE_U64(data, pos, val)

//#define SVAL(buf,pos) (uint32_t)PULL_LE_U16(buf, pos)
//#define IVAL(buf,pos) PULL_LE_U32(buf, pos)
//#define SSVALX(buf,pos,val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
//#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
//#define SVALS(buf,pos) ((int16_t)SVAL(buf,pos))
//#define IVALS(buf,pos) ((int32_t)IVAL(buf,pos))
//#define SSVAL(buf,pos,val) PUSH_LE_U16(buf, pos, val)
//#define SIVAL(buf,pos,val) PUSH_LE_U32(buf, pos, val)
//#define SSVALS(buf,pos,val) PUSH_LE_U16(buf, pos, val)
//#define SIVALS(buf,pos,val) PUSH_LE_U32(buf, pos, val)
#endif


/*
    9. If Connection.Dialect belongs to the SMB 3.x dialect family and SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request, the server MUST generate Channel.SigningKey by providing the following input values:
        ◦ The session key returned by the authentication protocol (in step 7) as the key derivation key.

        ◦ If Connection.Dialect is "3.1.1", the case-sensitive ASCII string "SMBSigningKey" as the label; otherwise, the case-sensitive ASCII string "SMB2AESCMAC" as the label.

        ◦ The label buffer size in bytes, including the terminating null character. The size of "SMBSigningKey" is 14. The size of "SMB2AESCMAC" is 12.

        ◦ If Connection.Dialect is "3.1.1", PreauthSessionTable.Session.PreauthIntegrityHashValue as the context; otherwise, the case-sensitive ASCII string "SmbSign" as context for the algorithm.

        ◦ The context buffer size in bytes. If Connection.Dialect is "3.1.1", the size of PreauthSessionTable.Session.PreauthIntegrityHashValue. Otherwise, the size of "SmbSign", including the terminating null character, is 8.
	Otherwise, if Connection.Dialect belongs to the SMB 3.x dialect family and SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request, the server MUST set Channel.SigningKey as Session.SigningKey.
*/

/*

    session key is the KDK (key derivation key)
    label and label size
	3.1.1 - case-sensitive string 'SMBSigningKey' as 'label'; label size is 14
	3.0+  - case-sensitive string 'SMB2AESCMAC'; label size is 12
    context and context size
	3.1.1 - PreauthSessionTable.Session.PreauthIntegrityHashValue; size is size of PreauthIntegrityHashValue
	3.0+  - case-sensitive string 'SmbSign'; size is 8
*/


#if 0

struct kvec {
	void *addr;
	size_t len;
};


typedef enum dialect {
	dialect_V30 = 0,
	dialect_V311 = 1,
};


int generate_key(
	struct kvec sess_key,
	struct kvec label,
	struct kvec ctx,
	struct kvec *key) {

	unsigned char zero = 0x0;
	uint8_t i[4] = { 0, 0, 0, 1};
	uint8_t L[4] = { 0, 0, 0, 128};

	uint8_t prfhash[SMB2_HMACSHA256_SIZE];
	uint8_t *hashptr = prfhash;

	memset(prfhash, 0, SMB2_HMACSHA256_SIZE);
	memset(key->addr, 0, key->len);

smb3_crypto_shash_allocate()

//crypto_shash_setkey(secmech.hmacsha256, ses->auth_key.response, SMB2_NTLMV2_SESSKEY_SIZE)
crypto_shash_setkey(secmech.hmacsha256, sess_key.addr, sess_key.len);

crypto_shash_init(secmech.sdeschmacsha256->shash);

rc = crypto_shash_update(&server->secmech.sdeschmacsha256->shash, i, 4);
crypto_shash_update(secmech.sdeschmacsha256->shash, label.addr, label.len);
crypto_shash_update(secmech.sdeschmacsha256->shash, &zero, 1);
crypto_shash_update(secmech.sdeschmacsha256->shash, ctx->addr, ctx->len);
crypto_shash_update(secmech.sdeschmacsha256->shash, L, 4);
crypto_shash_final(secmech.sdeschmacsha256->shash, hashptr)

}

int generate_signing_key_smb30(struct keygen_info *key_info, struct kvec *sign_key) {
	key_info->label.addr = "SMB2AESCMAC";
	key_info->label.len = 12;
	key_info->ctx.addr = "SmbSign";
	key_info->ctx.len = 8;
}
int generate_signing_key_smb311(struct keygen_info *key_info, struct kvec *sign_key) {

}

int generate_signing_key_smb3(enum dialect dialect, struct keygen_info *key_info, struct kvec *sign_key) {
	if (dialect == dialect_V311)
		return generate_signing_key_smb311(key_info,sign_key);
	else if (dialect == dialect_V30)
		return generate_signing_key_smb30(key_info,sign_key);;
	printf("error: bad dialect: %d\n", dialect);
	exit(EXIT_FAILURE);
}
#endif


int try1() {
//	uint8_t calc_md5_mac[16];
//        uint8_t *server_sent_mac;
//        uint8_t sequence_buf[8];

//	gnutls_hash_hd_t hash_hnd;

	char expected_signing_key_str[] = "4730de07b166eded4498e5b9b915f37e";
	uint16_t expected_signing_key_len = 0;
	unsigned char *expected_signing_key_bytes = dehexlify_string(expected_signing_key_str, &expected_signing_key_len);

//	int rc, i;
	int rc;

	char sig_str[] = "8d2e7f6d76078b7bd9a6029a25d620dd";
//	uint16_t sig_len = 0;
//	unsigned char *sig_bytes = dehexlify_string(sig_str, &sig_len);

	char msg_str0[] = "fe534d424000010000000000030040000800000000000000030000000000000079980000000000004c2b9d1d000000008d2e7f6d76078b7bd9a6029a25d620dd09000000480014005c005c0076006d0038005c0049005000430024000000";
	uint16_t msg_len0 = 0;
	unsigned char *msg_bytes0 = dehexlify_string(msg_str0, &msg_len0);

	uint8_t digest0[gnutls_hash_get_len(GNUTLS_MAC_AES_CMAC_128)];



	printf("message: ");
	printhex(msg_bytes0, msg_len0);
	printf("\n");

	unsigned char test_sig[16];
	memcpy(test_sig, msg_bytes0 + 0x30, 16);
	memset(msg_bytes0 + 0x30, 0, 16);

/*
	if ((rc = gnutls_hmac_fast(GNUTLS_MAC_SHA256, skey_bytes, skey_len, msg_bytes0, msg_len0, digest0)) < 0) {
		printf("error with gnutls_hmac_fast: %m\n");
		return EXIT_FAILURE;
	}
*/
	if ((rc = gnutls_hmac_fast(GNUTLS_MAC_AES_CMAC_128, expected_signing_key_bytes, expected_signing_key_len, msg_bytes0, msg_len0, digest0)) < 0) {
		printf("error with gnutls_hmac_fast: %m\n");
		return EXIT_FAILURE;
	}

	printf("message: ");
	printhex(msg_bytes0, msg_len0);
	printf("\n");

	printf("expected sig:    %s\n", sig_str);
	printf("expected sig:    ");
	printhex(test_sig, 16);
	printf("\n");

	printf("calculated sig:  ");
	printhex(digest0, 16);
	printf("\n");

	if (!memcmp(digest0, test_sig, 16))
		printf("match\n");
	else
		printf("not a match\n");

	return EXIT_SUCCESS;
}

typedef struct {
	char *str;
	unsigned char *bytes;
	uint16_t len;
} data_blob;


int main(int argc, char *argv[]) {

#define DEFINE_BLOB0(name, val) \
	data_blob name; \
	name.str = strdup(val); \
	name.len = strlen(name.str); \
	name.bytes = dehexlify_string(name.str, &name.len)
#define DEFINE_BLOB1(name, val) \
	data_blob name = { \
		.str = strdup(val), \
	}; \
	name.bytes = dehexlify_string(val, &name.len)

#define DEFINE_BLOB(name, val) DEFINE_BLOB1(name, val)



// ntlmssp.sessionkey


/*
	status = smb2_key_derivation(channel_key, sizeof(channel_key),
	d->label.data, d->label.length,
	d->context.data, d->context.length,
	session->smb2_channel.signing_key->blob.data,
	session->smb2_channel.signing_key->blob.length);

	NTSTATUS smb2_key_derivation(const uint8_t *KI, size_t KI_len,
		const uint8_t *Label, size_t Label_len,
		const uint8_t *Context, size_t Context_len,
		uint8_t *KO, size_t KO_len)
*/




printf("****************************************\n");

data_blob label_v30 = {
	.str = "SMB2AESCMAC",
	.bytes = (unsigned char *)"SMB2AESCMAC\\0",
	.len = 12, // per spec
};
data_blob context_v30 = {
	.str = "SmbSign",
	.bytes = (unsigned char *)"SmbSign\\0",
	.len = 8, // per spec
};

#define SMBSIGNINGKEY "SMBSigningKey\0\0"
data_blob label_v311 = {
	.str = "SMBSigningKey",
	.bytes = (unsigned char *)SMBSIGNINGKEY,
	.len = 14, // per spec
};

data_blob context_v311 = {
//	.str = "
	.len = 64,
}; // context is the preauth_sha_hash


/* trying to generate signing key */
int generate_key(data_blob *session_key, data_blob *label, data_blob *context, uint8_t *key, uint16_t key_size) {

	const size_t digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	uint8_t digest[digest_len];

//	unsigned char zero = 0x0;
	uint8_t i[4] = { 0, 0, 0, 1 }, L[4] = { 0, 0, 0, 128 }, zero = 0x0;
	int rc;
	int hashed_len = 0;

//printf("generate_key called with key size of %d\n", key_size);

//	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	gnutls_hmac_hd_t hmac_hnd = NULL;

//		GNUTLS_MAC_SHA256,
	if ((rc = gnutls_hmac_init(&hmac_hnd,
		GNUTLS_MAC_SHA256,
		session_key->bytes, /* session key */
		session_key->len)) < 0) {

		printf("error with gnutls_hmac_init: %m\n");
		return EXIT_FAILURE;
	}

	if ((rc = gnutls_hmac(hmac_hnd, i, 4)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	hashed_len += 4;

//	printf("hashing label: %s of length %d\n", label->bytes, label->len);
	if ((rc = gnutls_hmac(hmac_hnd, label->bytes, label->len)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	hashed_len += label->len;

	if ((rc = gnutls_hmac(hmac_hnd, &zero, 1)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	hashed_len += 1;

	// smb2.preauth_hash
	if ((rc = gnutls_hmac(hmac_hnd, context->bytes, context->len)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	hashed_len += context->len;
	// set to L, whatever that means
//	memset(buf, 0, 128);
//	buf[3] = 128;
//	if ((rc = (gnutls_hmac(hmac_hnd, buf, sizeof(buf)))) < 0) {


//printf("key size: %d\n", key_size);
//fflush(stdout);

	if ((rc = gnutls_hmac(hmac_hnd, L, 4))< 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	hashed_len += 4;

	gnutls_hmac_deinit(hmac_hnd, digest);

printf("in generate_key, hashed %d bytes\n", hashed_len);
	memcpy(key, digest, key_size);
	return 0;
}


/* trying to generate signing key */
int generate_key_v2(data_blob *session_key, data_blob *label, data_blob *context, data_blob *key) {
printf("expected signing key len: %d\n", SIGNING_KD_LEN);

	const size_t digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	uint8_t digest[digest_len];

	data_blob kd_bytes; // bytes to hash for key derivation
	kd_bytes.bytes = malloc(SIGNING_KD_LEN);
	kd_bytes.len = SIGNING_KD_LEN;
	int hashed_len = 0;

	uint8_t i[4] = { 0, 0, 0, 1 }, L[4] = { 0, 0, 0, 128 }, zero = 0x0;
	int rc;

//printf("generate_key called with key size of %d\n", key_size);

	memset(kd_bytes.bytes, 0, kd_bytes.len);
	memset(key->bytes, 0, key->len);

	gnutls_hmac_hd_t hmac_hnd = NULL;


//		GNUTLS_MAC_SHA256,
	if ((rc = gnutls_hmac_init(&hmac_hnd,
		GNUTLS_MAC_SHA256,
		session_key->bytes, /* session key */
		session_key->len)) < 0) {

		printf("error with gnutls_hmac_init: %m\n");
		return EXIT_FAILURE;
	}


	if ((rc = gnutls_hmac(hmac_hnd, i, 4)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}

	hashed_len += 3; // already zeroed
	kd_bytes.bytes[hashed_len++] = 1; // i

//	printf("hashing label: %s of length %d\n", label->bytes, label->len);
	if ((rc = gnutls_hmac(hmac_hnd, label->bytes, label->len)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}

	memcpy(kd_bytes.bytes + hashed_len, label->bytes, label->len);
	hashed_len += label->len;

	if ((rc = gnutls_hmac(hmac_hnd, &zero, 1)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
//	kd_bytes.bytes[hashed_len++] = 0; // already zeroed
	hashed_len += 1; // 'zero'

	// smb2.preauth_hash
	if ((rc = gnutls_hmac(hmac_hnd, context->bytes, context->len)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}
	memcpy(kd_bytes.bytes + hashed_len, context->bytes, context->len);
	hashed_len += context->len;

	// set to L, whatever that means
//	memset(buf, 0, 128);
//	buf[3] = 128;
//	if ((rc = (gnutls_hmac(hmac_hnd, buf, sizeof(buf)))) < 0) {

	if ((rc = gnutls_hmac(hmac_hnd, L, 4))< 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}

	hashed_len += 3; // already zeroed
	kd_bytes.bytes[hashed_len++] = 128;

	gnutls_hmac_deinit(hmac_hnd, digest);

printf("in generate_key, hashed %d bytes\n", hashed_len);
	memcpy(key->bytes, digest, key->len);



	return 0;
}
/* trying to generate signing key */
int generate_key_v3(data_blob *session_key, data_blob *label, data_blob *context, data_blob *key) {
printf("expected signing key len: %d\n", SIGNING_KD_LEN);

	const size_t digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	uint8_t digest[digest_len];

	data_blob kd_bytes; // bytes to hash for key derivation
	kd_bytes.bytes = malloc(SIGNING_KD_LEN);
	kd_bytes.len = SIGNING_KD_LEN;
	int hashed_len = 0;

//	uint8_t i[4] = { 0, 0, 0, 1 }, L[4] = { 0, 0, 0, 128 }, zero = 0x0;
	int rc;

//printf("generate_key called with key size of %d\n", key_size);

	memset(kd_bytes.bytes, 0, kd_bytes.len);
	memset(key->bytes, 0, key->len);

	gnutls_hmac_hd_t hmac_hnd = NULL;

//		GNUTLS_MAC_SHA256,
	if ((rc = gnutls_hmac_init(&hmac_hnd,
		GNUTLS_MAC_SHA256,
		session_key->bytes, /* session key */
		session_key->len)) < 0) {

		printf("error with gnutls_hmac_init: %m\n");
		return EXIT_FAILURE;
	}

	hashed_len += 3; // already zeroed
	kd_bytes.bytes[hashed_len++] = 1; // i

	memcpy(kd_bytes.bytes + hashed_len, label->bytes, label->len);
	hashed_len += label->len;

	hashed_len += 1; // 'zero'

	memcpy(kd_bytes.bytes + hashed_len, context->bytes, context->len);
	hashed_len += context->len;

	hashed_len += 3; // already zeroed
	kd_bytes.bytes[hashed_len++] = 128; // L

	if ((rc = gnutls_hmac(hmac_hnd, kd_bytes.bytes, kd_bytes.len)) < 0) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}

	gnutls_hmac_deinit(hmac_hnd, digest);

printf("in generate_key, hashed %d bytes\n", hashed_len);
	memcpy(key->bytes, digest, key->len);

	return 0;
}


DEFINE_BLOB(sess_key, "af e3 85 39 18 13 49 a7 f9 c0 cb 50 5b 37 ce c3"); // from stap
//DEFINE_BLOB(sess_key, "f9:30:8f:38:c2:f1:63:7c:e5:44:28:3a:10:7a:42:ae"); // from pcap
DEFINE_BLOB(preauth_hash, "06108c92a9e74c104bae71905d79fb804cfd2cf80d469bba04a1eb9f2ff15d316a0e50b533da4e522a382f1cf216c0604675233bad1958fcd7b5f5bc4be17b84");
DEFINE_BLOB(expected_signing_key, "11 3c eb b9 9e 78 03 2f ff f5 c6 b6 d5 ca 36 11"); // expected signing key

/*
    ses->server->session_key.response: 
    ses->preauth_sha_hash: 06108c92a9e74c104bae71905d79fb804cfd2cf80d469bba04a1eb9f2ff15d316a0e50b533da4e522a382f1cf216c0604675233bad1958fcd7b5f5bc4be17b84
    ses->server->session_key.response: 
    ses->auth_key.response af e3 85 39 18 13 49 a7 f9 c0 cb 50 5b 37 ce c3
    ses->binding: 0
    smb3signingkey: 11 3c eb b9 9e 78 03 2f ff f5 c6 b6 d5 ca 36 11
    ses->chans[0].signkey: 11 3c eb b9 9e 78 03 2f ff f5 c6 b6 d5 ca 36 11
    ses->smb3encryptionkey: 3a 6f 95 89 98 44 bf d8 f1 31 f6 6f 60 0b 68 f1
    ses->smb3encrdetionkey: 50 08 92 b5 bb 36 d2 0d fd aa 55 d3 8d f5 92 b1

    pcap session key
11  0.069964716 192.168.122.99 → 192.168.122.98 SMB2 422 Session Setup Request, NTLMSSP_AUTH, User: \user1 
    ntlmssp.auth.sesskey == f9:30:8f:38:c2:f1:63:7c:e5:44:28:3a:10:7a:42:ae
       smb2.preauth_hash == 06:10:8c:92:a9:e7:4c:10:4b:ae:71:90:5d:79:fb:80:4c:fd:2c:f8:0d:46:9b:ba:04:a1:eb:9f:2f:f1:5d:31:6a:0e:50:b5:33:da:4e:52:2a:38:2f:1c:f2:16:c0:60:46:75:23:3b:ad:19:58:fc:d7:b5:f5:bc:4b:e1:7b:84
              smb2.sesid == 0x000000002663c587
*/


/*
If Connection.Dialect belongs to the SMB 3.x dialect family, the client MUST generate Session.SigningKey, as specified in section 3.1.4.2, and pass the following inputs:
  Session.SessionKey as the key derivation key.
  If Connection.Dialect is "3.1.1", the case-sensitive ASCII string "SMBSigningKey" as the label; otherwise, the case-sensitive ASCII string "SMB2AESCMAC" as the label.
  The label buffer size in bytes, including the terminating null character. The size of "SMBSigningKey" is 14. The size of "SMB2AESCMAC" is 12.
  If Connection.Dialect is "3.1.1", Session.PreauthIntegrityHashValue as the context;
   otherwise, the case-sensitive ASCII string "SmbSign" as context for the algorithm.
  The context buffer size in bytes.
   If Connection.Dialect is "3.1.1", the size of Session.PreauthIntegrityHashValue.
   Otherwise, the size of "SmbSign", including the terminating null character, is 8.


3.1.4.2
the Key Derivation specification in [SP800-108] is used with the following inputs:
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf


The cryptographic keys MUST be generated using the KDF algorithm in Counter Mode, as specified in [SP800-108] section 5.1, with the following values:
  'r' value initialized to 32.
  If Connection.CipherId is AES-128-CCM or AES-128-GCM, 'L' value is initialized to 128. If Connection.CipherId is AES-256-CCM or AES-256-GCM, ‘L’ value is initialized to 256.
  The PRF used in the key derivation MUST be HMAC-SHA256.

GNUTLS_MAC_AES_CMAC_128

*/

// label is SMBSigningKey\0 - length 14
// context is preauth hash - length 64
DEFINE_BLOB(single_blob,
			"00 00 00 01" // i - whatever that is
			"53 4d 42 53 69 67 6e 69 6e 67 4b 65 79 00"  // SMBSigningKey\0 as 'label' - length 14
//                        "00 00 00 00" // zero?
                        "00" // zero?
                        "06108c92a9e74c104bae71905d79fb804cfd2cf80d469bba04a1eb9f2ff15d316a0e50b533da4e522a382f1cf216c0604675233bad1958fcd7b5f5bc4be17b84" // preauth_hash as 'context'
			"00 00 00 80" // L - bits inm the key
);
// generate_key signing.label, signing.context

//generate_smb30signingkey
//signing label - SMB2AESCMAC - 12
//signing context - SmbSign - 8
//generate_smb3signingkey()

//generate_smb311signingkey
//signing label - SMBSigningKey - 14
//signing context - preauth_sha_hash - 64
//generate_smb3signingkey()






printf("preauth hash: ");
printhex(preauth_hash.bytes, preauth_hash.len);
printf("\n");

printf("session key: ");
printhex(sess_key.bytes, sess_key.len);
printf("\n");

/*
        status = smb2_signing_key_sign_create(x->global->channels,
                                              c->signing_algo,
                                              &session_info->session_key,
                                              derivations.signing,
                                              &c->signing_key);
*/

/*
static NTSTATUS smb2_signing_key_create(TALLOC_CTX *mem_ctx,
                                        uint16_t sign_algo_id,
                                        uint16_t cipher_algo_id,
                                        const DATA_BLOB *master_key,
                                        const struct smb2_signing_derivation *d,
                                        struct smb2_signing_key **_key)

smb2_signing_key_create

*/

// generate_smb30signingkey
// generate_smb311signingkey
//  both call generate_smb3signingkey

// generate_smb3signingkey calls
//   generate_key(ses, ptriplet->signing.label,
//   		ptriplet->signing.context,
//   		signkey
//   		SMB3_SIGN_KEY_SIZE


if (0) {
#if 0
// passed into the function:
//  channel_key is session_key
//  K0_len
uint32_t KO_len = 16;

uint32_t L = KO_len * 8;
uint8_t *KI = sess_key.bytes;
size_t KI_len = sess_key.len;
static const uint8_t zero = 0;

//const size_t digest2_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
const size_t digest2_len = gnutls_hash_get_len(hmac_algo);

//uint8_t digest2[gnutls_hash_get_len(hmac_algo)];
uint8_t digest2[digest2_len];
//int rc;



// try to work out signing key from session key, etc.
if ((rc = gnutls_hmac_init(&hmac_hnd,
	GNUTLS_MAC_SHA256,
	KI, /* session key */
	KI_len)) < 0) {
		printf("error with gnutls_hmac_init: %m\n");
		return EXIT_FAILURE;
	}


if ((rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf))) < 0) {
	printf("error with gnutls_hmac: %m\n");
	return EXIT_FAILURE;
}

//if ((rc = gnutls_hmac(hmac_hnd, label.bytes, label.len)) < 0) {
if ((rc = gnutls_hmac(hmac_hnd, label_v311.bytes, label_v311.len)) < 0) {
	printf("error with gnutls_hmac: %m\n");
	return EXIT_FAILURE;
}

if ((rc = gnutls_hmac(hmac_hnd, &zero, 1)) < 0) {
	printf("error with gnutls_hmac: %m\n");
	return EXIT_FAILURE;
}

// smb2.preauth_hash
if ((rc = gnutls_hmac(hmac_hnd, preauth_hash.bytes, preauth_hash.len)) < 0) {
	printf("error with gnutls_hmac: %m\n");
	return EXIT_FAILURE;
}
// set to L, whatever that means
memset(buf, 0, 4);
buf[3] = 128;
if ((rc = (gnutls_hmac(hmac_hnd, buf, sizeof(buf)))) < 0) {
	printf("error with gnutls_hmac: %m\n");
	return EXIT_FAILURE;
}
gnutls_hmac_deinit(hmac_hnd, digest2);

printf("calculated signing key: ");
printhex(digest2, 16);
printf("\n");
printf("expected signing key:   ");
printhex(expected_signing_key.bytes, 16);
printf("\n");
#endif
}



{
	printf("expected signing key: ");
	printhex(expected_signing_key.bytes, expected_signing_key.len);
	printf("\n");
#if 0
	uint8_t key2[16];

	generate_key(&sess_key, &label_v311, &preauth_hash, key2, sizeof(key2));

	printf("another?:             ");
	printhex(key2, 16);
#else
	data_blob key;
	key.len = 16;
	key.bytes = malloc(key.len);

	generate_key_v3(&sess_key, &label_v311, &preauth_hash, &key);
	printf("another?:             ");
	printhex(key.bytes, key.len);
#endif
	printf("\n");
}



if (42) {
	const size_t digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	uint8_t digest[digest_len];
	int rc;
	gnutls_hmac_hd_t hmac_hnd = NULL;


printf("single_blob length: %d\n", single_blob.len);

	if ((rc = gnutls_hmac_init(&hmac_hnd,
		GNUTLS_MAC_SHA256,
		sess_key.bytes, /* session key */
		sess_key.len)) < 0) {

		printf("error with gnutls_hmac_init: %m\n");
                return EXIT_FAILURE;
        }

	if ((rc = gnutls_hmac(hmac_hnd, single_blob.bytes, single_blob.len))) {
		printf("error with gnutls_hmac: %m\n");
		return EXIT_FAILURE;
	}

	gnutls_hmac_deinit(hmac_hnd, digest);
	printf("how about: ");
	printhex(digest, 16);
	printf("\n");
}

	return EXIT_SUCCESS;
}

