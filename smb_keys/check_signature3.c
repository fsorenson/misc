#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define STR(x) #x
#define XSTR(x) STR(x)

#define max(a,b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b; \
})
#define SESSION_KEY_LEN 16
#define SIGNING_KEY_LEN 16

#define SMB30_LABEL_BYTES "SMB2AESCMAC"
#define SMB30_LABEL_LEN (sizeof(SMB30_LABEL_BYTES)) /* should be 12 */

_Static_assert(SMB30_LABEL_LEN == 12, "ERROR: " STR(SMB30_LABEL_LEN) " is not 12 bytes");


#define SMB30_CONTEXT_BYTES "SmbSign"
#define SMB30_CONTEXT_LEN (sizeof(SMB30_CONTEXT_BYTES)) /* should be 8 */
_Static_assert(SMB30_CONTEXT_LEN == 8, "ERROR: " STR(SMB30_CONTEXT_LEN) " is not 8 bytes");

#define SMB311_LABEL_BYTES "SMBSigningKey"
#define SMB311_LABEL_LEN (sizeof(SMB311_LABEL_BYTES))  /* should be 14 */
_Static_assert(SMB311_LABEL_LEN == 14, "ERROR: " STR(SMB311_LABEL_LEN) "is not 14 bytes");

#define SMB311_CONTEXT_LEN 64 /* value not determined at compile time - preauth hash */

#define SMB3_LABEL_LEN max(SMB30_LABEL_LEN, SMB311_LABEL_LEN)
#define SMB3_CONTEXT_LEN max(SMB30_CONTEXT_LEN, SMB311_CONTEXT_LEN)

#define SIGNING_KD_LEN ( 4 + SMB3_LABEL_LEN  + 1 + SMB3_CONTEXT_LEN + 4)

typedef struct {
	char *str;
	unsigned char *bytes;
	uint16_t len;
} data_blob;
#define DEFINE_BLOB(name, val) \
	data_blob name = { \
		.str = strdup(val), \
	}; \
	name.bytes = dehexlify_string(val, &name.len)

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

/*
    9. If Connection.Dialect belongs to the SMB 3.x dialect family and SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request, the server MUST generate Channel.SigningKey by providing the following input values:
        ◦ The session key returned by the authentication protocol (in step 7) as the key derivation key.


    session key is the KDK (key derivation key)
    label and label size
	3.0+  - case-sensitive string 'SMB2AESCMAC'; label size is 12
	3.1.1 - case-sensitive string 'SMBSigningKey' as 'label'; label size is 14

    context and context size
	3.0+  - case-sensitive string 'SmbSign'; size is 8
	3.1.1 - PreauthSessionTable.Session.PreauthIntegrityHashValue; size is size of PreauthIntegrityHashValue (PreauthSessionTable.Session.PreauthIntegrityHashValue)

	Otherwise, if Connection.Dialect belongs to the SMB 3.x dialect family and SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request, the server MUST set Channel.SigningKey as Session.SigningKey.
*/
// generate the signing key
int generate_key(data_blob *session_key, data_blob *label, data_blob *context, data_blob *key) {

	const size_t digest_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	uint8_t digest[digest_len];

	data_blob kd_bytes; // bytes to hash for key derivation
	kd_bytes.bytes = malloc(SIGNING_KD_LEN);
	kd_bytes.len = SIGNING_KD_LEN;
	int hashed_len = 0;
	int rc;

	memset(kd_bytes.bytes, 0, kd_bytes.len);
	memset(key->bytes, 0, key->len);

	gnutls_hmac_hd_t hmac_hnd = NULL;

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
	memcpy(key->bytes, digest, key->len);

	return 0;
}

int main(int argc, char *argv[]) {
	data_blob label_v30 = {
		.str = SMB30_LABEL_BYTES,
		.bytes = (unsigned char *)SMB30_LABEL_BYTES,
		.len = SMB30_LABEL_LEN, // per spec
	};
	data_blob context_v30 = {
		.str = SMB30_CONTEXT_BYTES,
		.bytes = (unsigned char *)SMB30_CONTEXT_BYTES,
		.len = SMB30_CONTEXT_LEN, // per spec
	};

	data_blob label_v311 = {
		.str = SMB311_LABEL_BYTES,
		.bytes = (unsigned char *)SMB311_LABEL_BYTES,
		.len = SMB311_LABEL_LEN, // per spec
	};

	data_blob context_v311 = {
	//	.str = "
		.len = SMB311_CONTEXT_LEN,
	}; // context is the preauth_sha_hash


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

*/

	printf("preauth hash: ");
	printhex(preauth_hash.bytes, preauth_hash.len);
	printf("\n");

	printf("session key: ");
	printhex(sess_key.bytes, sess_key.len);
	printf("\n");

// generate_smb30signingkey
// generate_smb311signingkey
//  both call generate_smb3signingkey

// generate_smb3signingkey calls
//   generate_key(ses, ptriplet->signing.label,
//   		ptriplet->signing.context,
//   		signkey
//   		SMB3_SIGN_KEY_SIZE


	printf("expected signing key:   ");
	printhex(expected_signing_key.bytes, expected_signing_key.len);
	printf("\n");
	data_blob key;
	key.len = SIGNING_KEY_LEN;
	key.bytes = malloc(key.len);

	generate_key(&sess_key, &label_v311, &preauth_hash, &key);
	printf("calculatec signing key: ");
	printhex(key.bytes, key.len);
	printf("\n");

	return EXIT_SUCCESS;
}

