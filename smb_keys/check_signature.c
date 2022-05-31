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
#define SMB3_GCM128_CRYPTKEY_SIZE       16
#define SMB3_GCM256_CRYPTKEY_SIZE       32

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


unsigned char *dehexlify_string(char *string) {
	unsigned char *buf = NULL;
	int len = strlen(string), i;

	if (len % 1) {
		printf("error: invalid hex string to decode (odd number of hex digits: %d)\n\t%s\n",
			len, string);
		goto out;
	}
	len /= 2;
	buf = malloc(len);
	//      memset(buf, 0, len);
	memset(buf, 'A', len); // why 'A' ?

	for (i = 0 ; i < len ; i++) {
		char b1, b2;
		hexchr2bin(string[i*2], &b1);
		hexchr2bin(string[i*2 + 1], &b2);
		buf[i] = (b1 << 4) | b2;
	}
out:
	return buf;
}


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

#define SVAL(buf,pos) (uint32_t)PULL_LE_U16(buf, pos)
#define IVAL(buf,pos) PULL_LE_U32(buf, pos)
#define SSVALX(buf,pos,val) (CVAL_NC(buf,pos)=(uint8_t)((val)&0xFF),CVAL_NC(buf,pos+1)=(uint8_t)((val)>>8))
#define SIVALX(buf,pos,val) (SSVALX(buf,pos,val&0xFFFF),SSVALX(buf,pos+2,val>>16))
#define SVALS(buf,pos) ((int16_t)SVAL(buf,pos))
#define IVALS(buf,pos) ((int32_t)IVAL(buf,pos))
#define SSVAL(buf,pos,val) PUSH_LE_U16(buf, pos, val)
#define SIVAL(buf,pos,val) PUSH_LE_U32(buf, pos, val)
#define SSVALS(buf,pos,val) PUSH_LE_U16(buf, pos, val)
#define SIVALS(buf,pos,val) PUSH_LE_U32(buf, pos, val)


#define HDR_COM 4
#define HDR_RCLS 5
#define HDR_REH 6
#define HDR_ERR 7
#define HDR_FLG 9
#define HDR_FLG2 10
#define HDR_PIDHIGH 12
#define HDR_SS_FIELD 14
#define HDR_TID 24
#define HDR_PID 26
#define HDR_UID 28
#define HDR_MID 30
#define HDR_WCT 32
#define HDR_VWV 33

int main(int argc, char *argv[]) {
	uint8_t calc_md5_mac[16];
        uint8_t *server_sent_mac;
        uint8_t sequence_buf[8];

	gnutls_hash_hd_t hash_hnd;
	char server_salt_str[] = "63d486dee8d55660dd9bbfdb330424e2b99fab80f1eb7bc1d2b70c34972ce9a3";

	uint16_t seq_num = 0;

	char salt_str[] = "c7f255d16bd120c57be0b0d7220967886b9c95449c8a52e6584ec2cd29fcd822";
	unsigned char *salt = dehexlify_string(salt_str);
	uint16_t salt_len = strlen(salt_str)/2;
	printf("salt_length: %d\n", salt_len);
	int rc, i;

	const int sign_range = 0;
	for (i = 0 - sign_range ; i <= 0 + sign_range ; i++) {
		SIVAL(sequence_buf, 0, seq_num + i);
		SIVAL(sequence_buf, 4, 0);


//	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5
		rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA512);


//	Negotiate Protocol
//	client->server request
//	Negotiate Context: SMB2_PREAUTH_INTEGRITY_CAPABILITIES 
//		Type: SMB2_PREAUTH_INTEGRITY_CAPABILITIES (0x0001)
//		DataLength: 38
//		Reserved: 00000000
//		HashAlgorithmCount: 1
//		SaltLength: 32
//		HashAlgorithm: SHA-512 (0x0001)
//		Salt: c7f255d16bd120c57be0b0d7220967886b9c95449c8a52e6584ec2cd29fcd822

//	server->client response
//	Negotiate Context: SMB2_PREAUTH_INTEGRITY_CAPABILITIES 
//		Type: SMB2_PREAUTH_INTEGRITY_CAPABILITIES (0x0001)
//		DataLength: 38
//		Reserved: 00000000
//		HashAlgorithmCount: 1
//		SaltLength: 32
//		HashAlgorithm: SHA-512 (0x0001)
//		Salt: 63d486dee8d55660dd9bbfdb330424e2b99fab80f1eb7bc1d2b70c34972ce9a3


// first signed message is Session Setup Response (frame 27?)
//
// smb2 message fe534d424000010000000000030040000800000000000000030000000000000029360000000000009d15c426000000007031dff78143a747f09f42a60bdeb85509000000480014005c005c0076006d0039005c0049005000430024000000
// smb2 header fe534d424000010000000000030040000800000000000000030000000000000029360000000000009d15c426000000007031dff78143a747f09f42a60bdeb855
// smb2 tree connect request 09000000480014005c005c0076006d0039005c004900500043002400
// filler 00 00

		char smb2_hdr_str[] = "fe534d424000010000000000030040000800000000000000030000000000000029360000000000009d15c426000000007031dff78143a747f09f42a60bdeb855";
		unsigned char *smb2_hdr_bytes = dehexlify_string(smb2_hdr_str);
		uint16_t smb2_hdr_len = strlen(smb2_hdr_str)/2;

		printf("header length: %d\n", smb2_hdr_len);


		char request_str[] = "09000000480014005c005c0076006d0039005c004900500043002400";
		unsigned char *request_bytes = dehexlify_string(request_str);
		uint16_t request_len = strlen(request_str)/2;
		printf("request length: %d\n", request_len);

		char filler_str[] = "0000";
		unsigned char *filler_bytes = dehexlify_string(filler_str);
		uint16_t filler_len = strlen(filler_str)/2;
		printf("filler length: %d\n", filler_len);


/*
		rc = gnutls_hash(hash_hnd, salt, salt_len);

		gnutls_hash(hash_hnd, smb2_hdr_bytes, 
		gnutls_hash(hash_hnd, sequence_buf, sizeof(sequence_buf));
		gnutls_hash(hash_hnd, 
*/



	}



//        uint8_t digest[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];
	printf("gnutls_hash_get_len(GNUTLS_MAC_SHA256) = %d\n", gnutls_hash_get_len(GNUTLS_MAC_SHA256));





/*
Frame 25 - Session Setup Response
tcp length: 76, nbss.length: 72, smb2.header_len: 64
  trim length: 4
        msg_id 2
                smb2.signature 50899e0324b487c52565a4de8ee9d23a
  payload len: 72
  payload: fe534d424000000000000000010082000900000000000000020000000000000029360000000000009d15c4260000000050899e0324b487c52565a4de8ee9d23a0900000048000000
length of smb payload: 72
session id: 9d15c42600000000
new message is 72 bytes: fe534d424000000000000000010082000900000000000000020000000000000029360000000000009d15c42600000000000000000000000000000000000000000900000048000000
*/
	printf("frame 25\n");

	char sig_str[] = "50899e0324b487c52565a4de8ee9d23a";
	unsigned char *sig_bytes = dehexlify_string(sig_str);
	uint16_t sig_len = strlen(sig_str)/2;

//	char full_msg[] = "00000048fe534d424000000000000000010082000900000000000000020000000000000029360000000000009d15c4260000000050899e0324b487c52565a4de8ee9d23a0900000048000000"
	char msg_str0[] = "00000048fe534d424000000000000000010082000900000000000000020000000000000029360000000000009d15c4260000000050899e0324b487c52565a4de8ee9d23a0900000048000000";
	char msg_str1[] = "fe534d424000000000000000010082000900000000000000020000000000000029360000000000009d15c42600000000000000000000000000000000000000000900000048000000";


	unsigned char *msg_bytes0 = dehexlify_string(msg_str0);
	uint16_t msg_len0 = strlen(msg_str0)/2;
	unsigned char *msg_bytes1 = dehexlify_string(msg_str1);
	uint16_t msg_len1 = strlen(msg_str1)/2;


	char skey_str[] = "5ea76c3d137f190eeee5c85ddffb23cd";
	unsigned char *skey_bytes = dehexlify_string(skey_str);
	uint16_t skey_len = strlen(skey_str)/2;


	uint8_t digest0[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];
	uint8_t digest1[gnutls_hash_get_len(GNUTLS_MAC_SHA256)];

/*
	if ((rc = gnutls_hmac_fast(GNUTLS_MAC_SHA256, skey_bytes, skey_len, msg_bytes0, msg_len0, digest0)) < 0) {
		printf("error with gnutls_hmac_fast: %m\n");
		return EXIT_FAILURE;
	}
*/
	if ((rc = gnutls_hmac_fast(GNUTLS_MAC_SHA256, skey_bytes, skey_len, msg_bytes1, msg_len1, digest1)) < 0) {
		printf("error with gnutls_hmac_fast: %m\n");
		return EXIT_FAILURE;
	}

	printf("expected sig:    %s\n", sig_str);

/*
	printf("calculated sig0: ");
	for (i = 0 ; i < 16 ; i++) {
		printf("%02x", digest0[i]);
	}
	printf("\n");
*/

	printf("calculated sig1: ");
	for (i = 0 ; i < 16 ; i++) {
		printf("%02x", digest1[i]);
	}
	printf("\n");

	if (!memcmp(digest1, sig_bytes, 16))
		printf("match\n");
	else
		printf("not a match\n");



uint16_t digest2[gnutls_hash_get_len(GNUTLS_MAC_AES_CMAC_128)];
if ((rc = gnutls_hmac_fast(GNUTLS_MAC_AES_CMAC_128, skey_bytes, skey_len, msg_bytes1, msg_len1, digest2)) < 0) {
                printf("error with gnutls_hmac_fast: %m\n");
                return EXIT_FAILURE;
        }
	if (!memcmp(digest2, sig_bytes, 16))
		printf("AES was match\n");
	else
		printf("AES was not a match\n");






//	char smb2_signature[SMB2_HMACSHA256_SIZE];
//	char 


typedef union {
	unsigned char byte[16];
	uint64_t val64[2];
} test_key_t;

test_key_t test_key;
memset(&test_key, 0, sizeof(test_key));
while (test_key.val64[0] != 0xffffffffffffffff && test_key.val64[1] != 0xffffffffffffffff) {

	if (test_key.val64[1] % 0x1000 == 0) {
		printf("%016" PRIx64 "%016" PRIx64 "\r", test_key.val64[0], test_key.val64[1]);
		fflush(stdout);
	}


	if ((rc = gnutls_hmac_fast(GNUTLS_MAC_SHA256, (unsigned char *)&test_key, 16, msg_bytes1, msg_len1, digest1)) < 0) {
		printf("error with gnutls_hmac_fast: %m\n");
		return EXIT_FAILURE;
	}

	if (!memcmp(digest1, sig_bytes, 16)) {
		printf("found a match with key: ");
		for (i = 0 ; i < 16 ; i++)
			printf("%02x", test_key.byte[i]);
		return EXIT_SUCCESS;
	}

	if (test_key.val64[1] == 0xffffffffffffffff)
		test_key.val64[0]++;
	test_key.val64[1]++;

}







	return EXIT_SUCCESS;
}

