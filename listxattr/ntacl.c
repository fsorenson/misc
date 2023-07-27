/*
	Frank Sorenson <sorenson@redhat.com>, 2022


	Display xattrs attached to a file/directory,
	and decode as many of them as possible
*/

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <acl/libacl.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <linux/fs.h>
#include <sys/vfs.h>
*/

#include "ntacl.h"


#if 0
# smbcacls -U user1 //vm1/user1 /
REVISION:1
CONTROL:SR|DP
OWNER:VM1\user1
GROUP:Unix Group\group1
ACL:Everyone:ALLOWED/0x0/READ
ACL:Everyone:ALLOWED/OI|CI|IO/READ
ACL:Creator Owner:ALLOWED/OI|CI|IO/FULL
ACL:Creator Group:ALLOWED/OI|CI|IO/READ
ACL:Unix Group\group1:ALLOWED/0x0/READ
ACL:VM1\user1:ALLOWED/0x0/FULL
ACL:VM1\user2:ALLOWED/0x0/READ

# smbcacls --numeric -U user1 //vm1/user1 /
//Enter REDHAT\user1's password: 
REVISION:1
CONTROL:0x8004
OWNER:S-1-5-21-1926775860-3195420675-2167497937-1000
GROUP:S-1-22-2-501
ACL:S-1-1-0:0/0x0/0x001200a9
ACL:S-1-1-0:0/0xb/0x001200a9
ACL:S-1-3-0:0/0xb/0x001f01ff
ACL:S-1-3-1:0/0xb/0x001200a9
ACL:S-1-22-2-501:0/0x0/0x001200a9
ACL:S-1-5-21-1926775860-3195420675-2167497937-1000:0/0x0/0x001f01ff
ACL:S-1-5-21-1926775860-3195420675-2167497937-1002:0/0x0/0x001200a9

# id user1
uid=501(user1) gid=501(group1) groups=501(group1)
$ printf %x\\n 501
1f5

# id user2
uid=502(user2) gid=502(group2) groups=502(group2)
$ printf %x\\n 502
1f6


so
OWNER:S-1-5-21-1926775860-3195420675-2167497937-1000
	owner
	S-1-5 - SECURITY_NT_AUTHORITY

GROUP:S-1-22-2-501
ACL:S-1-1-0:0/0x0/0x001200a9
	world (all users belong to)
ACL:S-1-1-0:0/0xb/0x001200a9
	
ACL:S-1-3-0:0/0xb/0x001f01ff
	S-1-3-0 - CREATOR OWNER
ACL:S-1-3-1:0/0xb/0x001200a9
	S-1-3-1 - CREATOR GROUP
ACL:S-1-22-2-501:0/0x0/0x001200a9
	
ACL:S-1-5-21-1926775860-3195420675-2167497937-1000:0/0x0/0x001f01ff
	S-1-5-21-domain accounts ?  mapped from uid 500?
ACL:S-1-5-21-1926775860-3195420675-2167497937-1002:0/0x0/0x001200a9
	S-1-5-21-domain accounts ?



https://renenyffenegger.ch/notes/Windows/security/SID/index
S-1-5-21-/... user accounts

knfsd/smbacl.c
/* S-1-22-1 Unmapped Unix users */
/* S-1-22-2 Unmapped Unix groups */

knfsd/smbacl.c quoting from http://technet.microsoft.com/en-us/library/hh509017(v=ws.10).aspx
/* S-1-5-88 MS NFS and Apple style UID/GID/mode */
/* S-1-5-88-1 Unix uid */
/* S-1-5-88-2 Unix gid */
/* S-1-5-88-3 Unix mode */



well-known sids - https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids


S-1-1-0
This example uses the string notation for SIDs in which S identifies the string as a SID, the first 1 is the revision level of the SID, and the remaining two digits are the SECURITY_WORLD_SID_AUTHORITY and SECURITY_WORLD_RID constants.



Universal well-known SID	String value	Identifies
Null SID			S-1-0-0		A group with no members. This is often used when a SID value is not known.
World				S-1-1-0		A group that includes all users.
Local				S-1-2-0		Users who log on to terminals locally (physically) connected to the system.
Creator Owner ID		S-1-3-0		A security identifier to be replaced by the security identifier of the user who created a new object. This SID is used in inheritable ACEs.
Creator Group ID		S-1-3-1		A security identifier to be replaced by the primary-group SID of the user who created a new object. Use this SID in inheritable ACEs.


Identifier authority		Value	String value
SECURITY_NULL_SID_AUTHORITY	0	S-1-0
SECURITY_WORLD_SID_AUTHORITY	1	S-1-1
SECURITY_LOCAL_SID_AUTHORITY	2	S-1-2
SECURITY_CREATOR_SID_AUTHORITY	3	S-1-3
SECURITY_NT_AUTHORITY		5	S-1-5

relative identifier authority	valuestring value
SECURITY_NULL_RID		0	S-1-0
SECURITY_WORLD_RID		0	S-1-1
SECURITY_LOCAL_RID		0	S-1-2
SECURITY_LOCAL_LOGON_RID	1	S-1-2
SECURITY_CREATOR_OWNER_RID	0	S-1-3
SECURITY_CREATOR_GROUP_RID	1	S-1-3



https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
S-1-#
WinNullSid			Value: 0	Indicates a null SID.
WinWorldSid			Value: 1	Indicates a SID that matches everyone.
WinLocalSid			Value: 2	Indicates a local SID.
WinCreatorOwnerSid		Value: 3	Indicates a SID that matches the owner or creator of an object.
WinCreatorGroupSid		Value: 4	Indicates a SID that matches the creator group of an object.
WinCreatorOwnerServerSid	Value: 5	Indicates a creator owner server SID.
WinLogonIdsSid			Value: 21	Indicates a SID that matches logon IDs.
WinLocalSystemSid		Value: 22	Indicates a SID that matches the local system.
WinLocalServiceSid		Value: 23	Indicates a SID that matches a local service.





# getfattr -d -m . -e hex /home/user1

security.NTACL=0x0400040000000200040002000100e8ba06a202b93b6f1d4fff64d9b283715221c834381578db9381abcb8b14dfaa0000000000000000000000000000000000000000000000000000000000000000706f7369785f61636c008a6f5ecccf54d801e9d5da70b55e295e5c7bcb4a5d12da2ea446ffc48c448f62f63fbebd477d8a02000000000000000000000000000000000000000000000000000000000000000001000480b4000000d000000000000000e00000000105000000000005150000003444d872034076bed1643181e8030000010200000000001602000000f50100000200b8000700000000001400a9001200010100000000000100000000000b1400a9001200010100000000000100000000000b1400ff011f00010100000000000300000000000b1400a900120001010000000000030100000000001800a9001200010200000000001602000000f501000000002400ff011f000105000000000005150000003444d872034076bed1643181e803000000002400a90012000105000000000005150000003444d872034076bed1643181ea030000

# getfattr -d -m . /home/user1
getfattr: Removing leading '/' from absolute path names
# file: home/user1
security.NTACL=0sBAAEAAAAAgAEAAIAAQDougaiArk7bx1P/2TZsoNxUiHINDgVeNuTgavLixTfqgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcG9zaXhfYWNsAIpvXszPVNgB6dXacLVeKV5ce8tKXRLaLqRG/8SMRI9i9j++vUd9igIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEABIC0AAAA0AAAAAAAAADgAAAAAQUAAAAAAAUVAAAANETYcgNAdr7RZDGB6AMAAAECAAAAAAAWAgAAAPUBAAACALgABwAAAAAAFACpABIAAQEAAAAAAAEAAAAAAAsUAKkAEgABAQAAAAAAAQAAAAAACxQA/wEfAAEBAAAAAAADAAAAAAALFACpABIAAQEAAAAAAAMBAAAAAAAYAKkAEgABAgAAAAAAFgIAAAD1AQAAAAAkAP8BHwABBQAAAAAABRUAAAA0RNhyA0B2vtFkMYHoAwAAAAAkAKkAEgABBQAAAAAABRUAAAA0RNhyA0B2vtFkMYHqAwAA
#endif


#ifndef FSTRING_LEN
#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];
#endif



/* permissions bits - kernel fs/ksmbd/smb_common.h */
#define FILE_READ_DATA        0x00000001  /* Data can be read from the file   */
#define FILE_WRITE_DATA       0x00000002  /* Data can be written to the file  */
#define FILE_APPEND_DATA      0x00000004  /* Data can be appended to the file */
#define FILE_READ_EA          0x00000008  /* Extended attributes associated   */
/* with the file can be read        */
#define FILE_WRITE_EA         0x00000010  /* Extended attributes associated   */
/* with the file can be written     */
#define FILE_EXECUTE          0x00000020  /*Data can be read into memory from */
/* the file using system paging I/O */
#define FILE_DELETE_CHILD     0x00000040
#define FILE_READ_ATTRIBUTES  0x00000080  /* Attributes associated with the   */
/* file can be read                 */
#define FILE_WRITE_ATTRIBUTES 0x00000100  /* Attributes associated with the   */
/* file can be written              */
#define DELETE                0x00010000  /* The file can be deleted          */
#define READ_CONTROL          0x00020000  /* The access control list and      */
/* ownership associated with the    */
/* file can be read                 */
#define WRITE_DAC             0x00040000  /* The access control list and      */
/* ownership associated with the    */
/* file can be written.             */
#define WRITE_OWNER           0x00080000  /* Ownership information associated */
/* with the file can be written     */
#define SYNCHRONIZE           0x00100000  /* The file handle can waited on to */
/* synchronize with the completion  */
/* of an input/output request       */
#define GENERIC_ALL           0x10000000
#define GENERIC_EXECUTE       0x20000000
#define GENERIC_WRITE         0x40000000
#define GENERIC_READ          0x80000000
/* In summary - Relevant file       */
/* access flags from CIFS are       */
/* file_read_data, file_write_data  */
/* file_execute, file_read_attributes*/
/* write_dac, and delete.           */


#if 0

        typedef [public,gensize,nosize] struct {
                security_acl_revision revision;
                [value(ndr_size_security_acl(r,ndr->flags))] uint16 size;
                [range(0,2000)] uint32 num_aces;
                security_ace aces[num_aces];
        } security_acl;

        typedef [gensize,nosize,public,flag(NDR_LITTLE_ENDIAN)] struct {
                security_descriptor_revision revision;
                security_descriptor_type type;     /* SEC_DESC_xxxx flags */
                [relative] dom_sid *owner_sid;
                [relative] dom_sid *group_sid;
                [relative] security_acl *sacl; /* system ACL */
                [relative] security_acl *dacl; /* user (discretionary) ACL */
        } security_descriptor;
#endif

#if 0
/* Types of ACLs. */
typedef enum {
	SMB_ACL_TAG_INVALID = 0,
	SMB_ACL_USER        = 1,
	SMB_ACL_USER_OBJ    = 2,
	SMB_ACL_GROUP       = 3,
	SMB_ACL_GROUP_OBJ   = 4,
	SMB_ACL_OTHER       = 5,
	SMB_ACL_MASK        = 6
} smb_acl_tag_t;
const char *NTACL_tag_name(int tag) {
        switch (tag) {
                case SMB_ACL_TAG_INVALID: return "INVALID"; break;
                case SMB_ACL_USER_OBJ: return "USER_OBJ"; break;
                case SMB_ACL_USER: return "USER"; break;
                case SMB_ACL_GROUP_OBJ: return "GROUP_OBJ"; break;
                case SMB_ACL_GROUP: return "GROUP"; break;
                case SMB_ACL_MASK: return "MASK"; break;
                case SMB_ACL_OTHER: return "OTHER"; break;
                default: return "ERROR"; break;
        }
}
#endif

// security_ace_type
#define SEC_ACE_TYPE_ACCESS_ALLOWED	0
#define SEC_ACE_TYPE_ACCESS_DENIED	1
#define SEC_ACE_TYPE_SYSTEM_AUDIT	2
#define SEC_ACE_TYPE_SYSTEM_ALARM	3
#define SEC_ACE_TYPE_ALLOWED_COMPOUND	4
#define SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT	5
#define SEC_ACE_TYPE_ACCESS_DENIED_OBJECT	6
#define SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT	7
#define SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT	8

// security_ace_flags;
#define SEC_ACE_FLAG_OBJECT_INHERIT	0x01
#define SEC_ACE_FLAG_CONTAINER_INHERIT	0x02
#define SEC_ACE_FLAG_NO_PROPAGATE_INHERIT	0x04
#define SEC_ACE_FLAG_INHERIT_ONLY	0x08
#define SEC_ACE_FLAG_INHERITED_ACE	0x10
#define SEC_ACE_FLAG_VALID_INHERIT	0x0f
#define SEC_ACE_FLAG_SUCCESSFUL_ACCESS	0x40
#define SEC_ACE_FLAG_FAILED_ACCESS	0x80
/*
typedef [bitmap32bit] bitmap {
	SEC_ACE_OBJECT_TYPE_PRESENT             = 0x00000001,
	SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT   = 0x00000002
} security_ace_object_flags;
*/

/*
typedef struct {
//	security_ace_object_flags flags;
	uint32_t flags;
	[switch_is(flags & SEC_ACE_OBJECT_TYPE_PRESENT)] security_ace_object_type type;

	[switch_is(flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT)] security_ace_object_inherited_type inherited_type;
} security_ace_object;
*/

const struct ace_type_strings {
	uint8_t type;
	char *name;
} ace_types[] = {
	{ SEC_ACE_TYPE_ACCESS_ALLOWED, "ALLOWED" },
	{ SEC_ACE_TYPE_ACCESS_DENIED, "DENIED" },
	{ SEC_ACE_TYPE_SYSTEM_AUDIT, "AUDIT" },
	{ SEC_ACE_TYPE_SYSTEM_ALARM, "ALARM" },
	{ SEC_ACE_TYPE_ALLOWED_COMPOUND, "ALLOWED_COMPOUND" },
	{ SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT, "ALLOWED_OBJECT" },
	{ SEC_ACE_TYPE_ACCESS_DENIED_OBJECT, "DENIED_OBJECT" },
};
char *ace_type_str(uint8_t type) {
	int i;

	for (i = 0 ; i < ARRAY_SIZE(ace_types) ; i++) {
		if (type == ace_types[i].type)
			return strdup(ace_types[i].name);
	}
	return strdup("ERROR");
}
const struct ace_access_mode_strings {
	uint32_t mode;
	char *name;
} ace_access_modes[] = {
	{ 0x001200a9, "READ+EXECUTE" },
	{ 0x00120089, "READ" },
	{ 0x001f01ff, "FULL" },
};
/*
	<listitem><para><emphasis>R</emphasis> - Allow read access </para></listitem>
	<listitem><para><emphasis>W</emphasis> - Allow write access</para></listitem>
	<listitem><para><emphasis>X</emphasis> - Execute permission on the object</para></listitem>
	<listitem><para><emphasis>D</emphasis> - Delete the object</para></listitem>
	<listitem><para><emphasis>P</emphasis> - Change permissions</para></listitem>
	<listitem><para><emphasis>O</emphasis> - Take ownership</para></listitem>
*/
char *ace_access_mode_str(uint32_t mode) {
	char *str;
	int i;

	for (i = 0 ; i < ARRAY_SIZE(ace_access_modes) ; i++) {
		if (mode == ace_access_modes[i].mode)
			return strdup(ace_access_modes[i].name);
	}
	str = malloc(10);
	snprintf(str, 9, "0x%"PRIx32, mode);
	return str;
}
struct ace_flag_strings {
	uint8_t flag;
	char *name;
};
struct ace_flag_strings ace_flags[] = {
	{ SEC_ACE_FLAG_OBJECT_INHERIT, "OI", },
	{ SEC_ACE_FLAG_CONTAINER_INHERIT, "CI", },
	{ SEC_ACE_FLAG_NO_PROPAGATE_INHERIT, "NP", },
	{ SEC_ACE_FLAG_INHERIT_ONLY, "IO", },
	{ SEC_ACE_FLAG_INHERITED_ACE, "ID", },
	{ SEC_ACE_FLAG_SUCCESSFUL_ACCESS, "SA", },
	{ SEC_ACE_FLAG_FAILED_ACCESS, "FA", },
};
char *ace_flag_str(uint8_t flags) {
	char buf[24], *p = buf;
	int i;

	if (flags == 0)
		return strdup("0x0");
	memset(buf, 0, sizeof(buf));
	for (i = 0 ; i < ARRAY_SIZE(ace_flags) ; i++) {
		if (flags & ace_flags[i].flag) {
			if (p != buf)
				*p++ = '|';
			p = stpcpy(p, ace_flags[i].name);
		}
	}
	return strdup(buf);
}

/*
typedef struct {
	uint8_t revision;
	uint16_t size;
	uint32_t num_aces;
	security_ace aces[0];
} security_acl;
*/
#define endian32(x) ( \
	((x >> 24) & 0xff) | \
	((x >> 8) & 0xff00) | \
	((x << 8) & 0xff0000) | \
	((x << 24) & 0xff0000) \
)
#define endian16(x) ( \
	((x >> 8) & 0xff) | \
	((x << 8) & 0xff00) \
)

// from ksmbd/misc.[ch]
#define NTFS_TIME_OFFSET	((uint64_t)(369 * 365 + 89) * 24 * 3600 * 10000000)
uint64_t unix_time_to_nt(struct timespec t) {
	 return (uint64_t)t.tv_sec * 10000000 + t.tv_nsec / 100 + NTFS_TIME_OFFSET;
}
struct timespec nt_time_to_unix_time(uint64_t ntutc) {
	struct timespec ts;
	int64_t t = (ntutc) - NTFS_TIME_OFFSET;

	ts.tv_nsec = (t % 10000000) * 100;
	ts.tv_sec = t / 10000000;
	return ts;
}

#define __packed __attribute__((packed))


#define NUM_AUTHS (6) /* authority fields */
#define SID_MAX_SUB_AUTHORITIES (15) /* max number of sub authority fields */
#define XATTR_SD_HASH_SIZE 64
#define XATTR_SD_HASH_TYPE_NONE 0x0
#define XATTR_SD_HASH_TYPE_SHA256 0x1


// from samba/librpc/idl/security.idl
//
struct smb_sid {
	uint8_t revision;
	uint8_t num_subauth;
	uint8_t authority[NUM_AUTHS];
	uint32_t sub_auth[SID_MAX_SUB_AUTHORITIES];
} __packed;

struct smb_acl {
	uint16_t revision;
	uint16_t size;
	uint32_t num_aces;
} __packed;

struct security_descriptor {
//	security_descriptor_revision revision;
	uint16_t revision;
//	security_descriptor_type type; /* SEC_DESC_xxxx flags */
	uint16_t type;
//	dom_sid *owner_sid;
//	dom_sid *group_sid;
	struct smb_sid owner_sid;
	struct smb_sid group_sid;
//	security_acl *sacl; // system ACL
	struct smb_acl *sacl;
//	security_acl *dacl; // user discretionary ACL
	struct smb_acl *dacl;

};
struct smb_ntsd {
	uint16_t revision;
	uint16_t type;
	uint32_t osidoffset;
	uint32_t gsidoffset;
	uint32_t sacloffset;
	uint32_t dacloffset;
} __packed;
#define NDR_NTSD_OFFSETOF	0xA0

// size of pntsd:
//     sizeof(struct smb_ntsd) +
//     sizeof(struct smb_sid) * 3 +
//     sizeof(struct smb_acl) +
//     sizeof(struct smb_ace) * ace_nums * 2

/*
// ignoring earlier versions for now
struct security_descriptor_hash_v4 {
	struct security_descriptor *sd;
	uint16_t hash_type;
	uint8_t hash[XATTR_SD_HASH_SIZE];
} __packed;
*/

struct smb_ace {
	uint8_t type;
	uint8_t flags;
	uint16_t size;
	uint32_t access_req;
	struct smb_sid sid;
} __packed;


#define SID_SIZE(sid) ( (unsigned char *)&(sid->sub_auth[sid->num_subauth]) - 	(unsigned char *)sid )
#define ACE_SIZE(ace) ( ((unsigned char *)&(ace->sid)) - (unsigned char *)ace + SID_SIZE((&ace->sid)) )

#define SID_BUF_LEN 128
char *sid_to_string(struct smb_sid *sid) {
	char buf[SID_BUF_LEN];
	int i, ret, len = 0;
	uint64_t ia;

	ia = ((uint64_t)sid->authority[5]) +
		((uint64_t)sid->authority[4] << 8 ) +
		((uint64_t)sid->authority[3] << 16) +
		((uint64_t)sid->authority[2] << 24) +
		((uint64_t)sid->authority[1] << 32) +
		((uint64_t)sid->authority[0] << 40);

	ret = snprintf(buf, SID_BUF_LEN - 1, "S-%"PRIu8"-", sid->revision);

	len = ret;
	if (ia >= UINT32_MAX)
		ret = snprintf(buf + len, max(SID_BUF_LEN - len - 1, 0), "0x%"PRIx64, ia);
	else
		ret = snprintf(buf + len, max(SID_BUF_LEN - len - 1, 0), "%"PRIu64, ia);
	len += ret;

	for (i = 0 ; i < sid->num_subauth ; i++) {
		ret = snprintf(buf + len, max(SID_BUF_LEN - len - 1, 0), "-%"PRIu32, sid->sub_auth[i]);
		len += ret;
	}
	return strdup(buf);
}

void *show_NTACL(const char *name, const unsigned char *buf, int len, bool is_dir) {
        unsigned char *p = (unsigned char *)buf;


	printf("decoding %d bytes\n", len);
	hexprint(buf, len);




//        typedef [public,gensize,nosize] struct {
//                security_acl_revision revision;
//                [value(ndr_size_security_acl(r,ndr->flags))] uint16 size;
//                [range(0,2000)] uint32 num_aces;
//                security_ace aces[num_aces];
//        } security_acl;


	uint16_t version1 = *(uint16_t *)p; p += 2;
	uint32_t version2 = *(uint32_t *)p; p += 4;
	printf("NTACL... version: %u/%u - %s\n", version1, version2, version1 == version2 ? "OKAY" : "MISMATCH");

	printf("level: %d\n", *(uint16_t *)p);
	p += 2;
	printf("ref id: %d\n", *(uint32_t *)p);
	p += 4;
	// if ref_id == 0x00020000 - posix acl
	// if ref_id == 0x00020004 - v4 ntacl

	// v0 - hash type none
	// v1 - hash type sha256
	printf("hash type: %d\n", *(uint16_t *)p);
	p += 2;

	unsigned char hash[XATTR_SD_HASH_SIZE];
	memcpy(hash, p, XATTR_SD_HASH_SIZE);

	printf("hash:\n");
	hexprint(hash, XATTR_SD_HASH_SIZE);

	p += XATTR_SD_HASH_SIZE;

	char acl_desc[10];
	memcpy(acl_desc, p, 10);
	printf("acl desc: %s\n", acl_desc);
	p += 10;

	struct timespec ts = nt_time_to_unix_time(*(uint64_t *)p);
	printf("time: 0x%016lx - %lu.%09ld\n", *(uint64_t *)p,ts.tv_sec, ts.tv_nsec);
	p += 8;


	printf("posix acl hash:\n");
	hexprint(p, XATTR_SD_HASH_SIZE); /* posix_acl_hash*/
	p += XATTR_SD_HASH_SIZE;

if (0) {
	printf("remaining size: %ld\n", len - ((uint64_t)p - (uint64_t)buf));
	hexprint(p, len - ((uint64_t)p-(uint64_t)buf));
}

	struct smb_ntsd *pntsd = (struct smb_ntsd *)p;
	printf("pntsd: %p\n", pntsd);

	printf("smb_ntsd size: %lu\n", sizeof(struct smb_ntsd));
	printf("  revision: %d\n", pntsd->revision);
	printf("  type: %d\n", pntsd->type);
	printf("  osidoffset: 0x%08x (%u)\n", pntsd->osidoffset, pntsd->osidoffset);


	if (0) {
//		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->osidoffset - NDR_NTSD_OFFSETOF);
		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->osidoffset);
		int sid_size = 1 + 1 + 6 + (sid->num_subauth*4);
		int test_size = pntsd->gsidoffset - pntsd->osidoffset;
		int test_size2 = SID_SIZE(sid);

		if (test_size != sid_size)
			printf("hrm... mismatch?  sid_size: %d, but thought it would be %d (or maybe %d?)\n", sid_size, test_size, test_size2);

//		hexprint_pad("    ", buf + pntsd->osidoffset, pntsd->gsidoffset - pntsd->osidoffset);
		hexprint_pad("    ", (unsigned char *)sid, sid_size);
	}


	printf("  gsidoffset: 0x%08x (%u)\n", pntsd->gsidoffset, pntsd->gsidoffset);
	if (0) {
//		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->gsidoffset - NDR_NTSD_OFFSETOF);
		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->gsidoffset);
		int sid_size = 1 + 1 + 6 + (sid->num_subauth*4);
		int test_size = pntsd->dacloffset - pntsd->gsidoffset;

		if (test_size != sid_size)
			printf("hrm... mismatch?  sid_size: %d, but thought it would be %d\n", sid_size, test_size);

		hexprint_pad("    ", (unsigned char *)sid, sid_size);
	}
//	hexprint_pad("    ", buf + pntsd->gsidoffset, pntsd->dacloffset - pntsd->gsidoffset);

//	printf("  sacloffset: 0x%08x (%ld)\n", pntsd->sacloffset, pntsd->sacloffset);
	printf("  dacloffset: 0x%08x (%u)\n", pntsd->dacloffset, pntsd->dacloffset);
	if (0) {
//		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->dacloffset - NDR_NTSD_OFFSETOF);
		struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->dacloffset);
		int sid_size = 1 + 1 + 6 + (sid->num_subauth*4);
		int test_size = len - pntsd->dacloffset;
		int test_size2 = SID_SIZE(sid);

		if (test_size != sid_size)
			printf("hrm... mismatch?  sid_size: %d, but thought it would be %d (or maybe %d)\n", sid_size, test_size, test_size2);

		hexprint_pad("    ", (unsigned char *)sid, sid_size);
	}
//	hexprint_pad("    ", buf + pntsd->dacloffset, len - pntsd->dacloffset);


	p += sizeof(struct smb_ntsd);


printf("size of smb_ntsd: %lu\n", sizeof(struct smb_ntsd));
printf("size of smb_sid: %lu to %lu\n", (unsigned long)&(((struct smb_sid *)(0x0))->sub_auth[0]), 	sizeof(struct smb_sid));
//printf("size of smb_acl: %lu\n", sizeof(struct smb_acl));
printf("size of smb_acl: %lu\n", sizeof(struct smb_acl));
printf("size of smb_ace: %lu\n", sizeof(struct smb_ace));


if (0) {
	int sd_size = len - ((uint64_t)p - (uint64_t)buf);

	printf("remaining size: %d\n", sd_size);
	hexprint(p, sd_size);
}
	{
p = buf + pntsd->osidoffset;

//struct smb_sid *sid = (struct smb_sid *)(pntsd + pntsd->osidoffset - NDR_NTSD_OFFSETOF);
struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->osidoffset);
char *sid_str = sid_to_string(sid);
//printf("trying to output osid at 0x%08"PRIx64" (current offset: %ld):  %s\n", (uint64_t)sid, (unsigned char *)sid-(unsigned char *)pntsd, sid_str);
printf("osid at 0x%08"PRIx64" (buf offset: %"PRIu64", osidoffset: %d, current offset: %ld):  %s\n",
		(uint64_t)sid,
		(uint64_t)p - (uint64_t)buf,
		pntsd->osidoffset,
		(unsigned char *)p-(unsigned char *)pntsd,
		sid_str);

p = (unsigned char *)&(sid->sub_auth[sid->num_subauth]);

//printf("    (size of that sid: %lu)\n", (unsigned long)(p-(unsigned char *)sid));
//printf("    offset now %ld\n", p - buf);
//printf("    size of that sid: %lu\n", SID_SIZE(sid));
free(sid_str);

	}
	{
p = buf + pntsd->gsidoffset;

//struct smb_sid *sid = (struct smb_sid *)(pntsd + pntsd->gsidoffset - NDR_NTSD_OFFSETOF);
struct smb_sid *sid = (struct smb_sid *)(buf + pntsd->gsidoffset);
char *sid_str = sid_to_string(sid);
//printf("trying to output gsid at %p (offset: %ld):  %s\n", sid, (unsigned char *)sid-(unsigned char *)pntsd, sid_str);
printf("gsid at 0x%08"PRIx64" (buf offset: %"PRIu64", gsidoffset: %d, current offset: %ld):  %s\n",
		(uint64_t)sid,
		(uint64_t)p - (uint64_t)buf,
		pntsd->gsidoffset,
		(unsigned char *)p-(unsigned char *)pntsd,
		sid_str);
//printf("    (size of that sid: %d)\n", (unsigned long)&(((struct smb_sid *)(0x0))->sub_auth[0]) + (sizeof((struct smb_sid *)0x).sub_auth[0]) * sid->num_subauth));
//printf("    (size of that sid: %lu)\n", (unsigned long)&(((struct smb_sid *)(0x0))->sub_auth[0]) + (sizeof(sid->sub_auth[0]) * sid->num_subauth));
p = (unsigned char *)&(sid->sub_auth[sid->num_subauth]);
//printf("    (size of that sid: %lu)\n", (unsigned long)(p-(unsigned char *)sid));
//printf("    offset now %ld\n", p - buf);

free(sid_str);
	}

#if 0



	// now, 3 smb_sids?
	int i;
	for (i = 0 ; i < 2 ; i++) {
		struct smb_sid sid;
		memcpy(&sid, p, sizeof(struct smb_sid));

		printf(" sid %d - at %p (offset from pntsd: %ld)\n", i, p, p - (unsigned char *)pntsd);

		printf("  revision: %d\n", sid.revision);
		printf("  num_subauth: %d\n", sid.num_subauth);
//		printf("  revision: %d\n", ace.sid.revision);
//		printf("  num_subauth: %d\n", ace.sid.num_subauth);

		char *sid_str = sid_to_string(&sid);

		printf("  sid string: %s\n", sid_str);
		free(sid_str);



/*
		int j;
		printf("  authority: ");
		for (j = 0 ; j < NUM_AUTHS ; j++) {
			printf("%d ", sid.authority[j]);
		}
		printf("\n");
		printf("  subauthorities: ");
		for (j = 0 ; j < sid.num_subauth ; j++) {
			printf("%u-", sid.sub_auth[j]);
		}
		printf("\n\n");

//		uint8_t authority[NUM_AUTHS];
//		uint32_t aub_auth[SID_MAX_SUB_AUTHORITIES];

		p += ((unsigned char *)(&sid.sub_auth[j]) - (unsigned char *)(&sid));
//			sizeof(struct smb_sid);
*/
		p += (unsigned char *)(&sid.sub_auth[sid.num_subauth]) - (unsigned char *)(&sid);


	}

#endif


	if (p  - buf != pntsd->dacloffset)
		printf("expected to be at %ld, but we're at %d instead\n", p - buf, pntsd->dacloffset);

if (0) {
	p = buf + pntsd->dacloffset;
	printf("current offset: %ld; bytes remaining: %ld\n",
		p - buf, len - (p - buf));
	hexprint_pad("  ", p, len - (p - buf));
}

	struct smb_acl *acl = (struct smb_acl *)(buf + pntsd->dacloffset);

	printf("acl:\n");
	if (0)
		hexprint_pad("    ", (unsigned char *)acl, sizeof(struct smb_acl));
	printf("  revision: %d\n", acl->revision);
	printf("  size: %d\n", acl->size);
	printf("  num_aces: %u\n", le32toh(acl->num_aces));


//	p = (unsigned char *)pntsd + pntsd->dacloffset + sizeof(struct smb_acl);
	p = (unsigned char *)buf + pntsd->dacloffset + sizeof(struct smb_acl);

	/*
	struct xattr_acl_entry {
		int type;
		uid_t uid;
		gid_t gid;
		mode_t perm;
	};
	*/
        while (p < buf + len) {
                struct smb_ace *ace = (struct smb_ace *)p;
//		struct smb_ace ace;
//		memcpy(&ace, p, sizeof(struct smb_ace));

		char *type_str = ace_type_str(ace->type);
		char *mode_str = ace_access_mode_str(ace->access_req);
		char *flags_str = ace_flag_str(ace->flags);
		char *sid_str = sid_to_string(&ace->sid);

		printf("ace: \n");
		printf(" type: %d - %s\n", ace->type, type_str);
		printf(" flags: %d - %s\n", ace->flags, flags_str);
		printf(" size: %d\n", ace->size);
		printf(" access_req: 0x%08x (%s)\n", ace->access_req, mode_str);

		printf(" sid: %s\n", sid_str);

		printf("  revision: %d\n", ace->sid.revision);
		printf("  num_subauth: %d\n", ace->sid.num_subauth);


// display numeric or textual?
		printf("ACE:%s:%d/0x%x/0x%08x\n",
			sid_str, ace->type, ace->flags, ace->access_req);
		printf("    ACE:%s:%s/%s/%s\n",
			"TODO", type_str, flags_str, mode_str);

		free(type_str);
		free(mode_str);
		free(flags_str);
		free(sid_str);
		p += ACE_SIZE(ace);
	}

	return 0;
}
