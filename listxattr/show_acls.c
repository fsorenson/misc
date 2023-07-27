#include <stdio.h>
#include <stdlib.h>
#include </usr/include/sys/acl.h>
#include <acl/libacl.h>


int main(int argc, char *argv[]) {
	ssize_t acl_len;
	acl_entry_t ace;
	char *acl_text;
	char *path;
	acl_t acl;
	int ret;
	int i;

	for (i = 1 ; i < argc ; i++) {
		path = argv[i];

		ret = acl_extended_file(path);
		if (ret == 0) {
			printf("%s has only standard permissions bits\n",
				path);
			continue;
		} else if (ret == -1) {
			printf("error occurred while checking for acls: %m\n");
			continue;
		}

		acl = acl_get_file(path, ACL_TYPE_DEFAULT);
		if (acl == NULL)
			printf("Unable to get default acl for %s: %m", path);
		else {
			ret = acl_get_entry(acl, ACL_FIRST_ENTRY, &ace);
			while (ret == 1) {
				printf("entry...\n");
				ret = acl_get_entry(acl, ACL_NEXT_ENTRY, &ace);
			}
		}
	}

	return EXIT_SUCCESS;
}

