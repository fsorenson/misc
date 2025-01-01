all: inobtree_workaround.so workaround_tester

CFLAGS = -fdiagnostics-color=always

mountpoint = /mnt/tmp
metadump = /var/tmp/test.dmp
image = /var/tmp/test.img

# some directories where files or directories cannot be created
dir1 = /path/to/directory1
dir2 = /path/to/directory2

pwd = $(shell pwd)
workaround_so = $(pwd)/inobtree_workaround.so

kernel_rpm_ver = 4.18.0-553.el8_10.x86_64

inobtree_workaround.so: inobtree_workaround.c
	gcc -Wall inobtree_workaround.c -o inobtree_workaround.so -shared -fPIC -ldl -g $(CFLAGS)

workaround_tester: workaround_tester.c
	gcc -Wall workaround_tester.c -o workaround_tester -g $(CFLAGS)

setup:
	@-umount $(mountpoint)
	@xfs_mdrestore $(metadump) $(image)
	@mount $(image) $(mountpoint)

test: inobtree_workaround.so workaround_tester
	@rm -rf $(mountpoint)$(dir1)/{testdir,testfile}*
	@export LD_PRELOAD=$(workaround_so) && \
		$(pwd)/workaround_tester $(mountpoint)$(dir1)

#	@rm -rf $(mountpoint)$(dir1)/{testdir,testfile}* $(mountpoint)$(dir2)/{testdir,testfile}*
#	@export LD_PRELOAD=$(workaround_so) && export LD_DEBUG=symbols,versions && \
#		export LD_TRACE_LOADED_OBJECTS=1 && \
#		$(pwd)/workaround_tester $(mountpoint)$(dir1) $(mountpoint)$(dir2)

test_rpm:
	rm -rf $(mountpoint)/var/lib/rpm/*
	export LD_PRELOAD=$(workaround_so) && \
		rpm --nodeps --noscripts --notriggers --root=$(mountpoint) -ivh /var/tmp/kernel-{,core-,modules-,debuginfo-,debuginfo-common-x86_64-}$(kernel_rpm_ver).rpm

test_dnf:
	rm -rf $(mountpoint)/var/lib/rpm/*
	export LD_PRELOAD=$(workaround_so) && cp -R /var/lib/rpm/* $(mountpoint)/var/lib/rpm
	rm -rf $(mountpoint)/var/lib/dnf
	export LD_PRELOAD=$(workaround_so) && cp -R /var/lib/dnf $(mountpoint)/var/lib
	rm -rf $(mountpoint)/etc/dnf
	export LD_PRELOAD=$(workaround_so) && cp -R /etc/dnf $(mountpoint)/etc
	rm -rf $(mountpoint)/etc/yum*
	export LD_PRELOAD=$(workaround_so) && cp -R /etc/yum* $(mountpoint)/etc
	rm -rf $(mountpoint)/var/cache/dnf
	export LD_PRELOAD=$(workaround_so) && cp -R /var/cache/dnf $(mountpoint)/var/cache
	export LD_PRELOAD=$(workaround_so) && \
		dnf -C install --installroot=$(mountpoint) /var/tmp/kernel-{,core-,modules-,debuginfo-,debuginfo-common-x86_64-}$(kernel_rpm_ver).rpm

debug_test: inobtree_workaround.so workaround_tester
	gdb -iex 'set exec-wrapper env LD_PRELOAD=$(workaround_so)' --args $(pwd)/workaround_tester $(mountpoint)$(dir1) $(mountpoint)$(dir2)

debug_fopen:
	gdb -iex 'set exec-wrapper env LD_PRELOAD=$(workaround_so)' --args /usr/bin/tee $(mountpoint)$(dir1)/test_fopen
