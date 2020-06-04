#!/bin/sh
#
# Reproducer to verify: https://bugzilla.redhat.com/show_bug.cgi?id=1826123
# Bug 1826123 - RHEL8.1 NFSv3 client hang due to kworker writeback deadlock by calling back into inode_wait_for_writeback from evict
#
# Outline
#
# FAIL: 
# PASS: 
#
v=${1:-3}

echo "NFS version=$v"
NFS_SERVER=127.0.2.1
RSIZE=65536
wsize=65536

# delay for lo; set to 0 for no delay
# ignored if delay is 0 or device is not 'lo'
NETWORK_DELAY=2ms
TC_DEV=

username=user1
test_dir=
repro_pid=
XFS_DEV=
XFS_MNT=
XFS_SIZE=2048M
QUOTA_SOFT=299200K
QUOTA_HARD=498400K
RC=1

EXE=bz1826123-3
REPRO_CHILDREN=200
REPROFILE_SIZE="(100 * MiB)"
REPRO_WRITE_SIZE="(32 * KiB)"

DATA_DIR=/mnt/data
if [ ! -e $DATA_DIR ]; then
	echo $DATA_DIR does not exist - please mount scratch filesystem
	exit 1
fi

function nfsd_start {
	systemctl status nfs-server >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo Trying to start nfs-server
		systemctl start nfs-server >/dev/null 2>&1
		if [ $? -ne 0 ]; then
			echo could not start nfs-server
			exit 1;
		fi
	fi
}
function nfsd_check_version {
	v=$1
	if [ ! /proc/fs/nfsd/versions ]; then
		echo Error please start the nfs server
		exit 1
	fi
	grep -q $v /proc/fs/nfsd/versions
	if [ $? -ne 0 ]; then
		echo Enabling NFS vers=$v in nfs-server
		nfsconf --set nfsd vers$v y
		systemctl restart nfs-server
	fi
}

function xfs_mktemp_local {
	local size
	if [ $# -ge 1 ]; then
		size=$1
	else
		size=250M
	fi
	TMPDIR=$(mktemp -d -p $DATA_DIR)
	IMG="$TMPDIR/img"
	truncate -s $size $IMG
	mkfs.xfs $IMG
	ret=$IMG
}
function xfs_cleanup {
	umount $1 && rmdir $1 && rm -f $2
}
function cleanup_network {
	if [[ -n $NETWORK_DELAY && $NETWORK_DELAY != "0" && -n $TC_DEV ]] ; then
		tc qdisc del dev $TC_DEV root >/dev/null 2>&1
	fi
}

function cleanup_exit {
	trap - EXIT
	trap "" SIGINT SIGTERM

	[[ -n $start_time ]] && echo "exiting after $(($SECONDS - $start_time)) seconds"

	if [[ -n $repro_pid ]] ; then
		kill $repro_pid
		wait $repro_pid
	fi
	sleep 1
	cleanup_network
	exportfs -au

	umount $test_dir
	rmdir $test_dir

	if [[ -n $XFS_MNT ]] ; then
		sed -e "s@^$XFS_MNT\s.\+@XXXXX@g" -e '/XXXXX/d' -i /etc/exports
	fi
	exportfs -a

	echo xfs_cleanup $XFS_MNT $XFS_DEV
	xfs_cleanup $XFS_MNT $XFS_DEV
	rmdir $TMPDIR
	trap - EXIT SIGINT SIGTERM

	exit $RC
}

function nfsd_export_subdir {
	grep -q "$1" /etc/exports
	if [ $? -ne 0 ]; then
		echo adding export $1
		echo "$1 *(rw,sec=sys)" >> /etc/exports
		exportfs -ra
	fi
}

function check_nfs_mount {
        grep -i nfs /proc/mounts | grep $1 > /dev/null
        if [ $? -ne 0 ]; then
                echo Please ensure $1 exists and $2 is an exported NFS filesystem
		exit
        fi
	if [ $# -lt 3 ]; then
		return
	fi
	grep $1 /proc/mounts | grep -i $3 > /dev/null
        if [ $? -ne 0 ]; then
                echo ERROR: Did not find $3 in mount options of NFS mount at $1
		exit
        fi
}

function check_bz1826123_signature {
	local flush_name=$1
	ps hxo 'stat,pid,comm' | awk -vflush_name="$flush_name" '
		BEGIN {
			if (flush_name=="") {flush_name="flush-[0-9]+:[0-9]+$"}
			else {flush_name=flush_name"$"}
		}
		{
			if ($1=="D" && match($3, flush_name)) {
				pid=$2
				cmd="grep -q -E --null-data \"inode_wait_for_writeback.+evict\" /proc/"pid"/stack 2>&1"
				ret=system(cmd)
				if (ret==0) {print "pid "pid" is hung with Red Hat BZ 1826123"; hits++}
			}
		}
		END { exit(hits ? 0 : 1) }'
	retval=$?
	echo "check_bz1826123_signature returning $retval"
}
function slow_network {
	if [[ -n $NETWORK_DELAY && $NETWORK_DELAY != "0" ]] ; then
		TC_DEV=$(ip route get to $NFS_SERVER 2>&1 | head -1 | awk '{for (i = 0 ; i <= NF ; i++) {if ($i=="dev" && i<NF) { print $(i+1) ; exit }}}')

# ip route get 127.0.2.1
#local 127.0.2.1 dev lo src 127.0.0.1 uid 0
#    cache <local>

# ip route get 192.168.122.2
#192.168.122.2 dev bond0 src 192.168.122.99 uid 0
#    cache

# ip route get 172.15.0.1
#172.15.0.1 via 192.168.122.1 dev bond0 src 192.168.122.99 uid 0
#    cache
		[[ -n $TC_DEV ]] || return

		# if it's not loopback, bail
		[[ $TC_DEV == "lo" ]] ||  {
			TC_DEV=""
			return
		}

		tc qdisc del dev $TC_DEV root >/dev/null 2>&1

		tc qdisc add dev $TC_DEV root handle 1: prio bands 10
		tc qdisc add dev $TC_DEV parent 1:1 handle 11: pfifo limit 1000
		tc qdisc add dev $TC_DEV parent 1:4 handle 14: netem limit 1000 delay $NETWORK_DELAY
		tc filter add dev $TC_DEV parent 1:0 prio 1 protocol ip u32 match ip dst $NFS_SERVER/255.255.255.255 flowid 1:4
	fi
}
RC=0

nfsd_start
nfsd_check_version $v

# 1. On NFS server, create temporary filesystem
echo "`date`: 1. On NFS server, create temporary filesystem"
xfs_mktemp_local $XFS_SIZE
XFS_DEV=$ret
XFS_MNT="$TMPDIR/xfs_mnt"
mkdir $XFS_MNT

echo "XFS_MNT = $XFS_MNT"
echo "XFS_DEV = $XFS_DEV"

trap cleanup_exit EXIT SIGINT SIGTERM

# 2. On NFS server, mount the filesystem with quotas
echo "`date`: 2. On NFS server, mount filesystem with quotas"
mount -o loop,uquota,gquota $XFS_DEV $XFS_MNT
# Assume if we cannot mount something bad happened
if [ $? -ne 0 ]; then
	echo Unable to mount xfs $XFS_DEV at $XFS_MNT exiting
	exit 1
fi

# 3. On NFS server, add user and set user quotas on the filesystem
echo "`date`: 3. On NFS server, add user and set user quotas on the filesystem"
adduser $username
chown -R $username:$username $XFS_MNT
xfs_quota -x -c "limit bsoft=$QUOTA_SOFT bhard=$QUOTA_HARD $username" $XFS_MNT
quota -s -u $username
df -h $XFS_MNT
grep $XFS_MNT /proc/mounts
sleep 1

# 4. On NFS server, export the filesystem just created
echo "`date`: 4. On NFS server, export the filesystem just created"
nfsd_export_subdir $XFS_MNT

# FIXME: $test_dir
# 5. On NFS client, mount -o vers=$v $NFS_SERVER:$XFS_MNT $test_dir
#mkdir -p $test_dir
test_dir=$(mktemp -d)
echo "`date`: 5. On NFS client, mount -o vers=$v,rsize=$RSIZE,wsize=$WSIZE $NFS_SERVER:$XFS_MNT $test_dir"
mount -o vers=$v,rsize=$RSIZE,wsize=$WSIZE $NFS_SERVER:$XFS_MNT $test_dir
check_nfs_mount $test_dir $NFS_SERVER:$XFS_MNT
slow_network

mount_dev=$(stat -c "%d" $test_dir)
flush_name="flush-$(($mount_dev / 0x100)):$(($mount_dev % 0x100))"

# FIXME: Location of C file
# 6. On NFS client, compile the reproducer
echo "`date`: 6. On NFS client, compile the reproducer"
gcc ./$EXE.c -o /var/tmp/$EXE -g -D FILE_SIZE="$REPRO_FILE_SIZE" -D MAX_CHILDREN="$REPRO_CHILDREN" -D WRITE_SIZE="$REPRO_WRITE_SIZE"
if [ $? -ne 0 ]; then
	echo "ERROR: unable to compile reproducer"
	RC=2
	exit
fi

# 7. On NFS client, change to the user and start reproducer
start_time=$SECONDS
echo "`date`: 7. On NFS client, change to the user and start reproducer"
IFS=: passwd=( $(getent passwd $username) ) #user1:x:501:501::/home/user1:/bin/bash
/var/tmp/$EXE ${passwd[2]} ${passwd[3]} $test_dir 2>&1 &
#su - $username -c "/var/tmp/$EXE $test_dir" &
repro_pid=$!

# 8. On NFS client, try to detect the hang
echo "`date`: 8. On NFS client, try to detect the hang"
while true; do
	echo "`date`: Checking for bz1826123 signature with name '$flush_name'"
	check_bz1826123_signature $flush_name
	if [ $retval -eq 0 ]; then
		echo "found bz1826123 signature"
		echo "TEST FAIL on kernel $(uname -r) with NFS vers=$v"
		RC=0
		break;
	fi
	sleep 10
done
