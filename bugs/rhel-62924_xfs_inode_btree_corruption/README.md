This is an xfs bug reported by a number of customers, including a cloud server provider seeing at least 50 customers with the bug.

# For background
XFS divides the filesystem blocks into allocation groups (AGs) with a fixed maximum size; mkfs.xfs tries to divide the blocks equally across 4 (default) AGs (more for filesystems > 4TiB).  Expanding the filesystem can also result in adding more AGs as needed.

However, since the number of filesystem blocks doesn't always divide evenly across AGs, and since people don't usually expand filesystems by **exactly** a multiple of the AG size, the last AG could be (and very often **is**) smaller than the rest.


Allocations of an inode for a new file/directory are done in an inode group of 64 inodes (with 512-byte inodes and 4 KiB filesystem blocks, that's 32 KiB or 8 filesystem blocks).

But the kernel also gets tricky with an inode group that runs up against the end of the AG, and doesn't quite fit... it just allocates as much as it can, so the inode group is shorter than the rest; the kernel limits inode allocation to fit within an AG


# The bug

That brings us to the bug...  when allocating an inode in the shortened inode group in the last, shorter AG, the kernel mistakenly limits the allocation to fit within the **normal** size of an AG, not the size of **that** particular AG...  meaning that the kernel is attempting to use space beyond the end of the filesystem.  The kernel detects this allocation-beyond-end, and returns an error (`EUCLEAN - Structure needs cleaning`).

A patch fixing the bug has been [merged upstream](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/fs/xfs/libxfs/xfs_ialloc.c?id=13325333582d4820d39b9e8f63d6a54e745585d9 "upstream commit"), and should appear in distribution kernels soon.

However, filesystems already experiencing the bug will not be able to install the updated kernel; file and directory creation will fail in affected directories, so rpm will exit as soon as the kernel attempts to allocate an inode in that final AG.


# More background

The AG selection algorithm for allocating inodes is pretty simple:
 - inodes for files are allocated from the same AG as their parent directory, so if the parent directory is in the final AG, file creation will fail; otherwise, file creation will succeed.
 - inodes for directories are allocated from the AGs round-robin, so directory creation will always fail once every '# of AGs'.


# Workaround

## Exploiting this allocation algorithm
 - the workaround for a failed directory creation is to simply try creating the directory a second time; this time, the inode will be allocated from AG 0, which should succeed.
 - the workaround for a failed file creation is to create the file in another directory which is allocated from a different AG, then move the file to its final destination.


## Automating the workaround
To automate these workarounds I wrote a shared library that can be used via `LD_PRELOAD`, which replaces the file/directory creation functions in glibc with my own.  If creation fails, the replacement functions automatically use the necessary workarounds to create the file/directory.  The replacement library functions can then return success to the calling program, which never sees the failures.

## Compiling the library

```
    # gcc -Wall inobtree_workaround.c -o inobtree_workaround.so -shared -fPIC -ldl
```

## Using the library

usage (bash):
```
    # export LD_PRELOAD=$(pwd)/inobtree_workaround.so
    # rpm -ivh kernel-...
```

