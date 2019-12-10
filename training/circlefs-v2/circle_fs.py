#!/usr/bin/python3.7
#!/usr/bin/env python3.7

import sys
import os
import time
import math
from stat import S_IFDIR, S_IFREG, S_IFLNK
from fuse import FUSE, FuseOSError, Operations

from errno import *


class circlefs(Operations):

	def __init__(self, **kw):
		self.radius = 0
		print("fuse initialized")

	def __call__(self, op, *args):
		print(" call: {}".format(op))
		if not hasattr(self, op):
			raise FuseOSError(EFAULT)
		ret = getattr(self, op)(*args)
		print(" {} returned {}".format(op, ret))
		return ret
#		return getattr(self, op)(*args)


	def readdir(self, path, fh=None):
		print("  readdir({})".format(path))

		if not path == '/':
			raise FuseOSError(ENOENT)

		dirents = ['.', '..', 'radius', 'circumference', 'pi', 'π']
		for dirent in dirents:
			yield dirent

	def getattr(self, path, fh=None):
		print("  getattr({})".format(path))

		if path in [ '.', '..', '/' ]:
			mode = 0o755 | S_IFDIR
		elif path in [ '/radius', '/circumference' ]:
			mode = 0o644 | S_IFREG
		elif path in [ '/pi' ]: # no, you can't write a new value for pi
			mode = 0o444 | S_IFREG
		elif path in [ '/π' ]: # link π to pi
			mode = 0o777 | S_IFLNK
		else:
			raise FuseOSError(ENOENT)

		now = time.time()
		return {
			'st_atime' : now,
			'st_ctime' : now,
			'st_mtime' : now,
			'st_uid' : os.getuid(),
			'st_gid' : os.getgid(),
			'st_size' : 4096,
			'st_mode' : mode,
			'st_blocks' : 1
		}

	def statfs(self, path):
		print("  statfs({})".format(path))
		return {
			'f_bsize' : 42,
			'f_bfree' : 1,
			'f_bavail' : 1,
			'f_blocks' : 1,
			'f_files' : 1,
			'f_ffree' : 1,
			'f_favail' : 1,
			'f_flag' : 0,
			'f_frsize' : 0,
			'f_namemax' : 255
		}

	def read(self, path, length, offset, fh):
		val = self.get_val_str(path)
		print("  read({}, length: {}, offset: {}, fh: {}): {}".format(path, length, offset, fh, val))

		return val.encode('utf-8')[offset:length]

	def open(self, path, flags):
		print("  open({})".format(path))
		if not path in [ '/radius', '/circumference' , '/pi']:
			if (flags & os.O_APPEND) or (flags & os.O_EXCL) or (flags & os.O_DIRECT):
				raise FuseOSError(EINVAL)
			if (flags & os.O_CREAT):
				raise FuseOSError(EACCES)

#			raise FuseOSError(EPERM)

		return 0

	def write(self, path, buf, offset, fh):
		print("  write({}, '{}', offset: {}".format(path, buf, offset))
		if offset is not 0:
			raise FuseOSError(EINVAL)

		val = float(buf)
		print("  => {}".format(val))
		if path == '/radius':
			self.radius = val
		elif path == '/circumference':
			self.radius = val / (2.0 * math.pi)
		elif path == '/pi':
			raise FuseOSError(EBADF)
		else: # huh?
			raise FuseOSError(EBADF)

		return len(buf)

	def get_val(self, var):
		if var == '/radius':
			return 1.0 * self.radius
		elif var == '/circumference':
			return 2.0 * math.pi * self.radius
		elif var == '/pi':
			return math.pi

	def get_val_str(self, var):
		val = self.get_val(var)
		return "{}\n".format(val)

	def create(self, path, mode, fh=None):
#		print("  create({})".format(path))
		raise FuseOSError(EACCES)

	def mknod(self, path, mode, dev):
#		print("  mknod({})".format(path))
		raise FuseOSError(ENOSYS)

	def truncate(self, path, length, fh=None):
#		print("  truncate({})".format(path))
		return length

	def opendir(self, path, fh=None):
#		print("  opendir({})".format(path))
		raise FuseOSError(ENOSYS)

	def readlink(self, path, buf, bufsize):
		if path == '/π':
			return 'pi'

		return ''


def main(mountpoint):
    FUSE(circlefs(), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[1])

# vim: sw=4 ts=4 noexpandtab
