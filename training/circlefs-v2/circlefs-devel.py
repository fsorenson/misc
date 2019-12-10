#!/usr/bin/env python3.7

import os
import sys
import time
import math
from errno import *
from stat import S_IFDIR, S_IFREG, S_IFLNK
from fuse import FUSE, Operations, FuseOSError

DEBUG = 0

class circlefs(Operations):

	def __init__(self, **kw):
		self.radius = 0
		print("fuse initialized")

	def __call__(self, op, *args):
		if DEBUG: print(" call: {}".format(op))
		if not hasattr(self, op):
			if DEBUG: print(" op '{}' not found".format(op))
			raise FuseOSError(EFAULT)
		try:
			ret = getattr(self, op)(*args)
		except Exception as e:
			if DEBUG: print(" op '{}' failed with {}".format(op, e))
			raise e
		if DEBUG: print(" {} returned {}".format(op, ret))
		return ret

	def readdir(self, path, fh=None):
		if (DEBUG): print("  readdir({})".format(path))

		# we don't need to support any subdirectories...
		if not path == '/':
			raise FuseOSError(ENOENT)

		dirents = ['.', '..', 'radius', 'diameter', 'circumference', 'pi', 'π' ]
		for dirent in dirents:
			yield dirent

	def getattr(self, path, fh=None):
		if DEBUG: print("  getattr({})".format(path))

		if path in [ '/' ]:
			mode = 0o755 | S_IFDIR
		elif path in [ '/radius' , '/diameter', '/circumference' ]:
			mode = 0o644 | S_IFREG
		elif path in [ '/pi' ]:
			mode = 0o444 | S_IFREG
		elif path in [ '/π' ]:
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

	# return the values as floats
	def get_val(self, var):
		if var == '/radius':
			return 1.0 * self.radius
		if var == '/diameter':
			return 2.0 * self.radius
		if var == '/circumference':
			return 2.0 * math.pi * self.radius
		if var == '/pi':
			return math.pi

	# return the values as strings
	def get_val_str(self, var):
		val = self.get_val(var)
		return "{}\n".format(val)

	def read(self, path, length, offset, fh=None):
		val = self.get_val_str(path)
		if DEBUG: print("  read({}, length: {}, offset: {}, fh: {}): {}".format(path, length, offset, fh, val))

		return val.encode('utf-8')[offset:length]

	def write(self, path, buf, offset, fh=None):
		if DEBUG: print("  write({}, '{}', offset: {}".format(path, buf, offset))

		# don't allow writing at anywhere except the beginning of the file
		# that makes no sense
		if offset is not 0:
			raise FuseOSError(EINVAL)

		val = float(buf)
		if DEBUG: print("  => {}".format(val))

		if path == '/radius':
			self.radius = val
		elif path == '/diameter':
			self.radius = val / 2.0
		elif path == '/circumference':
			self.radius = val / (2.0 * math.pi)
		elif path == '/pi':
			raise FuseOSError(EBADF) # nope, can't change pi
		else: # huh?
			raise FuseOSError(EBADF)

		return len(buf)

	def open(self, path, flags):
		if DEBUG: print("  open({})".format(path))

		if (flags & os.O_CREAT):
			raise FuseOSError(EACCES)

		if (flags & os.O_APPEND) or (flags & os.O_EXCL) or (flags & os.O_DIRECT):
			raise FuseOSError(EINVAL)

		if not path in [ '/radius', '/diameter', '/circumference', '/pi' ]:
			raise FuseOSError(EPERM)

		# from manpage for open(2):
		# EACCES The requested access to the file is not allowed ...
		if path == '/pi':
			# nope, can't truncate pi
			# also can't open with any mode which includes write
			if flags & os.O_TRUNC:
				raise FuseOSError(EACCES)

			# see the manpage for open(2), under the 'File access mode' section
			# for why this is obscure
			open_mode = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
			if open_mode == os.O_WRONLY or open_mode == os.O_RDWR:
				raise FuseOSError(EACCES)

		if (flags & os.O_TRUNC):
			self.radius = 0.0

		if DEBUG: print("successfully opened '{}'".format(path))
		return 0

	def truncate(self, path, length, fh=None):
		if DEBUG: print("  truncate({}, {})".format(path, length))
		if length:
			raise FuseOSError(EINVAL)
		if path == '/pi':
			return EBADF
		self.radius = 0.0
		return length

	def statfs(self, path):
		if DEBUG: print("  statfs({})".format(path))
		return {
			'f_bsize' : 42,
			'f_bfree' : 0,
			'f_bavail' : 0,
			'f_blocks' : 1,
			'f_files' : 1,
			'f_ffree' : 0,
			'f_favail' : 0,
			'f_flag' : 0,
			'f_frsize' : 0,
			'f_namemax' : 255
		}
	def readlink(self, path):
		if path == '/π':
			return 'pi'

		return ''


def main(mountpoint):
	FUSE(circlefs(), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
	main(sys.argv[1])

# vim: sw=4 ts=4 noexpandtab
