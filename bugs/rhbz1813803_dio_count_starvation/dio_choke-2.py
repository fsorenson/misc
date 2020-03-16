#!/usr/bin/python

# Frank Sorenson <sorenson@redhat.com>, 2020

from __future__ import print_function

import sys
import os
import time
import signal

DIO_CHILDREN = 10
OPENCLOSE_CHILDREN = 1

def pread(fd, count, pos = 0):
	try:
		return os.pread(fd, count, pos)
	except:
		os.lseek(fd, pos, os.SEEK_SET)
		return os.read(fd, count)

def child_int(signal, frame):
	exit(0)

def dio_child(path):
	signal.signal(signal.SIGINT, child_int)
	fd = os.open(path, os.O_DIRECT|os.O_RDONLY)
	while True:
		buf = pread(fd, 1024*1024, 0)

def oc_child(path):
	signal.signal(signal.SIGINT, child_int)
	while True:
		fd = os.open(path, os.O_RDWR)
		os.close(fd)
		print(".", end='')
		sys.stdout.flush()

if len(sys.argv) is not 2:
	print("usage: {} <path>".format(sys.argv[0]))
	sys.exit(0)

path = sys.argv[1]
if not os.path.exists(path):
	print("error: file '{}' does not exist".format(path))
	sys.exit(0)
if not os.path.isfile(path):
	print("error: '{}' is not a file".format(path))
	sys.exit(0)

children = []
for i in range(0, DIO_CHILDREN):
	cpid = os.fork()
	if cpid == 0:
		dio_child(path)
		sys.exit(0)
	else:
		children.append(cpid)

for i in range(0, OPENCLOSE_CHILDREN):
	cpid = os.fork()
	if cpid == 0:
		oc_child(path)
		sys.exit(0)
	children.append(cpid)

try:
	while True:
		time.sleep(1)
except KeyboardInterrupt:
	for i, cpid in enumerate(children):
		os.waitpid(cpid, 0)
