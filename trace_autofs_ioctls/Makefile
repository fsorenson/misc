all: trace_autofs_ioctls

trace_autofs_ioctls: trace_autofs_ioctls.c
	gcc -Wall trace_autofs_ioctls.c -o trace_autofs_ioctls.so -shared -fPIC -rdynamic -ldl -g -fdiagnostics-color=always

test:
	LD_PRELOAD=$(shell pwd)/trace_autofs_ioctls.so /usr/sbin/automount --systemd-service --dont-check-daemon -f

