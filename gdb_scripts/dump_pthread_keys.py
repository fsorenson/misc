#!/usr/bin/env python

# from bugzilla 2162939

pthread_keys = gdb.parse_and_eval('__pthread_keys')
pthread_keys.fetch_lazy()
pthread_keys_range = pthread_keys.type.range()
space = gdb.current_progspace()
for i in range(pthread_keys_range[0], pthread_keys_range[1] + 1):
    k = pthread_keys[i]
    seq = k['seq']
    destr = k['destr']
    if k['seq'] != 0 or k['destr'] != 0:
        soname = space.solib_name(int(destr))
        print("[{}:{}] {} ({})".format(i, seq, destr, soname))


# vim: sw=4 ts=4
