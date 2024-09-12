all: trace_opens.bpf.o attach_tp




#clang -D__x86_64__ -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -D__TARGET_ARCH_x86_64 -Ix86 -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -target bpf -Wall -O2 -g -c opensnoop.bpf.c -o opensnoop.bpf.o 


vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c >vmlinux.h

ztrace_opens.bpf.o: trace_opens.bpf.c vmlinux.h
	clang -D__x86_64__ -D__KERNEL__ -D__BPF_TRACING__ \
		-D__TARGET_ARCH_x86_64 \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-Wno-tautological-compare -Wno-unknown-warning-option \
		-target bpf -Wall -g -c trace_opens.bpf.c -o trace_opens.bpf.o

trace_opens.bpf.o: trace_opens.bpf.c vmlinux.h
	clang -D__x86_64__ -D__KERNEL__ -D__BPF_TRACING__ \
		-D__TARGET_ARCH_x86_64 \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-Wno-tautological-compare -Wno-unknown-warning-option \
		-target bpf -Wall -O2 -g -c trace_opens.bpf.c -o trace_opens.bpf.o



attach_tp:	attach_tp.c
	gcc -Wall attach_tp.c -o attach_tp -lbcc -lbpf

clean:
	rm -rf /sys/fs/bpf/trace_opens/* ; rmdir /sys/fs/bpf/trace_opens
