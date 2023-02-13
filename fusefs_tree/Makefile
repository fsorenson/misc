
all: repro_tree walk_tree


repro_tree: repro_tree.c
	gcc -Wall repro_tree.c `pkg-config fuse3 --cflags --libs` -o repro_tree -g

walk_tree: walk_tree.c
	gcc -Wall walk_tree.c -o walk_tree -g
