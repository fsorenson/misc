EXES = test_inotify_move test_inotify_move-2 test_inotify_move-3 test_inotify_move-4 barebones


FLAGS=-Wall -ggdb3

all: $(EXES)


%.c%: %.c
	gcc $(FLAGS) $< -o $@

#test_inotify_move: test_inotify_move.c
#test_inotify_move.c -o $< $(FLAGS) 2>&1



