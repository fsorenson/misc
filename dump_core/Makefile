CC = gcc
CFLAGS = -Wall -O0 -g
TARGET = dump_core

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $< -lm

clean:
	rm -f $(TARGET)
