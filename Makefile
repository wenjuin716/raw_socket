EXEC = raw_sock
OBJS = 
CC = gcc
CFLAGS += -Werror

all: $(OBJS) main.c
	$(CC) $(CFLAGS) main.c -o $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXEC)
