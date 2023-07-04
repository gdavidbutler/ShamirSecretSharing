CFLAGS = -I. -Os -g

all: sss.o main

clean:
	rm -f sss.o main s1 s2 s3 s4 tst

sss.o: sss.c sss.h
	$(CC) $(CFLAGS) -c sss.c

main: test/main.c sss.h sss.o
	$(CC) $(CFLAGS) -o main test/main.c sss.o

check: main
	./main 0-COPYING 1-test/r1 2-test/r2  1+s1 2+s2 3+s3 4+s4
	./main 1-s1 2-s2 3-s3 4-s4 0+tst
	cmp COPYING tst
	./main 1-s1 2-s2 3-s3 0+tst
	cmp COPYING tst
	./main 1-s1 2-s2 4-s4 0+tst
	cmp COPYING tst
	./main 2-s2 3-s3 4-s4 0+tst
	cmp COPYING tst
