CFLAGS = -I. -Os -g

all: sss.o main

clean:
	rm -f sss.o main s1 s2 s3 s4 tst

sss.o: sss.c sss.h
	$(CC) $(CFLAGS) -c sss.c

main: test/main.c sss.h sss.o
	$(CC) $(CFLAGS) -o main test/main.c sss.o

check: main
	./main 0-COPYING 1-test/r1 2-test/r2 3+s1 4+s2 5+s3 6+s4
	./main 3-s1 4-s2 5-s3 6-s4 1-test/r1 2-test/r2 0+tst
	cmp COPYING tst
	./main 3-s1 1-test/r1 2-test/r2 0+tst
	cmp COPYING tst
	./main 3-s1 6-s4 2-test/r2 0+tst
	cmp COPYING tst
	./main 3-s1 4-s2 5-s3 0+tst
	cmp COPYING tst
	./main 4-s2 5-s3 6-s4 0+tst
	cmp COPYING tst
	./main 5-s3 6-s4 3-s1 0+tst
	cmp COPYING tst
	./main 6-s4 3-s1 4-s2 0+tst
	cmp COPYING tst
