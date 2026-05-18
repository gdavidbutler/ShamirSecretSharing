CFLAGS = -I. -Os -g

all: sss.o main sssMkTest thrDspSssTest

clean:
	rm -f sss.o sssMk.o thrDspSss.o main sssMkTest thrDspSssTest s1 s2 s3 s4 tst

sss.o: sss.c sss.h
	$(CC) $(CFLAGS) -c sss.c

sssMk.o: sssMk.c sssMk.h
	$(CC) $(CFLAGS) -c sssMk.c

main: test/main.c sss.h sss.o
	$(CC) $(CFLAGS) -o main test/main.c sss.o

sssMkTest: test/sssMkTest.c sss.h sssMk.h sss.o sssMk.o ../rmd128/rmd128.o ../sha256/sha256.o
	$(CC) $(CFLAGS) -I../rmd128 -I../sha256 -o sssMkTest test/sssMkTest.c sss.o sssMk.o ../rmd128/rmd128.o ../sha256/sha256.o

# thrDsp adapter: exposes sss + sssMk via the threshold-dispersal
# plugin contract defined by ../asynchronousByzantineAgreementProtocols/
# thrDsp.h (consumed by ABAP's ct04Dsp).  Header-only dependency on
# that sibling repo; no link-time dependency in this direction.
thrDspSss.o: thrDspSss.c thrDspSss.h sss.h sssMk.h ../asynchronousByzantineAgreementProtocols/thrDsp.h
	$(CC) $(CFLAGS) -I../asynchronousByzantineAgreementProtocols -c thrDspSss.c

thrDspSssTest: test/thrDspSssTest.c thrDspSss.o sss.o sssMk.o thrDspSss.h ../asynchronousByzantineAgreementProtocols/thrDsp.h ../rmd128/rmd128.o ../sha256/sha256.o
	$(CC) $(CFLAGS) -I../asynchronousByzantineAgreementProtocols -I../rmd128 -I../sha256 -o thrDspSssTest test/thrDspSssTest.c thrDspSss.o sss.o sssMk.o ../rmd128/rmd128.o ../sha256/sha256.o

check: main sssMkTest thrDspSssTest
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
	./sssMkTest
	./thrDspSssTest
