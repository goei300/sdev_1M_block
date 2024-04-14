LDLIBS= -lnetfilter_queue

all: nfqnl_test preprocessing

nfqnl_test.o: nfqnl_test.c

preprocessing.o: preprocessing.c

nfqnl_test: nfqnl_test.o
preprocessing: preprocessing.o

clean:
	rm -f nfqnl_test
	rm -f preprocessing
	rm -f nfqnl_test.o
	rm -f preprocessing.o