CC = gcc
CFLAGS = -O3 -march=native -funroll-loops -fomit-frame-pointer

BIN_TEST = test_simac
BIN_BENCH = bench

all: $(BIN_TEST) $(BIN_BENCH)

$(BIN_TEST): test_simac.c slimiron.h
	$(CC) $(CFLAGS) -o $@ test_simac.c

$(BIN_BENCH): bench.c slimiron.h
	$(CC) $(CFLAGS) -o $@ bench.c

run-test: $(BIN_TEST)
	./$(BIN_TEST)

run-bench: $(BIN_BENCH)
	./$(BIN_BENCH)

clean:
	rm -f $(BIN_TEST) $(BIN_BENCH)