CC     = gcc
CFLAGS = -O3 -march=native -funroll-loops -fomit-frame-pointer

SRC_DIR   = src
TEST_DIR  = tests

BIN_TEST   = $(TEST_DIR)/test_simac
BIN_BENCH  = $(TEST_DIR)/bench
BIN_STRESS = $(TEST_DIR)/slimiron_stress

all: $(BIN_TEST) $(BIN_BENCH) $(BIN_STRESS)

$(BIN_TEST): $(TEST_DIR)/test_simac.c $(SRC_DIR)/slimiron.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/test_simac.c

$(BIN_BENCH): $(TEST_DIR)/bench.c $(SRC_DIR)/slimiron.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $(TEST_DIR)/bench.c

$(BIN_STRESS): $(TEST_DIR)/slimiron_stress.c
	$(CC) -O2 -march=native -pthread -o $@ $(TEST_DIR)/slimiron_stress.c

run-test: $(BIN_TEST)
	./$(BIN_TEST)

run-bench: $(BIN_BENCH)
	./$(BIN_BENCH)

run-stress: $(BIN_STRESS)
	./$(BIN_STRESS)

clean:
	rm -f $(BIN_TEST) $(BIN_BENCH) $(BIN_STRESS)
