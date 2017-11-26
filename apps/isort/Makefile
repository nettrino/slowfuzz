#
# General
#
#
CC=clang-4.0
CXX=clang++-4.0

SRC_DIR=../..

# Use local copy of Fuzzer
LIBFUZZER_SRC=$(SRC_DIR)/Fuzzer
LIBFUZZER_LIB=$(LIBFUZZER_SRC)/libFuzzer.a

DBGFLAGS=-g -ggdb3
CXXFLAGS=-O2 -Wall -std=c++11 -Wno-unused-variable $(DBGFLAGS)
COV_FLAGS=-fsanitize=address -fsanitize-coverage=edge,trace-pc-guard

# Defaults for LibFuzzer
CORPUS=corpus/
OUTPUT=out/
RUNS=-1

TARGET=driver
TARGET_SRC=driver.cpp

.PHONY:all
all: prelim $(TARGET)

prelim:
	rm -f $(TARGET)

# make our modified version of the Fuzzer
fuzzer:
	$(CXX) -c -g -O2 -std=c++11 $(LIBFUZZER_SRC)/*.cpp -I$(LIBFUZZER_SRC)
	ar rv $(LIBFUZZER_SRC)/libFuzzer.a Fuzzer*.o
	rm Fuzzer*.o

$(TARGET): $(TARGET_SRC)
	$(CXX) $(CXXFLAGS) $(COV_FLAGS) $< $(LIBFUZZER_LIB) -o $@

# ./seed corpus/1 `seq -s' ' 0 999`
.PHONY: test
test: $(TARGET)
	rm -rf $(CORPUS) $(OUTPUT) && mkdir -p $(CORPUS) $(OUTPUT) && cp best $(CORPUS) \
		&& ASAN_OPTIONS=halt_on_error=0:coverage=1:coverage_order_pcs=1:coverage_counters=1 \
	./$(TARGET) $(CORPUS) \
	-artifact_prefix=$(OUTPUT) -print_final_stats=1 \
	-detect_leaks=0 -rss_limit_mb=10000 -shuffle=0 \
	-runs=1000 -max_len=64 -death_mode=1

.PHONY: tools
tools:
	$(CXX) -o print tools/print.cpp
	$(CXX) -o seed tools/seed.cpp

time:
	$(CXX) -o time_test tests/time_test.cpp -I.


ins: tests/ins_test.cpp
	$(CXX) -c -g -O2 -std=c++11 tests/ins_test.cpp -o tests/ins_test.o
	$(CXX) $(CXXFLAGS) $(COV_FLAGS) tests/ins_test.o -o ins_test
	rm tests/ins_test.o

.PHONY:clean
clean:
	rm -rf *.o *.a $(TARGET) qtable.bin print seed time_test ins_test

.PHONY:cleanf
cleanf:
	rm $(LIBFUZZER_LIB)
