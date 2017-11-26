all:
	clang++-4.0 -c -g -O2 -std=c++11 *.cpp -I.
	ar rv libFuzzer.a Fuzzer*.o
	rm Fuzzer*.o
