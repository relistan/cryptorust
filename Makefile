LIB=-lcrypto
CC=clang

crypto: crypto.rs
	rustc -L `pwd` crypto.rs
	./crypto testing123123

all: crypto

test:
	rustc -L `pwd` --test crypto.rs -o cryptotest
	./cryptotest
