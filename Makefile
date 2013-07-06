LIB=-lcrypto
CC=clang

crypto: crypto.rs
	rustc -L `pwd` crypto.rs
	./crypto testing123123

cryptobindings:
	$(CC) -Wno-deprecated-declarations cryptobindings.c -g3 -std=c99 -c cryptobindings.c
	$(CC) -lcrypto -shared -Wl -o libcryptobindings.dylib cryptobindings.o

all: cryptobindings crypto

test: cryptobindings
	rustc -L `pwd` --test crypto.rs -o cryptotest
	./cryptotest
