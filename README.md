cryptorust
==========
This is a work in progress to give some purpose to my experimentation
with Rust. Currently this wraps OpenSSL hashing functions and
implements HMAC in native Rust code. I'll be looking to expand the
functionality as I learn the language.

There is currently a flaw with this which is that the OpenSSL hash
functions are not thread-safe without implementing the callbacks to
locking in OpenSSL. Because the Rust test runner is very 
multi-threaded, there are occasional test failures as the tests
stomp on each others' use of the buffer.  I am looking at how to
implement the hashing functions in native Rust.
