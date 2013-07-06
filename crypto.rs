extern mod std;

enum HashEngine { SHA1, SHA128, SHA224, SHA256, SHA512, MD5 }

extern mod crypto {
	fn SHA1(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
	fn MD5(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
}

extern mod cryptobindings {
	fn wrap_HMAC(method: HashEngine, 
		key: *u8, 
		key_size: libc::size_t, 
		data: *u8,
		size: libc::size_t,
		target: *u8) -> libc::c_uint;
}

fn as_hex(data: ~[u8]) -> ~str {
	let mut acc = ~"";
	for data.each |&byte| { acc += fmt!("%02x", byte as uint); }
	return acc;
}

fn sha1(data: ~str) -> ~str {
	unsafe {
		let bytes = str::to_bytes(data);
		let hash = crypto::SHA1(vec::raw::to_ptr(bytes),
								bytes.len() as libc::c_uint, ptr::null());
		as_hex(vec::from_buf(hash, 20))
	}
}

fn md5(data: ~str) -> ~str {
	unsafe {
		let bytes = str::to_bytes(data);
		let hash = crypto::MD5(vec::raw::to_ptr(bytes),
								bytes.len() as libc::c_uint, ptr::null());
		as_hex(vec::from_buf(hash, 16))
	}
}

fn hmac(engine: HashEngine, key: ~str, data: ~str) -> ~str {
	let hmac = unsafe {
		let mut digest = str::to_bytes(~"0123456789012345678901234567890123456789");
		let key_bytes  = str::to_bytes(key);
		let data_bytes = str::to_bytes(data);

		cryptobindings::wrap_HMAC(engine, 
			vec::raw::to_ptr(key_bytes),
			key_bytes.len() as libc::size_t,
			vec::raw::to_ptr(data_bytes),
			data_bytes.len() as libc::size_t,
			vec::raw::to_ptr(digest)
		);

		str::from_bytes(digest).clone()
	};
	hmac
}

fn main() {
	io::println(sha1(core::os::args()[1].clone()));
}

#[test]
fn test_sha1() {
	assert_eq!(sha1(~"testing SHA1"), ~"a07bb2f7f56b7b47e54fd9e29b4629c8967dde4c");
}

#[test]
fn test_md5() {
	assert_eq!(md5(~"testing MD5"), ~"da35df95d34f166890fa759f5e00e94c");
}

#[test]
fn test_hmac_sha1() {
	assert_eq!(hmac(SHA1, ~"my key", ~"some data to hmac"), ~"331c9bf4d7dc8ad7e9bab2f566c8612042a9f4e2");
}

#[test]
fn test_hmac_sha256() {
	assert_eq!(hmac(SHA256, ~"my key", ~"some data to hmac"), ~"17764a8a2e8c23ae3b9e1781c5ebeb5754c79208");
}

#[test]
fn test_hmac_md5() {
	assert_eq!(hmac(MD5, ~"my key", ~"some data to hmac"), ~"befd13e00ee07549520ade402c664a3a");
}

#[test]
fn test_wrap_HMAC() {
	unsafe {
		let mut digest = str::to_bytes(~"0123456789012345678901234567890123456789");
		let key_bytes  = str::to_bytes(~"test key");
		let data_bytes = str::to_bytes(~"testing HMAC");

		cryptobindings::wrap_HMAC(SHA1, vec::raw::to_ptr(key_bytes), 8 as libc::size_t, vec::raw::to_ptr(data_bytes), 12 as libc::size_t, vec::raw::to_ptr(digest));
		assert_eq!(str::from_bytes(digest), ~"9d20c8c35c7ce6b1c4283731bf1fe877d24aa8e7");
	}
}
