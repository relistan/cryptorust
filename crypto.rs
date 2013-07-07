extern mod std;

enum HashEngine { SHA1, SHA128, SHA224, SHA256, SHA384, SHA512, MD5 }

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
	acc
}

fn hash(data: ~str, hash_func: &fn(*u8, libc::c_uint, *u8) -> *u8, len: uint) -> ~str {
	unsafe {
		let bytes = str::to_bytes(data);
		let hash = hash_func(
			vec::raw::to_ptr(bytes),
			bytes.len() as libc::c_uint, ptr::null()
		);
		as_hex(vec::from_buf(hash, len))
	}
}

fn sha1(data: ~str) -> ~str {
	unsafe {
		hash(data, crypto::SHA1, 20)
	}
}

fn md5(data: ~str) -> ~str {
	unsafe {
		hash(data, crypto::MD5, 16)
	}
}

fn hmac(engine: HashEngine, key: ~str, data: ~str) -> ~str {
	unsafe {
		let mut digest = vec::from_elem(129, 0);
		let key_bytes  = str::to_bytes(key);
		let data_bytes = str::to_bytes(data);

		let result_size = cryptobindings::wrap_HMAC(engine, 
			vec::raw::to_ptr(key_bytes),
			key_bytes.len() as libc::size_t,
			vec::raw::to_ptr(data_bytes),
			data_bytes.len() as libc::size_t,
			vec::raw::to_ptr(digest)
		);

		let result = str::from_bytes(digest);
		result.slice(0, result_size as uint).to_owned()
	}
}

fn xor_with(message: &str, val: u8) -> ~str {
	str::from_bytes(do message.to_bytes().map |&c| { val ^ c })
}

fn hmac_native(key: ~str, message: ~str) -> ~str {
	let block_size = 64;

	let computed_key: &str = if key.len() > block_size {
		sha1(key)
	} else if key.len() < block_size {
		key + str::from_bytes(vec::from_elem(block_size - key.len(), 0))
	} else {
		key
	};

	let o_key_pad = xor_with(computed_key, 0x5c);
	println(o_key_pad);
	let i_key_pad = xor_with(computed_key, 0x36);
	println(i_key_pad);

	sha1(o_key_pad + sha1(i_key_pad + message))
}

#[test]
fn test_hmac_native() {
	assert_eq!(
		hmac_native(~"my key", ~"some data to hmac"), 
		~"331c9bf4d7dc8ad7e9bab2f566c8612042a9f4e2"
	)
}

fn main() {
	if core::os::args().len() < 2 { fail!(~"Nothing to hash: supply an argument") }
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
	assert_eq!(
		hmac(SHA256, ~"my key", ~"some data to hmac"), 
		~"17764a8a2e8c23ae3b9e1781c5ebeb5754c7920806021032e9133051e10118be"
	);
}

#[test]
fn test_hmac_sha512() {
	assert_eq!(
		hmac(SHA512, ~"my key", ~"some data to hmac"), 
		~"b54973feba2e436c4f0911855c80e7320d72edd37b359d6474d714718c52775f163832b79214e9fa9d400208d21372a465b2cda2a1d5ab488bbc02b0daea9626"
	);
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
