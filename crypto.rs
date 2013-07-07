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

struct Digest { digest: ~[u8] }

impl Digest {
    fn new(digest: ~[u8]) -> ~Digest { return ~Digest{ digest: digest } }

    fn hexdigest(&self) -> ~str {
        let mut acc = ~"";
        for self.digest.each |&byte| { acc += fmt!("%02x", byte as uint); }
        acc
    }
}

fn hash(data: ~[u8], hash_func: &fn(*u8, libc::c_uint, *u8) -> *u8, len: uint) -> ~Digest {
  unsafe {
    Digest::new(
      vec::from_buf(
        hash_func(
          vec::raw::to_ptr(data),
          data.len() as libc::c_uint, ptr::null()
        ),
        len
      )
    )
  }
}

fn sha1(data: ~[u8]) -> ~Digest {
  unsafe {
    hash(data, crypto::SHA1, 20)
  }
}

fn md5(data: ~[u8]) -> ~Digest {
  unsafe {
    hash(data, crypto::MD5, 16)
  }
}

fn xor_with(subject: &str, val: u8) -> ~[u8] {
  do subject.to_bytes().map |&c| { val ^ c }
}

fn hmac(key: ~str, message: ~str) -> ~str {
  let block_size = 64;

  let computed_key: &str = if key.len() > block_size {
    sha1(key.to_bytes()).hexdigest() // TODO this should be .digest more likely
  } else if key.len() < block_size {
    key + str::from_bytes(vec::from_elem(block_size - key.len(), 0))
  } else {
    key
  };

  let o_key_pad = xor_with(computed_key, 0x5c);
  let i_key_pad = xor_with(computed_key, 0x36);
  let bin_message = message.to_bytes();

  sha1(o_key_pad + sha1(i_key_pad + bin_message).digest).hexdigest()
}

fn main() {
  if core::os::args().len() < 2 { fail!(~"Nothing to hash: supply an argument") }
  io::println(sha1(core::os::args()[1].clone().to_bytes()).hexdigest());
}

#[test]
fn test_sha1() {
  assert_eq!(sha1("testing SHA1".to_bytes()).hexdigest(), ~"a07bb2f7f56b7b47e54fd9e29b4629c8967dde4c");
}

#[test]
fn test_md5() {
  assert_eq!(md5("testing MD5".to_bytes()).hexdigest(), ~"da35df95d34f166890fa759f5e00e94c");
}

#[test]
fn test_hmac() {
  assert_eq!(
    hmac(~"my key", ~"some data to hmac"), 
    ~"331c9bf4d7dc8ad7e9bab2f566c8612042a9f4e2"
  )
}


/*
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
*/
