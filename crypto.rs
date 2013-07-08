extern mod std;

use std::{io, vec, ptr, os};
use std::libc::{c_uint};

mod crypto {
  use std::libc::{c_uint};
#[link_args = "-lcrypto"]
  extern { 
    fn SHA1(src: *u8, sz: c_uint, out: *u8) -> *u8;
    fn MD5(src: *u8, sz: c_uint, out: *u8) -> *u8;
    fn SHA224(src: *u8, sz: c_uint, out: *u8) -> *u8;
    fn SHA256(src: *u8, sz: c_uint, out: *u8) -> *u8;
    fn SHA384(src: *u8, sz: c_uint, out: *u8) -> *u8;
    fn SHA512(src: *u8, sz: c_uint, out: *u8) -> *u8;
  }
}

enum HashMethod { MD5, SHA1, SHA224, SHA256, SHA384, SHA512 }

struct HashEngine {
  engine:      (extern "C" unsafe fn(*u8, c_uint, *u8) -> *u8),
  digest_size: uint,
  block_size:  uint
}

impl HashEngine {
  fn new(engine: HashMethod) -> ~HashEngine {
    match engine {
      MD5    => ~HashEngine{ engine: crypto::MD5,    digest_size: 16, block_size: 64  },
      SHA1   => ~HashEngine{ engine: crypto::SHA1,   digest_size: 20, block_size: 64  },
      SHA224 => ~HashEngine{ engine: crypto::SHA224, digest_size: 28, block_size: 64  },
      SHA256 => ~HashEngine{ engine: crypto::SHA256, digest_size: 32, block_size: 64  },
      SHA384 => ~HashEngine{ engine: crypto::SHA384, digest_size: 48, block_size: 64  },
      SHA512 => ~HashEngine{ engine: crypto::SHA512, digest_size: 64, block_size: 128 }
    }
  }

  fn hash(&self, data: ~[u8]) -> ~Digest {
    let hash_func = self.engine;
    Digest::new(
      unsafe {
        vec::from_buf(
          hash_func(
            vec::raw::to_ptr(data),
            data.len() as c_uint, ptr::null()
          ),
          self.digest_size
        )
      }
    )
  }

  fn hmac(&self, key: ~[u8], message: ~[u8]) -> ~Digest {
    let computed_key = match key.len() {
      _ if key.len() > self.block_size => self.zero_pad(self.hash(key).digest),
      _ if key.len() < self.block_size => self.zero_pad(key),
      _ => key
    };
  
    let o_key_pad = HashEngine::xor_with(computed_key, 0x5c);
    let i_key_pad = HashEngine::xor_with(computed_key, 0x36);
  
    self.hash(o_key_pad + self.hash(i_key_pad + message).digest)
  }

  priv fn xor_with(subject: &[u8], val: u8) -> ~[u8] {
    do subject.map |&c| { val ^ c }
  }

  priv fn zero_pad(&self, subject: ~[u8]) -> ~[u8] {
  	subject + vec::from_elem(self.block_size - subject.len(), 0)
  }
}

struct Digest { digest: ~[u8] }

impl Digest {
  fn new(digest: ~[u8]) -> ~Digest { return ~Digest{ digest: digest } }

  fn hexdigest(&self) -> ~str {
    let mut acc = ~"";
    for self.digest.iter().advance |&byte| { acc = acc.append(fmt!("%02x", byte as uint)); }
    acc
  }
}

fn sha1(data: ~[u8]) -> ~Digest {
  HashEngine::new(SHA1).hash(data)
}

fn sha224(data: ~[u8]) -> ~Digest {
  HashEngine::new(SHA224).hash(data)
}

fn sha256(data: ~[u8]) -> ~Digest {
  HashEngine::new(SHA256).hash(data)
}

fn sha384(data: ~[u8]) -> ~Digest {
  HashEngine::new(SHA384).hash(data)
}

fn sha512(data: ~[u8]) -> ~Digest {
  HashEngine::new(SHA512).hash(data)
}

fn md5(data: ~[u8]) -> ~Digest {
  HashEngine::new(MD5).hash(data)
}

fn hmac_md5(key: ~[u8], message: ~[u8]) -> ~Digest {
  HashEngine::new(MD5).hmac(key, message)
}

fn hmac_sha1(key: ~[u8], message: ~[u8]) -> ~Digest {
  HashEngine::new(SHA1).hmac(key, message)
}

fn hmac_sha256(key: ~[u8], message: ~[u8]) -> ~Digest {
  HashEngine::new(SHA256).hmac(key, message)
}

fn hmac_sha512(key: ~[u8], message: ~[u8]) -> ~Digest {
  HashEngine::new(SHA512).hmac(key, message)
}

fn main() {
  if os::args().len() < 2 { fail!(~"Nothing to hash: supply an argument") }
  let args = ~os::args();
  io::println(sha1(args[1].as_bytes().to_owned()).hexdigest());
}

#[test]
fn test_sha1() {
  assert_eq!(sha1("testing SHA1".as_bytes().to_owned()).hexdigest(), ~"a07bb2f7f56b7b47e54fd9e29b4629c8967dde4c");
}

#[test]
fn test_md5() {
  assert_eq!(md5("testing MD5".as_bytes().to_owned()).hexdigest(), ~"da35df95d34f166890fa759f5e00e94c");
}

#[test]
fn test_hmac_sha1_with_a_64_byte_key() {
  assert_eq!(
    hmac_sha1("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(), 
    ~"d6264ce636b593e6c5b43c90ec4ca3550032c99f"
  )
}

#[test]
fn test_hmac_sha1_with_a_too_long_key() {
  assert_eq!(
    hmac_sha1("keyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(), 
    ~"4361f0a10ae7fc1ce33d2795e998d0e526a38815"
  )
}

#[test]
fn test_hmac_sha1_with_a_too_short_key() {
  assert_eq!(
    hmac_sha1("my key".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(), 
    ~"331c9bf4d7dc8ad7e9bab2f566c8612042a9f4e2"
  )
}

#[test]
fn test_hmac_sha256() {
  assert_eq!(
    hmac_sha256("my key".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(),
    ~"17764a8a2e8c23ae3b9e1781c5ebeb5754c7920806021032e9133051e10118be"
  );
}

#[test]
fn test_hmac_sha512() {
  assert_eq!(
    hmac_sha512("my key".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(),
    ~"b54973feba2e436c4f0911855c80e7320d72edd37b359d6474d714718c52775f163832b79214e9fa9d400208d21372a465b2cda2a1d5ab488bbc02b0daea9626"
  );
}

#[test]
fn test_hmac_md5() {
  assert_eq!(hmac_md5("my key".as_bytes().to_owned(), "some data to hmac".as_bytes().to_owned()).hexdigest(), ~"befd13e00ee07549520ade402c664a3a");
}
