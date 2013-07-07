extern mod std;

extern mod crypto {
  fn SHA1(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
  fn MD5(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
  fn SHA224(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
  fn SHA256(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
  fn SHA384(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
  fn SHA512(src: *u8, sz: libc::c_uint, out: *u8) -> *u8;
}

enum HashMethod { MD5, SHA1, SHA224, SHA256, SHA384, SHA512 }

struct HashEngine {
  engine:      (extern unsafe fn(*u8, libc::c_uint, *u8) -> *u8),
  digest_size: uint,
  block_size:  uint
}

impl HashEngine {
  fn by_name(engine: HashMethod) -> ~HashEngine {
    unsafe {
      match engine {
        MD5    => ~HashEngine{ engine: crypto::MD5,    digest_size: 16, block_size: 64  },
        SHA1   => ~HashEngine{ engine: crypto::SHA1,   digest_size: 20, block_size: 64  },
        SHA224 => ~HashEngine{ engine: crypto::SHA224, digest_size: 28, block_size: 64  },
        SHA256 => ~HashEngine{ engine: crypto::SHA256, digest_size: 32, block_size: 64  },
        SHA384 => ~HashEngine{ engine: crypto::SHA384, digest_size: 48, block_size: 64  },
        SHA512 => ~HashEngine{ engine: crypto::SHA512, digest_size: 64, block_size: 128 }
      }
    }
  }

  fn hash(&self, data: ~[u8]) -> ~Digest {
    let hash_func = self.engine;
    Digest::new(
      unsafe {
        vec::from_buf(
          hash_func(
            vec::raw::to_ptr(data),
            data.len() as libc::c_uint, ptr::null()
          ),
          self.digest_size
        )
      }
    )
  }
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

fn hash(engine_name: HashMethod, data: ~[u8]) -> ~Digest {
  let details   = HashEngine::by_name(engine_name);
  let hash_func = details.engine;

  Digest::new(
    unsafe {
      vec::from_buf(
        hash_func(
          vec::raw::to_ptr(data),
          data.len() as libc::c_uint, ptr::null()
        ),
        details.digest_size
      )
    }
  )
}

fn sha1(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(SHA1).hash(data)
  }
}

fn sha224(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(SHA224).hash(data)
  }
}

fn sha256(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(SHA256).hash(data)
  }
}

fn sha384(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(SHA384).hash(data)
  }
}

fn sha512(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(SHA512 ).hash(data)
  }
}

fn md5(data: ~[u8]) -> ~Digest {
  unsafe {
    HashEngine::by_name(MD5).hash(data)
  }
}

fn xor_with(subject: &str, val: u8) -> ~[u8] {
  do subject.to_bytes().map |&c| { val ^ c }
}

fn hmac_md5(key: ~str, message: ~str) -> ~Digest {
  hmac(key, message, 64, md5)
}

fn hmac_sha1(key: ~str, message: ~str) -> ~Digest {
  hmac(key, message, 64, sha1)
}

fn hmac_sha256(key: ~str, message: ~str) -> ~Digest {
  hmac(key, message, 64, sha256)
}

fn hmac_sha512(key: ~str, message: ~str) -> ~Digest {
  hmac(key, message, 128, sha512)
}

fn hmac(key: ~str, message: ~str, block_size: uint, hash_func: &fn(~[u8]) -> ~Digest) -> ~Digest {
  let computed_key: &str = match key.len() {
    _ if key.len() > block_size => hash_func(key.to_bytes()).hexdigest(), // TODO this should be .digest more likely
    _ if key.len() < block_size => key + str::from_bytes(vec::from_elem(block_size - key.len(), 0)),
    _ => key
  };

  let o_key_pad = xor_with(computed_key, 0x5c);
  let i_key_pad = xor_with(computed_key, 0x36);
  let bin_message = message.to_bytes();

  hash_func(o_key_pad + hash_func(i_key_pad + bin_message).digest)
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
fn test_hmac_sha1() {
  assert_eq!(
    hmac_sha1(~"my key", ~"some data to hmac").hexdigest(), 
    ~"331c9bf4d7dc8ad7e9bab2f566c8612042a9f4e2"
  )
}

#[test]
fn test_hmac_sha256() {
  assert_eq!(
    hmac_sha256(~"my key", ~"some data to hmac").hexdigest(),
    ~"17764a8a2e8c23ae3b9e1781c5ebeb5754c7920806021032e9133051e10118be"
  );
}

#[test]
fn test_hmac_sha512() {
  assert_eq!(
    hmac_sha512(~"my key", ~"some data to hmac").hexdigest(),
    ~"b54973feba2e436c4f0911855c80e7320d72edd37b359d6474d714718c52775f163832b79214e9fa9d400208d21372a465b2cda2a1d5ab488bbc02b0daea9626"
  );
}

#[test]
fn test_hmac_md5() {
  assert_eq!(hmac_md5(~"my key", ~"some data to hmac").hexdigest(), ~"befd13e00ee07549520ade402c664a3a");
}
