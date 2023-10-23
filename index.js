const module = (() => {
    include("./sjcl/sjcl.js");
    include("./sjcl/convenience.js");
    include("./sjcl/bitArray.js");
    include("./sjcl/codecString.js");
    include("./sjcl/codecBytes.js");
    include("./sjcl/codecBase64.js");
    include("./sjcl/codecBase58.js");
    include("./sjcl/codecBase58Check.js");
    include("./sjcl/codecBytes.js");
    include("./sjcl/codecHex.js");
    include("./sjcl/sha256.js");
    include("./sjcl/sha512.js");
    include("./sjcl/ripemd160.js");
    include("./sjcl/aes.js");
    include("./sjcl/ccm.js");
    include("./sjcl/random.js");
    include("./sjcl/bn.js");
    include("./sjcl/ecc.js");
    include("./sjcl/pbkdf2.js");
    include("./sjcl/scrypt.js");
    include("./sjcl/hmac.js");

    if (!global["__sha3_defined__"]) {
        include("./sha3.js");
        global["__sha3_defined__"] = true;
    }

    const _encrypt_params = {
        "iv": "tjp81jkAzUpW1bI9gLDDpg==", // iv Base64 encoded
        "v": 1,                           // version
        "iter": 1000,                     // iteration count
        "ks": 128,                        // key size in bits
        "ts": 64,                         // authentication strength
        "mode": "ccm",                    // mode
        "cipher": "aes",                  // cipher
        "salt": "lx06UoJDNys=",           // key derivation salt
    }
    
    const _hash = {
        "sha256": sjcl.hash.sha256,
        "sha512": sjcl.hash.sha512,
        "ripemd160": sjcl.hash.ripemd160
    }
    
    sjcl.random.addEntropy(random(1024));

    return {
        sha256: {
            digest: (data) => {
                return sjcl.hash.sha256.hash(data);
            }
        },
        
        sha512: {
            digest: (data) => {
                return sjcl.hash.sha512.hash(data);
            }
        },
        
        ripemd160: {
            digest: (data) => {
                return sjcl.hash.ripemd160.hash(data);
            }
        },
        
        keccak256: {
            digest: (data) => {
                return sjcl.codec.hex.toBits(
                    Sha3.hash256(sjcl.codec.hex.fromBits(data), {
                        "msgFormat":"hex-bytes",
                        "padding":"keccak",
                        "outFormat":"hex"
                    })
                );
            }
        },
        
        hmac: {
            digest: (hash, key, data) => {
                return new sjcl.misc.hmac(key, _hash[hash]).encrypt(data);
            }
        },
        
        pbkdf2: {
            digest: (hash, password, salt, count, length) => {
                return sjcl.misc.pbkdf2(password, salt, count, length, function(key) {
                    return new sjcl.misc.hmac(key, _hash[hash]);
                });
            }
        },
        
        ecdsa: {
            generate_keys: (curve, secret) => {
                return sjcl.ecc.ecdsa.generateKeys(
                    curve, 0, secret
                );
            },
            secret_key: (curve, secret) => {
                return new sjcl.ecc.ecdsa.secretKey(
                    curve, sjcl.bn.fromBits(secret)
                );
            },
            curve_from_name: (name) => {
                return sjcl.ecc.curves[name];
            }
        },
        
        base58: {
            encode: (bits) => {
                return sjcl.codec.base58.fromBits(bits);
            },
            decode: (string) => {
                return sjcl.codec.base58.toBits(string);
            },
            check: {
                encode: (version, bits, checksum_fn) => {
                    return sjcl.codec.base58Check.fromBits(version, bits, checksum_fn);
                },
                decode: (string, checksum_fn) => {
                    return sjcl.codec.base58Check.toBits(string, checksum_fn)
                }
            }
        },
        
        encrypt: (password, plaintext) => {
            return sjcl.encrypt(password, plaintext, _encrypt_params);
        },
        
        decrypt: (password, ciphertext) => {
            return sjcl.decrypt(password, ciphertext);
        },
        
        number_from_bits: (bits) => {
            return sjcl.bn.fromBits(bits);
        },
        
        number_to_bits: (number) => {
            return number.toBits();
        },
        
        number_from_hex: (hex) => {
            return new sjcl.bn(hex);
        },
        
        number_from_value: (value) => {
            return new sjcl.bn(value);
        },
        
        random_number: (modulus, paranoia) => {
            return new sjcl.bn.random(modulus, paranoia);
        },
        
        string_to_bits: (string) => {
            return sjcl.codec.utf8String.toBits(string);
        },
        
        bytes_from_bits: (bits) => {
            return sjcl.codec.bytes.fromBits(bits);
        },
        
        bytes_to_bits: (bytes) => {
            return sjcl.codec.bytes.toBits(bytes);
        },
        
        hex_from_bits: (bits) => {
            return sjcl.codec.hex.fromBits(bits);
        },
        
        hex_to_bits: (hex) => {
            return sjcl.codec.hex.toBits(hex);
        },
        
        bits_from_value: (value) => {
            return new sjcl.bn(value).toBits();   
        },
        
        bits_concat: (bits1, bits2) => {
            return sjcl.bitArray.concat(bits1, bits2);
        },
        
        bits_slice: (bits, start, end) => {
            return sjcl.bitArray.bitSlice(bits, start, end);
        },
        
        bits_extract: (bits, start, length) => {
            return sjcl.bitArray.extract(bits, start, length);
        },
        
        bits_partial: (length, value) => {
            return sjcl.bitArray.partial(length, value);
        },
        
        bits_length: (bits) => {
            return sjcl.bitArray.bitLength(bits);
        },
        
        is_odd_bits: (bits) => {
            return sjcl.bn.fromBits(bits).limbs[0] & 0x1;
        },
        
        version: () => {
            return "1.0";
        },
    }
})();

__MODULE__ = module;
