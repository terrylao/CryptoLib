# CryptoLib
FreePascal Crypt Library
沿自
CryptoLib4Pascal: Crypto for Modern Object Pascal [![License](http://img.shields.io/badge/license-MIT-green.svg)](https://github.com/Xor-el/CryptoLib4Pascal/blob/master/LICENSE)
========================================
基本上修改了一些，以適應FreePascal。以及我自己的SSH Client 使用，具體改了哪些，我也記不起來。
實際應用上，在我的SSH Client 中正確和OpenSSHD 接上，並無錯誤。
呀，這套沒有RSA，你要用請自行IMPLEMENT。因為SSH 也沒在RSA 了。

Available Algorithms
----------------------------------------

 ### Symmetric Encryption
----------------------------------------
###### Block Ciphers
* `AES (128, 192, and 256)` 

* `Rijndael` 

* `Blowfish`

* `Speck`

###### Stream Ciphers
* `ChaCha`

* `(X)Salsa20` 

##### Block Cipher Modes Of Operation 
----------------------------------------

* `ECB` 

* `CBC` 

* `CFB` 

* `CTR` 

* `CTS` 

* `OFB` 

* `SIC`

##### Block Cipher Padding Schemes 
----------------------------------------

* `ISO 10126-2` 

* `ISO 7816-4` 

* `Bit (ISO/IEC 9797-1)` 

* `PKCS#5` 

* `PKCS#7`
 
* `TBC (Trailing Bit Complement)` 

* `ANSI X9.23` 

* `Zero`

### Asymmetric Cryptography
----------------------------------------

* `DSA`

* `(DET)ECDSA (supported curves: NIST, X9.62, SEC2, Brainpool)`

* `ECNR`

* `ECSchnorr`
 
* `EdDSA (Ed25519, Ed25519Blake2B)`

### Key Agreement/Exchange
----------------------------------------

* `DH`

* `ECDH`

* `ECDHC`
 
* `X25519` 

### Key Derivation Functions
----------------------------------------

* `HKDF` 
 
* `KDF1`

* `KDF2`

###### Password Hashing Schemes (Password Based Key Derivation Functions)
----------------------------------------

* `PBKDF2`
 
* `Argon2 (2i, 2d and 2id variants)`

* `Scrypt`

### MAC
----------------------------------------

* `HMAC (all supported hashes)`

* `KMAC (KMAC128, KMAC256)`

### Hashes
----------------------------------------

 * `MD2`

 * `MD4`

 * `MD5`

 * `SHA-1`

 * `SHA-2 (224, 256, 384, 512, 512-224, 512-256)`

 * `Gost3411`

 * `Gost3411-2012 (256, 512)`

 * `RIPEMD (128, 160, 256, 256, 320)`

 * `Tiger`

 * `WhirlPool`

 * `Blake2B (160, 256, 384, 512)`
 
 * `Blake2S (128, 160, 224, 256)`

 * `SHA-3 (224, 256, 384, 512)`
 
 * `Keccak (224, 256, 288, 384, 512)`

### XOF (Extendable Output Function)
----------------------------------------

* `Shake (Shake-128, Shake-256)`

### Other Useful Things
----------------------------------------

* `RNG wrappers for system RNG`

* `ASN1 Parsing Utilities`

* `Base Encoding and Decoding Utilities`

### Compile-Time Dependencies
----------------------------------------

* [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal)
* [SimpleBaseLib4Pascal](https://github.com/Xor-el/SimpleBaseLib4Pascal)

### Supported Compilers
----------------------------------------

* `FreePascal 3.2.0+`

* `Delphi Tokyo+`

### Supported / Tested OSes
----------------------------------------

###### Tested OS boxes are checked
----------------------------------------

* - [x] `Windows XP+`


* - [x] `Linux (Including Android and Raspberry PI)`


* - [x] `Mac OS X`


* - [x] `iOS 2.0+`


* - [x] `(Oracle) Solaris`


* - [x] `OpenBSD`


* - [ ] `FreeBSD`


* - [ ] `NetBSD`


* - [ ] `DragonFlyBSD`
