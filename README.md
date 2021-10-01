# Bagsværd Crypto RSA API

Bagsværd Crypto RSA API implements a subset of IETF RFC 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2".

## Design goals

* Implement encryption and signing features of IETF RFC 8017 with OAEP and PSS padding.
* Sourcecode speaks the "language" of RFC 8017 when possible to make assessment of correctness easier.
* Lightweight with few or no dependencies other than the Java Standard API. 
* Is not a JCA provider and does not publish security primitives from JCA through its own public API.
* Limited support for PKCS1 and PKCS8 ASN.1 key schemas and X.690 DER encoding and decoding of keys.

### Limitations

* Limited to two prime factors P and Q.
* Legacy crypto schemes using EME-PKCS1-v1_5 and EMSA-PKCS1-v1_5 padding are not supported.

### Extensions

* Imposes additional constraints on generated public and private keys.
* Implements blinding of private exponent d.

## License

Bagsværd Crypto RSA API is subject to the terms of the GNU General Public License Version 2 with "Classpath" exception. 
The terms are listed in the LICENSE file that accompanies this work. You may not distribute and/or use this code except 
in compliance with the license.

## Build

Requires Java 11 and Maven 3.

`mvn package`

## Generate Javadoc

`mvn javadoc:javadoc`

## Use

### Generate RSA keys

The default key factory uses Carmichael's Lambda Function as prescribed by RFC 8017.

```java
    KeyPair keyPair = KeyFactory.getInstance().generateKeyPair(2048);
    PublicKey publicKey = keyPair.getPublicKey();
    PrivateKey privateKey = keyPair.getPrivateKey();
```
Euler's Phi Function can be used alternatively by specifying the KeyFactoryAlgorithm. 
```java
    KeyPair keyPair = KeyFactory.getInstance(KeyFactoryAlgorithm.EULER).generateKeyPair(2048);
```

### Encrypt

The following snippet shows how to encrypt a message M with a public key to produce a ciphertext C.

```java
    byte[] M = "secret message".getBytes(UTF_8);
    Crypt crypt = Crypt.getInstance(HashAlgorithm.SHA256);
    byte[] C = crypt.encrypt(publicKey, M);
```

Encryption uses OAEP padding with one of the RFC 8017 approved hash function such as SHA256 and the default mask 
generating function MGF1-SHA1.

### Decrypt

This snippet shows how to decrypt a ciphertext C with a private key to produce a plaintext m. 

```java
    byte[] m = crypt.decrypt(privateKey, C);    
    String M = new String(m, UTF_8);
```

The default Crypt implementation uses the Chinese Remainder Theorem when decrypting for speed and blinds the private
exponent with a method based on Paul C. Kocher's *"Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and 
Other Systems"*

### Sign

This snippet shows how to sign a message M with a private key to produce a signature S.

```java
    byte[] M = "message to be signed".getBytes(UTF_8);
    Signature signature = Signature.getInstance(new SignatureParameterPssImpl(HashAlgorithm.SHA256, HashAlgorithm.SHA256, 20));
    signature.update(M);
    byte[] S = signature.sign(privateKey);
```

The signature implementation uses PSS padding with one of the RFC 8017 approved hash functions and the mask generating
function MGF1 with another of the approved hash functions and a salt length.

It implements the Chinese Remainder Theorem for speed and blinds the private exponent with a method based on 
Paul C. Kocher's *"Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems"*

### Verify

The following snippet verifies the signature S of message M with a public key.

```java
   Signature signature = Signature.getInstance(new SignatureParameterPssImpl(HashAlgorithm.SHA256, HashAlgorithm.SHA256, 20));
   signature.update(M);
   boolean verified = signature.verify(publicKey, S);
```

### Encode private key

This snippet shows how to structure a private key according to the ASN.1 schema in PKCS #8 
*"Private-Key Information Syntax Specification Version 1.2"* and encode it with X.690 DER.

```java
    byte[] encodedPrivateKey = privateKey.encode(PrivateKeyEncodingScheme.DER_PKCS8);
```

### Decode private key

The following snippet shows how to decode a private key that has been structured according the ASN.1 schema
in PKCS #8 *"Private-Key Information Syntax Specification Version 1.2"* and encoded with X.690 DER.

```java
   KeyFactory keyFactory = KeyFactory.getInstance();
   KeyPair keyPair = keyFactory.decodePrivateKey(encodedPrivateKey, PrivateKeyEncodingScheme.DER_PKCS8);
   PrivateKey privateKey = keyPair.getPrivateKey();
```

Despite its title, PKCS #8 also holds the public key, which is why a KeyPair is returned. 

### Encode public key

Public keys can be structured according to the ASN.1 schema in PKCS #1 and X.690 DER encoded.

```java
    byte[] encodedPublicKey = publicKey.encode(PublicKeyEncodingScheme.DER_PKCS1);
```

### Decode public key

This snippet shows how to decode a public key that was structured according to the ASN.1 schema in PKCS #1 and
encoded with X.690 DER.

```java
    KeyFactory keyFactory = KeyFactory.getInstance();
    PublicKey publicKey = keyFactory.decodePublicKey(encodedPublicKey, PublicKeyEncodingScheme.DER_PKCS1);
```
