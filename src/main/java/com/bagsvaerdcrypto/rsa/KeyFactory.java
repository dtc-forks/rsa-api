/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Key factory.
 *
 * @author Søren Thalbitzer Poulsen
 */
public abstract class KeyFactory {

    /*
     * SecureRandom is threadsafe.
     */
    protected static SecureRandom rnd = new SecureRandom();

    /**
     * Minimum length of RSA modulus n for generated keys.
     */
    protected static final int NLEN_MIN = 1024;

    protected KeyFactory() {
    }

    /**
     * Get instance of default KeyFactory. The Default KeyFactory generates keys using Carmichael's lambda function as
     * specified in RFC 8017.
     *
     * @return Instance of default KeyFactory.
     */
    public static KeyFactory getInstance() {
        return getInstance(KeyFactoryAlgorithm.CARMICHAEL);
    }

    /**
     * Get instance of KeyFactory that implements a specific algorithm for generating keys.
     *
     * @param keyFactoryAlgorithm Key factory algorithm.
     * @return Instance of KeyFactory.
     */
    public static KeyFactory getInstance(KeyFactoryAlgorithm keyFactoryAlgorithm) {
        KeyFactory instance = null;
        switch (keyFactoryAlgorithm) {
            case CARMICHAEL: {
                instance = KeyFactoryCarmichaelImpl.getCarmichaelInstance();
                break;
            }
            case EULER: {
                instance = KeyFactoryEulerImpl.getEulerInstance();
                break;
            }
        }
        return instance;
    }

    /**
     * Create public key.
     *
     * @param e RSA public exponent e.
     * @param n RSA modulus n.
     * @return RSA public key.
     */
    public PublicKey createPublicKey(BigInteger e, BigInteger n) {
        return new PublicKey(e, n);
    }

    /**
     * Create private key.
     *
     * @param d RSA private exponent.
     * @param e RSA public exponent.
     * @param n RSA modulus n.
     * @param p Prime factor p of RSA modulus n.
     * @param q Prime factor q of RSA modulus n.
     * @return RSA private key.
     */
    public PrivateKey createPrivateKey(BigInteger d, BigInteger e, BigInteger n, BigInteger p, BigInteger q) {
        BigInteger pOne = p.subtract(BigInteger.ONE), qOne = q.subtract(BigInteger.ONE);
        BigInteger dP = d.mod(pOne);
        BigInteger dQ = d.mod(qOne);
        BigInteger qInv = q.modInverse(p);
        return new PrivateKeyCrt(d, e, n, p, q, dP, dQ, qInv);
    }

    /**
     * Create private key.
     *
     * @param d    RSA private exponent.
     * @param e    RSA public exponent.
     * @param n    RSA modulus n.
     * @param p    Prime factor p of RSA modulus n.
     * @param q    Prime factor q of RSA modulus n.
     * @param dP   Exponent d in the CRT domain for p.
     * @param dQ   Exponent d in the CRT domain for q.
     * @param qInv CRT coefficient qInv.
     * @return RSA private key.
     */
    public PrivateKey createPrivateKey(BigInteger d, BigInteger e, BigInteger n, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv) {
        return new PrivateKeyCrt(d, e, n, p, q, dP, dQ, qInv);
    }

    /**
     * Generate a new key pair.
     *
     * @param nlen RSA modulus n length in bits.
     * @return Key pair.
     */
    public KeyPair generateKeyPair(int nlen) {
        return generateKeyPair(nlen, KeyFactorySpec.DEFAULT);
    }

    /**
     * Generate a new key pair.
     *
     * @param nlen           RSA modulus n length in bits.
     * @param keyFactorySpec Key factory specification.
     * @return Key pair.
     */
    public abstract KeyPair generateKeyPair(int nlen, KeyFactorySpec keyFactorySpec);

    /**
     * Derive a public key from a private key.
     * <br>
     * Note that the same private exponent d may produce different exponents e depending on whether the Carmichael or
     * Euler key factory is used.
     *
     * @param K RSA private key.
     * @return Derived public key.
     */
    public abstract PublicKey derivePublicKey(PrivateKey K);

    /**
     * Decode a private key.
     * <br>
     * PKCS8, although titled "Private-Key Information Syntax Specification", may contain both a public and private key
     * which is why a KeyPair is returned. The public key may be null depending on the encoding scheme and the
     * actual key.
     *
     * @param key            Encoded private key.
     * @param encodingScheme Key encoding scheme.
     * @return Decoded KeyPair.
     */
    public KeyPair decodePrivateKey(byte[] key, PrivateKeyEncodingScheme encodingScheme) {
        return KeyDecoding.decodePrivateKey(key, encodingScheme);
    }

    /**
     * Decode a public key.
     *
     * @param key            Encoded public key.
     * @param encodingScheme Encoding scheme.
     * @return Decoded public key.
     */
    public PublicKey decodePublicKey(byte[] key, PublicKeyEncodingScheme encodingScheme) {
        return KeyDecoding.decodePublicKey(key, encodingScheme);
    }
}
