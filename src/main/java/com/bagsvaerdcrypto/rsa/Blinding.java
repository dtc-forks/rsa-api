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
 * Blinding prevents timing attacks on operations that use the private key.
 * <br>
 * Based on method described in Paul C. Kocher "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other
 * Systems".
 *
 * @author Søren Thalbitzer Poulsen
 */
class Blinding {

    /*
     * Secure random is thread safe.
     */
    private static final SecureRandom rnd = new SecureRandom();

    /**
     * KeyFactory is used to derive the RSA exponent e from d.
     */
    private static final KeyFactory keyFactory = KeyFactory.getInstance(KeyFactoryAlgorithm.CARMICHAEL);

    /**
     * "vf" is used to blind a ciphertext.
     */
    private BigInteger vf;

    /**
     * "vi" is used to unblind a cipherstext.
     */
    private BigInteger vi;

    /**
     * RSA modulus n.
     */
    private BigInteger n;

    /**
     * When "vf" and "vi" have been used they are marked dirty and will be updated on next use.
     */
    private boolean dirty = false;

    /**
     * Construct Blinding.
     *
     * @param K RSA private key.
     */
    public Blinding(PrivateKey K) {
        BigInteger e = K.getE();
        if (e == null || e.equals(BigInteger.ZERO)) {
            e = keyFactory.derivePublicKey(K).getE();
        }
        this.n = K.getN();

        /*
         * "Choose a random 'vf' relative prime to n". Note: override to make it relative prime to Carmichael's lambda
         * function to make sure it has a modular inverse. This forces us to only support full RSA private keys where
         * primes P and Q are valid.
         */

        BigInteger pOne = K.getP().subtract(BigInteger.ONE), qOne = K.getQ().subtract(BigInteger.ONE);
        BigInteger lambda = BigMath.lcm(pOne, qOne);
        BigInteger eUpperBound = K.getN().subtract(BigInteger.ONE);
        do {
            vf = new BigInteger(eUpperBound.bitLength(), rnd);
        }
        while (!vf.testBit(0) || vf.compareTo(BigInteger.ONE) < 0 || vf.compareTo(eUpperBound) > 0 || !vf.gcd(lambda).equals(BigInteger.ONE));

        /*
         * "Compute vi = (vf^-1)^e mod n".
         */

        vi = vf.modInverse(n).modPow(e, n);
    }

    /**
     * Blind input x.
     *
     * @param x Input message to be blinded.
     * @return Blinded ciphertext.
     */
    public BigInteger blind(BigInteger x) {

        if (dirty) {

            /*
             * Compute vf' = vf^2 mod n, vi' = vi^2 mod n for repeated blinding of the same private key K. This is
             * faster than creating a new Blinding instance every time.
             */

            vf = vf.modPow(BigInteger.TWO, n);
            vi = vi.modPow(BigInteger.TWO, n);
        }

        /*
         * "Before the modular exponentiation operation, the input message should be multiplied by vi mod n".
         */

        BigInteger b = x.multiply(vi).mod(n);
        dirty = true;
        return b;
    }

    /**
     * Unblind message b.
     *
     * @param b Message to be unblinded.
     * @return Unblinded ciphertext.
     */
    public BigInteger unblind(BigInteger b) {

        /*
         * "Afterwards the result is corrected by multiplying with vf mod n".
         */

        return b.multiply(vf).mod(n);
    }

}
