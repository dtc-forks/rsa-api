/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test RSAKeyFactoryCarmichaelImpl.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class KeyFactoryCarmichaelImplTest {

    /**
     * Test range of exponent e and d and modulus n for RANDOM_FIPS.
     */
    @Test
    public void testRangeRandomStrict() {
        KeyPair keys = KeyFactory.getInstance().generateKeyPair(2048, KeyFactorySpec.RANDOM_STRICT);

        BigInteger n = keys.getPublicKey().getN();
        assertEquals(2048, n.bitLength());

        BigInteger e = keys.getPublicKey().getE();
        assertTrue(e.testBit(0));
        assertTrue(e.compareTo(BigInteger.valueOf(2).pow(16)) > 0);
        assertTrue(e.compareTo(BigInteger.valueOf(2).pow(256)) < 0);

        BigInteger d = keys.getPrivateKey().getD();
        assertTrue(d.compareTo(BigInteger.valueOf(2).pow(n.bitLength() / 2)) > 0);
    }

    /**
     * Test that the exponent e of value 65537 is a coprime of Carmichaels lambda function.
     */
    @Test
    public void testDefautlE() {
        SecureRandom rnd = new SecureRandom();
        int nlen = 2048;
        BigInteger p = BigInteger.probablePrime(nlen / 2, rnd);
        BigInteger q = BigInteger.probablePrime(nlen / 2, rnd);
        BigInteger pOne = p.subtract(BigInteger.ONE), qOne = q.subtract(BigInteger.ONE);
        BigInteger lambda = BigMath.lcm(pOne, qOne);
        BigInteger e = BigInteger.valueOf(65537);
        assertEquals(BigInteger.ONE, e.gcd(lambda));
    }
}
