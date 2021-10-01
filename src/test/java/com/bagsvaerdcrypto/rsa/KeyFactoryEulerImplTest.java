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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test Euler key factory impl.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class KeyFactoryEulerImplTest extends KeyFactoryEulerImpl {

    /**
     * Test that the exponent e of value 65537 is a coprime of Euler's Phi function.
     */
    @Test
    public void testDefautlE() {
        int nlen = 2048;
        BigInteger p = BigInteger.probablePrime(nlen / 2, rnd);
        BigInteger q = BigInteger.probablePrime(nlen / 2, rnd);
        BigInteger pOne = p.subtract(BigInteger.ONE), qOne = q.subtract(BigInteger.ONE);
        BigInteger phi = pOne.multiply(qOne);
        BigInteger e = BigInteger.valueOf(65537);
        assertEquals(BigInteger.ONE, e.gcd(phi));
    }

}
