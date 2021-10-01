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
 * Test BigMath
 *
 * @author Søren Thalbitzer Poulsen
 */
public class BigMathTest {

    @Test
    public void testLcm() {
        BigInteger lcm = BigMath.lcm(new BigInteger("40"), new BigInteger("45"));
        assertEquals(new BigInteger("360"), lcm);
    }

    @Test
    public void testLcm0() {
        BigInteger lcm = BigMath.lcm(new BigInteger("0"), new BigInteger("45"));
        assertEquals(new BigInteger("0"), lcm);
    }

    @Test
    public void testLcm00() {
        BigInteger lcm = BigMath.lcm(new BigInteger("0"), new BigInteger("0"));
        assertEquals(new BigInteger("0"), lcm);
    }

    @Test
    public void testLcm1() {
        BigInteger lcm = BigMath.lcm(new BigInteger("1"), new BigInteger("45"));
        assertEquals(new BigInteger("45"), lcm);
    }

    @Test
    public void testLcm11() {
        BigInteger lcm = BigMath.lcm(new BigInteger("1"), new BigInteger("1"));
        assertEquals(new BigInteger("1"), lcm);
    }

}
