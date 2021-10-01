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
 * Test Mask Generating Function mgf1.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class MGFTest {

    /**
     * Test mgf1 on a short 128 bit key and 32 bit hash.
     */
    @Test
    public void testMGF1Sha1() {

        /*
         * k is the octet length of the modulus n and hLen is the octet length of the hash. Seed has to be the same
         * length as the hash length.
         */

        int k = 128 / 8, hLen = 32 / 8, maskLen = k - hLen - 1;
        BigInteger testSeed = new BigInteger("61297663");
        byte[] seed = Crypt.I2OSP(testSeed, 4);
        byte[] dbMask = new MGF().generateMask(seed, maskLen);
        BigInteger dbMaskInteger = Crypt.OS2IP(dbMask);
        BigInteger expected = new BigInteger("58227699098146415120695771");
        assertEquals(expected, dbMaskInteger);
    }
}
