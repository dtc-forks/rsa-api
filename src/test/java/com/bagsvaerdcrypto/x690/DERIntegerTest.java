/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test DER Integer support class.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class DERIntegerTest {

    /**
     * Test integer to compact byte array
     */
    @Test
    public void testToCompactByteArray() {
        byte[] bytes1 = DERInteger.toCompactByteArray(128);
        assertEquals(1, bytes1.length);
        assertEquals((byte) 0x80, bytes1[0]);

        byte[] bytes2 = DERInteger.toCompactByteArray(255);
        assertEquals(1, bytes2.length);
        assertEquals((byte) 0xFF, bytes2[0]);

        byte[] bytes = DERInteger.toCompactByteArray(256);
        assertEquals(2, bytes.length);
        assertEquals((byte) 1, bytes[0]);
        assertEquals((byte) 0, bytes[1]);
    }

}
