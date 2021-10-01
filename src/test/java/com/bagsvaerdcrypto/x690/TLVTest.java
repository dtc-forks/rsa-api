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
 * Test tag-length-value building block.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class TLVTest {

    @Test
    public void testEncodeLengthZero() {
        byte[] l = TLV.encodeLength(0);
        assertEquals(1, l.length);
        assertEquals(0, l[0]);
    }

    @Test
    public void testEncodeLengthShortFormat() {

        // 127 must encode in short format.

        byte[] l = TLV.encodeLength(127);
        assertEquals(1, l.length);
        assertEquals(127, l[0]);
    }

    @Test
    public void testEncodeLengthLongFormat() {

        // 128 must encode in long format.

        byte[] l = TLV.encodeLength(128);
        assertEquals(2, l.length);
        assertEquals((byte) 0x81, l[0]); // bit 8 set and bit 7-1 is the length of the length octets that follow.
        assertEquals((byte) 0x80, l[1]); // 128 unsigned byte

        // 256 must encode in the long format.

        l = TLV.encodeLength(256);
        assertEquals(3, l.length);
        assertEquals((byte) 0x82, l[0]); // bit 8 set and bit 7-1 is the length of the length octets that follow.
        assertEquals((byte) 0x01, l[1]); // 0x100 = 256.
        assertEquals((byte) 0x00, l[2]);
    }

}