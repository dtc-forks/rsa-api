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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test OID.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class OIDTest extends OID {

    static final String rsaOID = "1.2.840.113549.1.1.1";

    static byte[] rsaOIDEncoded = new byte[]{0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01};

    /**
     * Test DER encoding of real RSA OID.
     */
    @Test
    public void testOIDEncoding() {
        OID oid = new OID(rsaOID);
        byte[] encoded = oid.getEncoded();
        assertArrayEquals(rsaOIDEncoded, encoded);
    }

    /**
     * Test OID that is too short.
     */
    @Test
    public void testOIDTooShort() {
        try {
            OID oid = new OID("1");
        } catch (OIDException e) {
            assertTrue(true);
        }
    }

    /**
     * Test OID with first component that is greater than 2.
     */
    @Test
    public void testOIDFirstCompTooLarge() {
        try {
            OID oid = new OID("3.1");
        } catch (OIDException e) {
            assertTrue(true);
        }
    }

    /**
     * Test OID with second component that is greater than 39.
     */
    @Test
    public void testOIDSecondCompTooLarge() {
        try {
            OID oid = new OID("2.40");
        } catch (OIDException e) {
            assertTrue(true);
        }
    }

    /**
     * Test encoding of single component that is contained in one byte and encodes to a single 7 bit slice. The
     * remaining bit 8 is identified as a zero and is not encoded.
     */
    @Test
    public void testEncodeOne7bitSlice() {
        byte[] bytes = encodeComponent(88);
        assertEquals(1, bytes.length);
        assertEquals(88, bytes[0]);
    }

    /**
     * Test encoding of a single component that is contained in one byte but encoded in two 7 bit slices because bit
     * 8 of the component is 1.
     */
    @Test
    public void testEncodeOneByteWithTwoSlices() {
        byte[] bytes = encodeComponent(0b11111111);
        assertEquals(2, bytes.length);
        assertEquals((byte) 0b10000001, bytes[0]);
        assertEquals(0b01111111, bytes[1]);
    }

    /**
     * Test slicing first 7 bits from a single byte.
     */
    @Test
    public void testSlice7BitFirstByte() {
        byte[] bytes = DERInteger.toCompactByteArray(290);
        byte b1 = slice7bit(7, bytes);
        assertEquals(34, b1);

        bytes = DERInteger.toCompactByteArray(255);
        byte b = slice7bit(7, bytes);
        assertEquals(127, b);
    }

    /**
     * Test slicing bit 14 to 7 of multibyte array.
     */
    @Test
    public void testSlice7BitFromBit14MultiByte() {
        byte[] bytes = DERInteger.toCompactByteArray(290);
        byte slice = slice7bit(14, bytes);
        assertEquals(2, slice);

        bytes = DERInteger.toCompactByteArray(1472);
        slice = slice7bit(14, bytes);
        assertEquals(11, slice);
    }

    /**
     * Test slicing bit 21 to 14 of multibyte array.
     */
    @Test
    public void testSlice7BitFromBit21MultiByte() {
        byte[] bytes = DERInteger.toCompactByteArray(68811);
        byte slice = slice7bit(21, bytes);
        assertEquals(4, slice);
    }
}
