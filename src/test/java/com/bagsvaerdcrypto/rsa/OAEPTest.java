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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test OAEP.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class OAEPTest {

    /**
     * Test that padding and unpadding returns the same message.
     */
    @Test
    public void testPadUnpadMgf1Sha1() {
        String msg = "secret message";
        OAEP oaep = new OAEP(HashAlgorithm.SHA256);
        int k = 1024 / 8;
        byte[] pad = oaep.encode(msg.getBytes((StandardCharsets.UTF_8)), k);
        assertEquals(k, pad.length);
        assertEquals(0, pad[0]);
        byte[] unpad = oaep.decode(pad, k);
        assertEquals(msg, new String(unpad, StandardCharsets.UTF_8));
    }

    /**
     * Test the sha1 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha1OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA1;
        testShaOfEmptyStringL(hashAlgo);
    }

    /**
     * Test the sha256 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha256OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA256;
        testShaOfEmptyStringL(hashAlgo);
    }

    /**
     * Test the sha384 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha384OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA384;
        testShaOfEmptyStringL(hashAlgo);
    }

    /**
     * Test the sha512 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha512OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA512;
        testShaOfEmptyStringL(hashAlgo);
    }

    /**
     * Test the sha512_224 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha512_224OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA512_224;
        testShaOfEmptyStringL(hashAlgo);
    }

    /**
     * Test the sha512_256 hardcoded in OAEP for the optional string L which is empty.
     */
    @Test
    public void testSha512_256OfEmptyStringL() {
        HashAlgorithm hashAlgo = HashAlgorithm.SHA512_256;
        testShaOfEmptyStringL(hashAlgo);
    }

    private void testShaOfEmptyStringL(HashAlgorithm hashAlgo) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(hashAlgo.getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
        byte[] stdHashOfEmptyString = md.digest();
        byte[] oaepHashOfEmptyL = OAEP.getHashOfOptionalL(hashAlgo);
        assertTrue(MessageDigest.isEqual(stdHashOfEmptyString, oaepHashOfEmptyL));
    }
}
