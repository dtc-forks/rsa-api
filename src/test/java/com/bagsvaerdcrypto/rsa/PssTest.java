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
 * Probabilistic Signing Scheme test.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PssTest {

    /**
     * Test encode and decode with a PSS sha1 hash, MGF sha1 hash and salt of 20 octets.
     */
    @Test
    public void testEncodeDecodeSha1Salt20() {

        String M = "hello world";
        HashAlgorithm pssHashAlgo = HashAlgorithm.SHA1;
        HashAlgorithm mgfHashAlgo = HashAlgorithm.SHA1;
        int sLen = 20;
        MessageDigest mHash = null;
        try {
            mHash = MessageDigest.getInstance(pssHashAlgo.getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
        mHash.update(M.getBytes(StandardCharsets.UTF_8));
        PSS pss = new PSS(new SignatureParameterPssImpl(pssHashAlgo, mgfHashAlgo, sLen));
        byte[] encoded = pss.encode(mHash.digest(), 2048 - 1);
        assertEquals(256, encoded.length);

        MessageDigest mHash2 = null;
        try {
            mHash2 = MessageDigest.getInstance(pssHashAlgo.getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            fail();
        }

        mHash2.update(M.getBytes(StandardCharsets.UTF_8));
        boolean verified = pss.verify(mHash2.digest(), encoded, 2048 - 1);
        assertTrue(verified);

    }

}
