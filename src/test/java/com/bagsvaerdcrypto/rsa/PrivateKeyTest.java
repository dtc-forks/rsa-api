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

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test private key.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PrivateKeyTest {

    @Test
    public void testEncodePkcs1() {
        KeyFactory kfac = KeyFactory.getInstance();
        KeyPair keyPair = kfac.generateKeyPair(2048);
        byte[] encodedPK = keyPair.getPrivateKey().encode(PrivateKeyEncodingScheme.DER_PKCS1);
    }

    /**
     * Test that private keys encoded with Bagsværd Crypto can load with Java's standard API
     */
    @Test
    public void testEncodePkcs8AgainstStdAPI() {

        /*
         * Create a private keyk with Bagsværd Crypto.
         */

        KeyFactory kfac = KeyFactory.getInstance();
        PrivateKey nativePriKey = kfac.generateKeyPair(2048).getPrivateKey();

        /*
         * PKCS8 encode private key with Bagsværd Crypto.
         */

        byte[] encodedPK = nativePriKey.encode(PrivateKeyEncodingScheme.DER_PKCS8);

        /*
         * Load the encoded key into Java's standard API
         */

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedPK);
        RSAPrivateKey priKey = null;
        try {
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            priKey = (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail();
        }

        /*
         * Check the private key is intact.
         */

        assertEquals(nativePriKey.getN(), priKey.getModulus());
        assertEquals(nativePriKey.getD(), priKey.getPrivateExponent());
    }
}
