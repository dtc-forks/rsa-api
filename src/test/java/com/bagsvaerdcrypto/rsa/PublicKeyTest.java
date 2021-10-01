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

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test public key.
 *
 * @author Søren Thalbitzer Poulsen.
 */
public class PublicKeyTest {

    /**
     * Test public key DER PKCS11 encoding.
     */
    @Test
    public void testEncodePkcs1() {
        KeyFactory keyFactory = KeyFactory.getInstance();
        KeyPair keyPair = keyFactory.generateKeyPair(2048);
        PublicKey pubKey = keyPair.getPublicKey();
        byte[] encoded = pubKey.encode(PublicKeyEncodingScheme.DER_PKCS1);
        assertNotNull(encoded);
    }
}
