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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Key factory test.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class KeyFactoryTest {

    /**
     * Test private CRT key decoding.
     */
    @Test
    public void testDecodingPkcs8FullCrtKey() {

        /*
         * Create and encode a private key with Bagsværd Crypto.
         */

        KeyFactory keyFactory = KeyFactory.getInstance();
        PrivateKeyCrt nativePriKey = (PrivateKeyCrt) keyFactory.generateKeyPair(2048).getPrivateKey();
        byte[] encodedPK = nativePriKey.encode(PrivateKeyEncodingScheme.DER_PKCS8);

        /*
         * Decode the private key with Bagsværd Crypto.
         */

        KeyPair keyPair = keyFactory.decodePrivateKey(encodedPK, PrivateKeyEncodingScheme.DER_PKCS8);

        /*
         * Test the decoded key.
         */

        assertNotNull(keyPair);

        PrivateKey decodePriKey = keyPair.getPrivateKey();
        PublicKey decodedPubKey = keyPair.getPublicKey();

        assertNotNull(decodePriKey);
        assertNotNull(decodedPubKey);

        assertEquals(nativePriKey.getN(), decodePriKey.getN());
        assertEquals(nativePriKey.getE(), decodePriKey.getE());
        assertEquals(nativePriKey.getD(), decodePriKey.getD());
        assertEquals(nativePriKey.getP(), decodePriKey.getP());
        assertEquals(nativePriKey.getQ(), decodePriKey.getQ());
        assertEquals(nativePriKey.getLengthInOctets(), decodePriKey.getLengthInOctets());

        assertTrue(decodePriKey instanceof PrivateKeyCrt);
        PrivateKeyCrt decodedPriKeyCrt = (PrivateKeyCrt) decodePriKey;

        assertEquals(nativePriKey.getdP(), decodedPriKeyCrt.getdP());
        assertEquals(nativePriKey.getdQ(), decodedPriKeyCrt.getdQ());
        assertEquals(nativePriKey.getqInv(), decodedPriKeyCrt.getqInv());
    }

    /**
     * Test anemic private key (only d and n defined) decoding. Must reject decoding the key.
     */
    @Test
    public void testDecodingAnemicKey() {

        KeyFactory keyFactory = KeyFactory.getInstance();
        KeyPair keyPair = keyFactory.generateKeyPair(2048);
        PrivateKey priKey = keyPair.getPrivateKey();

        /*
         * Create and encode the anemic key through Java's std API.
         */

        java.security.KeyFactory kf;
        java.security.PrivateKey stdPriKey = null;
        try {
            kf = java.security.KeyFactory.getInstance("RSA");
            stdPriKey = kf.generatePrivate(new RSAPrivateKeySpec(priKey.getN(), priKey.getD()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail();
        }
        byte[] stdKeyEncoded = stdPriKey.getEncoded();

        /*
         * Try to decode the anemic key using Bagsværd Crypto.
         */

        try {
            KeyPair decodedKeyPair = keyFactory.decodePrivateKey(stdKeyEncoded, PrivateKeyEncodingScheme.DER_PKCS8);
        } catch (KeyInvalidException ex) {
            assertTrue(true);
        }
    }

    /**
     * Test native decoding of key created and encoded with Java's Std API.
     */
    @Test
    public void testDecodingAgainstStdAPIKey() {

        /*
         * Generate and encode a private key with Java's std api.
         */

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
        kpg.initialize(2048);

        java.security.KeyPair kp = kpg.generateKeyPair();
        java.security.interfaces.RSAPrivateCrtKey priKey = (java.security.interfaces.RSAPrivateCrtKey) kp.getPrivate();

        byte[] encodedStdPriKey = priKey.getEncoded();
        String format = priKey.getFormat();
        assertEquals("PKCS#8", format);

        /*
         * Decode private key with Bagsværd Crypto.
         */

        KeyFactory keyFactory = KeyFactory.getInstance();
        KeyPair keyPair = keyFactory.decodePrivateKey(encodedStdPriKey, PrivateKeyEncodingScheme.DER_PKCS8);

        /*
         * Test decoded key is intact.
         */

        assertNotNull(keyPair);
        PrivateKey decodedPriKey = keyPair.getPrivateKey();
        assertNotNull(decodedPriKey);
        assertTrue(decodedPriKey instanceof PrivateKeyCrt);
        PrivateKeyCrt decodedPriKeyCrt = (PrivateKeyCrt) decodedPriKey;
        assertEquals(priKey.getModulus(), decodedPriKeyCrt.getN());
        assertEquals(priKey.getPrivateExponent(), decodedPriKeyCrt.getD());
        assertEquals(priKey.getPublicExponent(), decodedPriKeyCrt.getE());
        assertEquals(priKey.getPrimeP(), decodedPriKeyCrt.getP());
        assertEquals(priKey.getPrimeQ(), decodedPriKeyCrt.getQ());
        assertEquals(priKey.getPrimeExponentP(), decodedPriKeyCrt.getdP());
        assertEquals(priKey.getPrimeExponentQ(), decodedPriKeyCrt.getdQ());
        assertEquals(priKey.getCrtCoefficient(), decodedPriKeyCrt.getqInv());
    }

    /**
     * Test public key DER PKCS1 decoding.
     */
    @Test
    public void testDecodingPublicKey() {

        /*
         * Create and encode a public key with Bagsværd Crypto.
         */

        KeyFactory keyFactory = KeyFactory.getInstance();
        KeyPair keyPair = keyFactory.generateKeyPair(2048);
        PublicKey pubKey = keyPair.getPublicKey();
        byte[] encoded = pubKey.encode(PublicKeyEncodingScheme.DER_PKCS1);

        /*
         * Decode the public key.
         */

        PublicKey decodedPubKey = keyFactory.decodePublicKey(encoded, PublicKeyEncodingScheme.DER_PKCS1);

        /*
         * Test the decoded public key.
         */

        assertNotNull(decodedPubKey);
        assertNotNull(decodedPubKey.getN());
        assertNotNull(decodedPubKey.getE());
        assertEquals(pubKey.getN(), decodedPubKey.getN());
        assertEquals(pubKey.getE(), decodedPubKey.getE());
        assertEquals(pubKey.getLengthInOctets(), decodedPubKey.getLengthInOctets());
    }

    /**
     * Test decoding a truncated key. Must throw KeyDecodingException.
     */
    @Test
    public void testDecodingTruncatedPublicKey() {

        /*
         * Create and encode a public key with Bagsværd Crypto.
         */

        KeyFactory keyFactory = KeyFactory.getInstance();
        KeyPair keyPair = keyFactory.generateKeyPair(2048);
        PublicKey pubKey = keyPair.getPublicKey();
        byte[] encoded = pubKey.encode(PublicKeyEncodingScheme.DER_PKCS1);

        /*
         * Truncate encoded key.
         */

        encoded = Arrays.copyOf(encoded, 1);

        /*
         * Decode the public key.
         */

        try {
            PublicKey decodedPubKey = keyFactory.decodePublicKey(encoded, PublicKeyEncodingScheme.DER_PKCS1);
        } catch (KeyDecodingException ex) {
            assertTrue(true);
        }
    }

}
