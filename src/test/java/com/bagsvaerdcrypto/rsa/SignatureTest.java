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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Signature test.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class SignatureTest {

    private final static byte[] M = "hello world".getBytes(StandardCharsets.UTF_8);

    /**
     * Test the length of the produced signature.
     */
    @Test
    public void testSignatureLengthSha1Salt20() {

        KeyPair keyPair = KeyFactory.getInstance().generateKeyPair(2048);
        Signature signature = Signature.getInstance(new SignatureParameterPssImpl(HashAlgorithm.SHA1, HashAlgorithm.SHA1, 20));
        signature.update(M);
        byte[] signed = signature.sign(keyPair.getPrivateKey());

        assertEquals(256, signed.length);
    }

    /**
     * Sign with Bagsværd Crypto and verify with the std. api.
     */
    @Test
    public void testSignAgainstStdAPI() {

        /*
         * Sign message M with Bagsværd Crypto api to produce signature S.
         */

        KeyPair keyPair = KeyFactory.getInstance().generateKeyPair(2048);
        Signature signature = Signature.getInstance(new SignatureParameterPssImpl(HashAlgorithm.SHA1, HashAlgorithm.SHA1, 20));
        signature.update(M);
        byte[] S = signature.sign(keyPair.getPrivateKey());

        /*
         * Load Bagsværd Crypto key into a std api key.
         */

        PublicKey pk = keyPair.getPublicKey();
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pk.getN(), pk.getE());
        RSAPublicKey pubKey = null;
        try {
            java.security.KeyFactory stdKeyFactory = java.security.KeyFactory.getInstance("RSASSA-PSS");
            pubKey = (RSAPublicKey) stdKeyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail();
        }

        /*
         * Verify signature S of Message M using std. api.
         */

        java.security.Signature signVerifier;
        boolean signatureOK = false;
        try {
            signVerifier = java.security.Signature.getInstance("RSASSA-PSS");
            signVerifier.initVerify(pubKey);
            PSSParameterSpec spec = new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.TRAILER_FIELD_BC);
            signVerifier.setParameter(spec);
            signVerifier.update(M);
            signatureOK = signVerifier.verify(S);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | java.security.SignatureException e) {
            fail();
        }

        assertTrue(signatureOK);
    }

    /**
     * Sign with std. api and verify with Bagsværd Crypto.
     */
    @Test
    public void testVerifyAgainstStdAPI() {

        /*
         * Generate key using std. api.
         */

        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSASSA-PSS");
        } catch (NoSuchAlgorithmException e) {
            fail();
        }
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();
        java.security.interfaces.RSAPrivateCrtKey stdPriKey = (java.security.interfaces.RSAPrivateCrtKey) kp.getPrivate();
        java.security.interfaces.RSAPublicKey stdPubKey = (java.security.interfaces.RSAPublicKey) kp.getPublic();

        /*
         * Sign message using std. api.
         */

        java.security.Signature stdSignature;
        byte[] S = null;
        try {
            stdSignature = java.security.Signature.getInstance("RSASSA-PSS");
            stdSignature.initSign(stdPriKey);
            PSSParameterSpec spec = new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.TRAILER_FIELD_BC);
            stdSignature.setParameter(spec);
            stdSignature.update(M);
            S = stdSignature.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | java.security.SignatureException e) {
            fail();
        }

        /*
         * Load the std. api key into a Bagsværd Crypto key.
         */

        PublicKey pubKey = KeyFactory.getInstance().createPublicKey(stdPubKey.getPublicExponent(), stdPubKey.getModulus());

        /*
         * Verify the signature S of message M.
         */

        Signature signature = Signature.getInstance(new SignatureParameterPssImpl(HashAlgorithm.SHA1, HashAlgorithm.SHA1, 20));
        signature.update(M);
        boolean verified = signature.verify(pubKey, S);

        assertTrue(verified);
    }


}
