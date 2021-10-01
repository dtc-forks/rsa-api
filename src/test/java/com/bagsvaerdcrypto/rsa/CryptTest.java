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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test Crypt.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class CryptTest {

    /**
     * Test encrypt and decrypt with default implementation classes and default config.
     */
    @Test
    public void testEncryptAndDecrypt2048bit() {
        byte[] M = "hello world".getBytes(UTF_8);
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance().generateKeyPair(2048);
        byte[] C = rsa.encrypt(keys.getPublicKey(), M);
        byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
        assertArrayEquals(M, m);
    }

    /**
     * Test encrypt and decrypt with default implementation classes and randomly generated exponent e.
     */
    @Test
    public void testEncryptAndDecryptRnd2048bit() {
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance().generateKeyPair(2048, KeyFactorySpec.RANDOM);
        byte[] C = rsa.encrypt(keys.getPublicKey(), "hello world".getBytes(UTF_8));
        byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
        String msg = new String(m, UTF_8);
        assertEquals("hello world", msg);
    }

    /**
     * Test encrypt and decrypt with default implementation classes and randomly generated strict exponent e.
     */
    @Test
    public void testEncryptAndDecryptRndStrict2048bit() {
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance().generateKeyPair(2048, KeyFactorySpec.RANDOM_STRICT);
        byte[] C = rsa.encrypt(keys.getPublicKey(), "hello world".getBytes(UTF_8));
        byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
        String msg = new String(m, UTF_8);
        assertEquals("hello world", msg);
    }

    /**
     * Test encrypt and decrypt with the Euler implementation of the key factory.
     */
    @Test
    public void testEncryptAndDecryptWithEulerKeyFactory2048bit() {
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance(KeyFactoryAlgorithm.EULER).generateKeyPair(2048);
        byte[] C = rsa.encrypt(keys.getPublicKey(), "hello world".getBytes(UTF_8));
        byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
        String msg = new String(m, UTF_8);
        assertEquals("hello world", msg);
    }

    /**
     * Test encrypt and decrypt with the Euler implementation of the key factory and randomly generated exponent e.
     */
    @Test
    public void testEncryptAndDecryptWithEulerKeyFactoryRnd2048bit() {
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance(KeyFactoryAlgorithm.EULER).generateKeyPair(2048, KeyFactorySpec.RANDOM);
        byte[] C = rsa.encrypt(keys.getPublicKey(), "hello world".getBytes(UTF_8));
        byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
        String msg = new String(m, UTF_8);
        assertEquals("hello world", msg);
    }

    /**
     * Test against the standard api by encrypting with Bagsvaerd Crypto and decrypting with the std api. The keys are
     * generated using the standard api.
     */
    @Test
    public void testEncryptionAgainstStdAPIUsingStdAPIkeys() {

        String s = "hello world";

        /*
         * Generate keys using std api.
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
        java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) kp.getPublic();

        /*
         * Load the generated std key into Bagsvaerd Crypto key.
         */

        PublicKey publicKey = KeyFactory.getInstance().createPublicKey(pubKey.getPublicExponent(), pubKey.getModulus());

        /*
         * Encrypt a message using Bagsvaerd Crypto.
         */
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        byte[] C = rsa.encrypt(publicKey, s.getBytes(UTF_8));

        /*
         * Decrypt the message using the std api.
         */

        Cipher cipher;
        byte[] M = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            M = cipher.doFinal(C);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            fail();
        }
        String msg = new String(M, UTF_8);

        /*
         * Assert the message is the same.
         */

        assertEquals(s, msg);

    }

    /**
     * Test against the standard api by encrypting with Bagsvaerd Crypto and decrypting with the std api. The keys are
     * generated using Bagsværd Crypto.
     */
    @Test
    public void testEncryptionAgainstStdAPIUsingOwnkeys() {

        String s = "hello world";

        /*
         * Generate keys using Bagsværd Crypto
         */

        KeyPair keyPair = KeyFactory.getInstance().generateKeyPair(2048);
        PrivateKey priKey = keyPair.getPrivateKey();
        PublicKey pubKey = keyPair.getPublicKey();

        /*
         * Encrypt a message using Bagsvaerd Crypto.
         */

        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        byte[] C = rsa.encrypt(pubKey, s.getBytes(UTF_8));

        /*
         * Load Bagsvaerd Crypto key into a std API key.
         */

        java.security.KeyFactory kf;
        java.security.PrivateKey stdPriKey = null;
        try {
            kf = java.security.KeyFactory.getInstance("RSA");
            stdPriKey = kf.generatePrivate(new RSAPrivateKeySpec(priKey.getN(), priKey.getD()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail();
        }

        /*
         * Decrypt the message using the std api.
         */

        Cipher cipher;
        byte[] M = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, stdPriKey);
            M = cipher.doFinal(C);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            fail();
        }
        String msg = new String(M, UTF_8);

        /*
         * Assert the message is the same.
         */

        assertEquals(s, msg);

    }

    /**
     * Test against the std api by encrypting using the std api and decrypting using Bagsvaerd Crypto. Keys are
     * generated using Bagsvaerd Crypto.
     */
    @Test
    public void testDecryptionAgainstStdAPIUsingOwnKeys() {

        String s = "hello world";

        /*
         * Create keys using Bagsvaerd Crypto.
         */

        KeyPair keyPair = KeyFactory.getInstance().generateKeyPair(2048);
        PrivateKey priKey = keyPair.getPrivateKey();
        PublicKey pubKey = keyPair.getPublicKey();

        /*
         * Load Bagsvaerd Crypto key into a std API key.
         */

        java.security.KeyFactory kf;
        java.security.PublicKey stdPublicKey = null;
        try {
            kf = java.security.KeyFactory.getInstance("RSA");
            stdPublicKey = kf.generatePublic(new RSAPublicKeySpec(pubKey.getN(), pubKey.getE()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail();
        }

        /*
         * Encrypt message using std api.
         */

        byte[] c = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, stdPublicKey);
            c = cipher.doFinal(s.getBytes());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            fail();
        }

        /*
         * Decrypt message using Bagsvaerd Crypto.
         */

        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        byte[] m = rsa.decrypt(priKey, c);
        String msg = new String(m, UTF_8);

        /*
         * Assert the message is the same.
         */

        assertEquals(s, msg);
    }

    /**
     * Test encrypt and decrypt with default implementation classes and default config.
     */
    @Test
    public void testBlindingReuse() {
        byte[] M = "hello world".getBytes(UTF_8);
        Crypt rsa = Crypt.getInstance(HashAlgorithm.SHA256);
        KeyPair keys = KeyFactory.getInstance().generateKeyPair(2048);
        byte[] C = rsa.encrypt(keys.getPublicKey(), M);

        for (int i=0; i<10; i++) {
            byte[] m = rsa.decrypt(keys.getPrivateKey(), C);
            assertArrayEquals(M, m);
        }
    }

}
