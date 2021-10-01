/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import java.math.BigInteger;

/**
 * Crypt implementation that uses the Chinese Remainder Theorem as specified in RFC 8017.
 *
 * @author Søren Thalbitzer Poulsen
 */
class CryptCrtImpl extends Crypt {

    /*
     * OAEP encoding.
     */
    private final OAEP oaep;

    /**
     * Create an instance of CryptCrtImpl.
     *
     * @param labelHashAlgorithm Hash function for the optional label L. In practical use L is an empty string.
     */
    protected CryptCrtImpl(HashAlgorithm labelHashAlgorithm) {
        oaep = new OAEP(labelHashAlgorithm);
    }

    /**
     * Create an instance of CryptCrtImpl.
     *
     * @param labelHashAlgorithm Hash function for the optional label L. In practical use L is an empty string.
     * @param mgfHashAlgorithm   Hash function for the Mask Generating Function.
     */
    protected CryptCrtImpl(HashAlgorithm labelHashAlgorithm, HashAlgorithm mgfHashAlgorithm) {
        oaep = new OAEP(labelHashAlgorithm, mgfHashAlgorithm);
    }

    @Override
    public byte[] encrypt(PublicKey pubKey, byte[] M) {

        /*
         * OAEP encoding
         */

        byte[] EM = oaep.encode(M, pubKey.getLengthInOctets());

        /*
         * "Convert the encoded message EM to an integer message representative m"
         */

        BigInteger m = OS2IP(EM);

        /*
         * "Apply the RSAEP encryption primitive to the RSA public key (n, e) and the message representative m to
         * produce an integer ciphertext representative c"
         */

        BigInteger c = RSAEP(m, pubKey);

        /*
         * "Convert the ciphertext representative c to a ciphertext C of length k octets"
         */

        return I2OSP(c, pubKey.getLengthInOctets());
    }

    @Override
    public byte[] decrypt(PrivateKey K, byte[] C) {

        /*
         * "Convert the ciphertext C to an integer ciphertext representative c"
         */

        BigInteger c = OS2IP(C);

        /*
         * Blind ciphertext c before decryption to prevent timing attack.
         */

        Blinding blinding = K.getBlinding();
        c = blinding.blind(c);

        /*
         * "Apply the RSADP decryption primitive to the RSA private key K and the ciphertext representative c to produce
         * an integer message representative m"
         */

        BigInteger m = RSADP(K, c);

        /*
         * Unblind after decryption.
         */

        m = blinding.unblind(m);

        /*
         * "Convert the message representative m to an encoded message EM of length k octets"
         */

        byte[] EM = I2OSP(m, K.getLengthInOctets());

        /*
         * OAEP decoding
         */

        return oaep.decode(EM, K.getLengthInOctets());
    }

    /**
     * RSA encryption primitive.
     *
     * @param m      Message representative, an integer between 0 and n-1.
     * @param pubKey RSA public key.
     * @return Cipher text integer representative.
     */
    protected BigInteger RSAEP(BigInteger m, PublicKey pubKey) {
        if (m.compareTo(pubKey.getN()) >= 0) {
            throw new CryptException("message representative out of range");
        }
        return m.modPow(pubKey.getE(), pubKey.getN());
    }

    /**
     * RSA decryption primitive.
     *
     * @param K RSA private key.
     * @param c Cipher text integer representation.
     * @return Message integer representation.
     */
    protected BigInteger RSADP(PrivateKey K, BigInteger c) {

        if (c.compareTo(K.getN()) >= 0) {
            throw new CryptException("decryption error");
        }

        BigInteger m;

        if (K instanceof PrivateKeyCrt) {
            PrivateKeyCrt pk = (PrivateKeyCrt) K;

            /*
             * "Let m_1 = c^dP mod p and m_2 = c^dQ mod q."
             */

            BigInteger m_1 = c.modPow(pk.getdP(), pk.getP());
            BigInteger m_2 = c.modPow(pk.getdQ(), pk.getQ());

            /*
             * "Let h = (m_1 - m_2) * qInv mod p."
             */

            BigInteger h = m_1.subtract(m_2).multiply(pk.getqInv()).mod(pk.getP());

            /*
             * "Let m = m_2 + q * h."
             */

            m = pk.getQ().multiply(h).add(m_2);
        } else {
            m = c.modPow(K.getD(), K.getN());
        }
        return m;
    }
}
