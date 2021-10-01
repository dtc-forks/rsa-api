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
import java.util.Arrays;

/**
 * RSA encryption and decryption.
 *
 * @author Søren Thalbitzer Poulsen
 */
public abstract class Crypt {

    /**
     * Encrypt message M.
     *
     * @param M      Message to be encrypted, an octet string of length mLen, where mLen &lt;= k - 2hLen - 2.
     * @param pubKey RSA public key.
     * @return Ciphertext, an octet string of length k.
     */
    public abstract byte[] encrypt(PublicKey pubKey, byte[] M);

    /**
     * Decrypt ciphertext C.
     *
     * @param C Ciphertext to be decrypted, an octet string of length k.
     * @param K RSA private key.
     * @return Message, an octet string of length mLen, where mLen &lt;= k - 2hLen - 2.
     */
    public abstract byte[] decrypt(PrivateKey K, byte[] C);

    /**
     * Get an instance of the default Crypt implementation with the default mask generating function MGF1SHA1.
     *
     * @param labelHashAlgorithm Hash function for the optional label L.
     * @return Instance of default Crypt implementation.
     */
    public static Crypt getInstance(HashAlgorithm labelHashAlgorithm) {
        return new CryptCrtImpl(labelHashAlgorithm);
    }

    /**
     * Get an instance of Crypt.
     *
     * @param labelHashAlgorithm Hash function for the optional label L. In practical use L is an empty string.
     * @param mgfHashAlgorithm   Hash function for the Mask Generating Function.
     * @return Instance of Crypt.
     */
    public static Crypt getInstance(HashAlgorithm labelHashAlgorithm, HashAlgorithm mgfHashAlgorithm) {
        return new CryptCrtImpl(labelHashAlgorithm, mgfHashAlgorithm);
    }

    /**
     * Octet string to unsigned integer conversion.
     *
     * @param EM Octet string
     * @return Unsigned integer.
     */
    protected static BigInteger OS2IP(byte[] EM) {
        return new BigInteger(1, EM);
    }

    /**
     * Unsigned integer to octet string conversion.
     *
     * @param x    Unsigned integer to be converted.
     * @param xLen Intended length of the resulting octet string.
     * @return Octet string of length xLen.
     */
    protected static byte[] I2OSP(BigInteger x, int xLen) {
        byte[] C = x.toByteArray();
        if (C.length < xLen) {
            byte[] xExpand = new byte[xLen];
            System.arraycopy(C, 0, xExpand, xLen - C.length, C.length);
            C = xExpand;
        } else if (C.length == xLen + 1 && C[0] == 0) {

            /*
             * x.toByteArray[] includes a sign bit which is why the length of C may be one byte longer than xLen.
             * The value of the leading byte is 0 because RSA only works on unsigned numbers.
             */

            C = Arrays.copyOfRange(C, 1, xLen + 1);
        } else if (C.length > xLen) {

            /*
             * "If x >= 256^xLen, output "integer too large" and stop."
             */
            throw new CryptException("integer too large");
        }
        return C;
    }
}
