/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Mask Generating Function for OAEP and PSS encoding schemes.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class MGF {

    private MessageDigest hash;

    /*
     * Hash length in octets.
     */
    private final int hLen;

    /**
     * Create the default Mask Generating Function MGF1SHA1 as per RFC 8017.
     */
    public MGF() {
        this(HashAlgorithm.SHA1);
    }

    /**
     * Create a Mask Generating Function with a specified hash algorithm.
     *
     * @param mgfHashAlgorithm Mask Generating Function algorithm.
     */
    public MGF(HashAlgorithm mgfHashAlgorithm) {
        try {
            hash = MessageDigest.getInstance(mgfHashAlgorithm.getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptException("Failed to create MGF hash", e);
        }
        hLen = hash.getDigestLength();
    }

    /**
     * Generate mask.
     *
     * @param mgfSeed Seed from which mask is generated, an octet string.
     * @param maskLen Intended length in octets of the mask.
     * @return Mask.
     */
    public byte[] generateMask(byte[] mgfSeed, int maskLen) {

        /*
         * RFC 8017 states "If maskLen > 2^32 hLen, output 'mask too long' and stop" but because the implementation
         * uses a byte array the maximum mask length is roughly half of that.
         */

        if (maskLen > 2147483647 - hLen) {
            throw new CryptException("mask too long");
        }

        int iterations = (maskLen + hLen - 1) / hLen;

        byte[] T = new byte[iterations * hLen];
        byte[] C = new byte[4];

        /*
         * "For counter from 0 to ceil (maskLen / hLen) - 1,.."
         */

        for (int counter = 0, Toffset = 0; counter < iterations; counter++, Toffset += hLen) {

            /*
             * "C = I2OSP (counter, 4)"
             */

            I2OSP4(counter, C);

            /*
             * "T = T || Hash(mgfSeed || C)"
             */

            hash.update(mgfSeed);
            hash.update(C);
            System.arraycopy(hash.digest(), 0, T, Toffset, hLen);
        }

        /*
         * "Output the leading maskLen octets of T"
         */

        return Arrays.copyOf(T, maskLen);
    }

    /**
     * Convert integer to octet string of 4 bytes. PKCS1 is Big Endian, see section 4 on I2OSP.
     *
     * @param integer Integer to convert.
     * @param dest4   Destination byte array of length 4.
     */
    protected static void I2OSP4(int integer, byte[] dest4) {
        dest4[0] = (byte) ((integer >> 24) & 0xff);
        dest4[1] = (byte) ((integer >> 16) & 0xff);
        dest4[2] = (byte) ((integer >> 8) & 0xff);
        dest4[3] = (byte) (integer & 0xff);
    }

}
