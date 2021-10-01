/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

/**
 * Byte array support class.
 *
 * @author Søren Thalbitzer Poulsen
 */
class ByteArray {

    /**
     * XOR two byte arrays.
     *
     * @param srcA Byte array A
     * @param srcB Byte array B
     * @return Exclusive Or of byte array A and B.
     */
    static byte[] xor(byte[] srcA, byte[] srcB) {
        if (srcA.length != srcB.length) {
            throw new CryptException("byte arrays must be equal length");
        }
        byte[] result = new byte[srcA.length];
        int i = 0;
        for (byte b : srcA) {
            result[i] = (byte) (b ^ srcB[i]);
            i++;
        }
        return result;
    }
}
