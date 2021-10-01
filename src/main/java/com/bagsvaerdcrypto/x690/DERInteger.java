/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

import java.util.Arrays;

/**
 * Integer DER encoding support.
 *
 * @author Søren Thalbitzer Poulsen
 */
class DERInteger {

    /**
     * Convert a non-negative integer to a compact byte array.
     *
     * @param integer Non-negative integer.
     * @return Compact array representation of the integer.
     */
    static byte[] toCompactByteArray(int integer) {
        byte[] b = new byte[]{(byte) (integer >>> 24), (byte) (integer >>> 16), (byte) (integer >>> 8), (byte) integer};
        int compactLength = 4;
        for (int i = 0; i < 3; i++) {
            if (b[i] != 0) {
                break;
            }
            compactLength--;
        }
        return Arrays.copyOfRange(b, 4 - compactLength, 4);
    }
}
