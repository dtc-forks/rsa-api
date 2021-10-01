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
 * BigMath provides additional support for BigInteger math.
 *
 * @author Søren Thalbitzer Poulsen
 */
class BigMath {

    /**
     * Calculate the Least Common Multiple of two positive numbers a and b.
     *
     * @param a Positive number a.
     * @param b Positive number b.
     * @return Least Common Multiple of a and b.
     */
    protected static BigInteger lcm(BigInteger a, BigInteger b) {
        BigInteger lcm;
        if (a.compareTo(BigInteger.ZERO) == 0 || b.compareTo(BigInteger.ZERO) == 0) {
            lcm = BigInteger.ZERO;
        } else {
            lcm = a.multiply(b).abs().divide(a.gcd(b));
        }
        return lcm;
    }

}
