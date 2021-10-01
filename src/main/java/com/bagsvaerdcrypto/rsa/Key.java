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
 * Base RSA key.
 *
 * @author Søren Thalbitzer Poulsen
 */
class Key {

    /**
     * RSA modulus n.
     */
    private BigInteger n;

    /**
     * k is the length in octets of the RSA modulus n.
     */
    private int k;

    /**
     * Construct a base RSA key.
     *
     * @param n RSA modulus n.
     */
    protected Key(BigInteger n) {
        this.n = n;
        this.k = n.bitLength() / 8;
        if (!isBaseValid()) {
            throw new KeyInvalidException("Key base components are invalid");
        }
    }

    /**
     * Get modulus n.
     *
     * @return Modulus n.
     */
    public BigInteger getN() {
        return n;
    }

    /**
     * Get length in octets of the RSA modulus n.
     *
     * @return Length in octets of the RSA modulus n.
     */
    public int getLengthInOctets() {
        return k;
    }

    /**
     * Validate base key.
     *
     * @return True is base key is valid.
     */
    protected boolean isBaseValid() {
        boolean isValid = true;
        if (n == null || n.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (k == 0) {
            isValid = false;
        }
        return isValid;
    }
}
