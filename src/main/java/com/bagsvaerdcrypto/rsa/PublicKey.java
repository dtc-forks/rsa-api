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
 * RSA public key.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PublicKey extends Key {

    /**
     * RSA public exponent e.
     */
    private BigInteger e;

    /**
     * Create an instance of RSA public key.
     *
     * @param e The RSA public exponent, a positive integer.
     * @param n The RSA modulus, a positive integer.
     */
    protected PublicKey(BigInteger e, BigInteger n) {
        super(n);
        this.e = e;
        if (!isPublicKeyValid()) {
            throw new KeyInvalidException("Public key components are invalid");
        }
    }

    /**
     * Get RSA public exponent e.
     *
     * @return RSA public exponent e.
     */
    public BigInteger getE() {
        return e;
    }

    /**
     * Encode public key.
     *
     * @param encodingScheme Encoding scheme.
     * @return Encoded public key.
     */
    public byte[] encode(PublicKeyEncodingScheme encodingScheme) {
        return KeyEncoding.encodePublicKey(this, encodingScheme);
    }

    /**
     * Validate public key. All key components must be valid.
     *
     * @return True if all key components are valid.
     */
    protected boolean isPublicKeyValid() {
        boolean isValid = true;
        if (e == null || e.equals(BigInteger.ZERO)) {
            isValid = false;
        }
        return isValid;
    }
}
