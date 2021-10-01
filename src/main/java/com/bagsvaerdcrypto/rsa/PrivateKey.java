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
 * RSA private key.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PrivateKey extends Key {

    /**
     * RSA private exponent.
     */
    private BigInteger d;

    /**
     * RSA public exponent.
     * <br>
     * The public exponent is member of the private key because it is used for Blinding of the private key and it is a
     * component of the PKCS#1 and PKCS#2 serialization of private keys.
     */
    private BigInteger e;

    /**
     * First two prime factors p and q of the RSA modulus n
     */
    private BigInteger p, q;

    /**
     * Blinding is created on first use of the private key and is updated every time the key is used.
     */
    private Blinding blinding = null;

    /**
     * Create instance of RSA private key.
     *
     * @param d RSA private exponent d.
     * @param e RSA public exponent e.
     * @param n RSA modulus n.
     * @param p Prime factor p.
     * @param q Prime factor q.
     */
    protected PrivateKey(BigInteger d, BigInteger e, BigInteger n, BigInteger p, BigInteger q) {
        super(n);
        this.d = d;
        this.e = e;
        this.p = p;
        this.q = q;
        if (!isPrivateKeyValid()) {
            throw new KeyInvalidException("Private key components are invalid");
        }
    }

    /**
     * Get RSA private exponent d.
     *
     * @return RSA private exponent d.
     */
    public BigInteger getD() {
        return d;
    }

    /**
     * Get prime factor p of modulus n.
     *
     * @return Prime factor p.
     */
    public BigInteger getP() {
        return p;
    }

    /**
     * Get prime factor q of modulus n.
     *
     * @return Prime factor q.
     */
    public BigInteger getQ() {
        return q;
    }

    /**
     * Get public exponent e.
     *
     * @return Public exponent e.
     */
    protected BigInteger getE() {
        return e;
    }

    /**
     * Get instance of Blinding specific to this private key.
     *
     * @return Blinding instance.
     */
    synchronized Blinding getBlinding() {
        if (blinding == null) {
            this.blinding = new Blinding(this);
        }
        return blinding;
    }

    /**
     * Encode private key.
     *
     * @param encodingScheme Encoding scheme.
     * @return Encoded private key.
     */
    public byte[] encode(PrivateKeyEncodingScheme encodingScheme) {
        return KeyEncoding.encodePrivateKey(this, encodingScheme);
    }

    /**
     * Validate key components. All key components must be valid.
     *
     * @return True if all key components are valid.
     */
    protected boolean isPrivateKeyValid() {
        boolean isValid = true;
        if (d == null || d.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (e == null || e.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (p == null || p.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (q == null || q.equals(BigInteger.ZERO)) {
            isValid = false;
        }
        return isValid;
    }

}
