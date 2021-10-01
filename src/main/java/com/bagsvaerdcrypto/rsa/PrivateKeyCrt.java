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
 * RSA private key that supports the Chinese Remainder Theorem.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PrivateKeyCrt extends PrivateKey {

    /**
     * RSA private exponents in the CRT domain.
     */
    private BigInteger dP, dQ;

    /**
     * CRT coefficient of q.
     */

    private BigInteger qInv;

    /**
     * Create instance of RSA private key.
     *
     * @param d    RSA private exponent d.
     * @param e    RSA public exponent e.
     * @param n    RSA modulus n.
     * @param p    Prime factor p of RSA modulus n.
     * @param q    Prime factor q of RSA modulus n.
     * @param dP   Exponent d in the CRT domain for p.
     * @param dQ   Exponent d in the CRT domain for q.
     * @param qInv CRT coefficient qInv.
     */
    protected PrivateKeyCrt(BigInteger d, BigInteger e, BigInteger n, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv) {
        super(d, e, n, p, q);
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
        if (!this.isCrtValid()) {
            throw new KeyInvalidException("CRT private key components are invalid");
        }
    }

    /**
     * Get CRT decryption exponent for p.
     *
     * @return CRT decryption exponent for p.
     */
    public BigInteger getdP() {
        return dP;
    }

    /**
     * Get CRT decryption exponent for q.
     *
     * @return CRT decryption exponent for q.
     */
    public BigInteger getdQ() {
        return dQ;
    }

    /**
     * CRT coefficient qInv.
     *
     * @return CRT coefficient qInv.
     */
    public BigInteger getqInv() {
        return qInv;
    }

    /**
     * Encode private key.
     *
     * @param encodingScheme Encoding scheme.
     * @return Encoded private key.
     */
    @Override
    public byte[] encode(PrivateKeyEncodingScheme encodingScheme) {
        return KeyEncoding.encodePrivateKey(this, encodingScheme);
    }

    /**
     * Validate key components. All key components must be valid.
     *
     * @return True if all key components are valid.
     */
    protected boolean isCrtValid() {
        boolean isValid = true;
        if (dP == null || dP.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (dQ == null || dQ.equals(BigInteger.ZERO)) {
            isValid = false;
        } else if (qInv == null || qInv.equals(BigInteger.ZERO)) {
            isValid = false;
        }
        return isValid;
    }
}