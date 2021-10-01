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
 * RSA signing and verification.
 *
 * @author Søren Thalbitzer Poulsen
 */
public abstract class Signature {

    private SignatureParameter signParam;

    /**
     * Get instance of Signature that supports the passed type of SignatureParameter.
     *
     * @param signParam Signature parameter.
     * @return Signature.
     */
    public static Signature getInstance(SignatureParameter signParam) {
        Signature instance;
        if (signParam instanceof SignatureParameterPssImpl) {
            instance = new SignaturePssImpl((SignatureParameterPssImpl) signParam);
        } else {
            throw new SignatureException("Unsupported signature parameter type");
        }
        return instance;
    }

    /**
     * Update hash of message M.
     *
     * @param M Message M to be hashed.
     */
    public abstract void update(byte[] M);

    /**
     * Sign message M with private key K.
     *
     * @param K RSA private key K.
     * @return Signature, an octet string of length k, where k is the length in octets of the RSA modulus n.
     */
    public abstract byte[] sign(PrivateKey K);

    /**
     * Verify signature S of message M.
     *
     * @param pubKey RSA public key.
     * @param S      Signature to be verified, an octet string of length k, where k is the length in octets of the
     *               RSA modulus n
     * @return True if the signature is valid, otherwise false.
     */
    public abstract boolean verify(PublicKey pubKey, byte[] S);

    /**
     * Get signature parameter.
     *
     * @return Signature parameter
     */
    public SignatureParameter getSignatureParameter() {
        return signParam;
    }
}
