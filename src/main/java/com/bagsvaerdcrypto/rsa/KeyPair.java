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
 * RSA key pair.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class KeyPair {

    /**
     * RSA public key.
     */
    private final PublicKey publicKey;

    /**
     * RSA private key.
     */
    private final PrivateKey privateKey;

    /**
     * Create RSA key pair.
     *
     * @param privateKey RSA private key.
     * @param publicKey  RSA public key.
     */
    public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Get RSA public key.
     *
     * @return RSA public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get RSA private key.
     *
     * @return RSA private key.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
