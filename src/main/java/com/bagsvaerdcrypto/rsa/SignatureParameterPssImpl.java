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
 * Signature parameter specific to the Probabilistic Signing Scheme.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class SignatureParameterPssImpl implements SignatureParameter {

    /*
     * Probabilistic Signing Scheme hash algorithm.
     */
    private final HashAlgorithm pssHashAlgorithm;

    /*
     * Mask Generating Function hash algorithm.
     */
    private final HashAlgorithm mgfHashAlgorithm;

    /*
     * Salt length.
     */
    private final int sLen;

    /**
     * Construct signature parameter for Probabilistic Signing Scheme.
     *
     * @param pssHashAlgorithm PSS hash algorithm.
     * @param mgfHashAlgorithm MGF hash algorithm.
     * @param sLen             Salt length in octets.
     */
    public SignatureParameterPssImpl(HashAlgorithm pssHashAlgorithm, HashAlgorithm mgfHashAlgorithm, int sLen) {
        this.pssHashAlgorithm = pssHashAlgorithm;
        this.mgfHashAlgorithm = mgfHashAlgorithm;
        this.sLen = sLen;
    }

    /**
     * Get PSS hash algorithm.
     *
     * @return PSS hash algorithm.
     */
    public HashAlgorithm getPssHashAlgorithm() {
        return pssHashAlgorithm;
    }

    /**
     * Get MGF hash algorithm.
     *
     * @return  MGF hash algorithm.
     */
    public HashAlgorithm getMgfHashAlgorithm() {
        return mgfHashAlgorithm;
    }

    /**
     * Get salt length in octets.
     *
     * @return Salt length in octets.
     */
    public int getsLen() {
        return sLen;
    }
}
