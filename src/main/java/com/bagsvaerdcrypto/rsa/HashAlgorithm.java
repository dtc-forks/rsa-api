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
 * Hash functions recommended in RFC 8017 for OAEP and PSS encoding.
 * <p>
 * Values are named according to the FIPS-180-4 naming scheme.
 *
 * @author Søren Thalbitzer Poulsen
 */
public enum HashAlgorithm {
    SHA1("SHA-1"), SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512"),
    SHA512_224("SHA-512/224"), SHA512_256("SHA-512/256");
    private String fipsName;

    /**
     * Create HashAlgorithm instance.
     *
     * @param fipsName FIPS-180-4 name.
     */
    HashAlgorithm(String fipsName) {
        this.fipsName = fipsName;
    }

    /**
     * Get name.
     *
     * @return Name
     */
    String getFIPSName() {
        return fipsName;
    }
}
