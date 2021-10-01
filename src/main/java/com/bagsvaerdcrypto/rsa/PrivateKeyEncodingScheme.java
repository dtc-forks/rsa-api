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
 * Private key encoding scheme.
 *
 * @author Søren Thalbitzer Poulsen
 */
public enum PrivateKeyEncodingScheme {
    /**
     * DER encoded PKCS1 key.
     */
    DER_PKCS1,
    /**
     * DER encoded PKCS8 key.
     */
    DER_PKCS8
}
