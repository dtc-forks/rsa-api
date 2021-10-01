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
 * The key factory algorithm determines how RSA exponents e and d are generated.
 *
 * @author Søren Thalbitzer Poulsen
 */
public enum KeyFactoryAlgorithm {
    /**
     * The DEFAULT algorithm generates RSA exponents e and d using Carmichael's lambda function as specified in RFC 8017
     * .
     */
    CARMICHAEL,
    /**
     * The EULER algorithm generates RSA exponents e and d using the typical textbook implementation with Euler's Phi
     * function.
     */
    EULER
}
