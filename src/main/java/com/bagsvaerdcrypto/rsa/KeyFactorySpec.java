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
 * Key factory specification for key generation. See {@link KeyFactory} implementation classes
 * {@link KeyFactoryCarmichaelImpl} and {@link KeyFactoryEulerImpl} for details.
 *
 * @author Søren Thalbitzer Poulsen
 */
public enum KeyFactorySpec {
    /**
     * DEFAULT selects the fixed public exponent e=65537.
     */
    DEFAULT,
    /**
     * RANDOM selects a random, positive, odd exponent e.
     */
    RANDOM,
    /**
     * RANDOM_STRICT selects a random, positive, odd exponent e in a more strict range.
     */
    RANDOM_STRICT
}
