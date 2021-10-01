/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

/**
 * OID Exception.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class OIDException extends RuntimeException {

    /**
     * Constructs a new OIDException with null as its detail message.
     */
    public OIDException() {
    }

    /**
     * Constructs a new OIDException with the specified detail message and cause.
     *
     * @param msg Message
     */
    public OIDException(String msg) {
        super(msg);
    }

    /**
     * Constructs a new OIDException with the specified detail message and cause.
     *
     * @param msg   Message.
     * @param cause Cause.
     */
    public OIDException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
