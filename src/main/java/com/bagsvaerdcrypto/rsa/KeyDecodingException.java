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
 * Key decoding exception.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class KeyDecodingException extends KeyException {

    /**
     * Constructs a new KeyDecodingException with null as its detail message.
     */
    public KeyDecodingException() {
    }

    /**
     * Constructs a new KeyDecodingException with the specified detail message and cause.
     *
     * @param msg Message
     */
    public KeyDecodingException(String msg) {
        super(msg);
    }

    /**
     * Constructs a new KeyDecodingException with the specified detail message and cause.
     *
     * @param msg   Message.
     * @param cause Cause.
     */
    public KeyDecodingException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
