/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

import com.bagsvaerdcrypto.rsa.KeyDecodingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * X.690 DER encoded input stream.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class DERInputStream extends ByteArrayInputStream {

    /**
     * Construct DERInputStream from byte array.
     *
     * @param buf Byte array to construct input stream from.
     */
    public DERInputStream(byte[] buf) {
        super(buf);
    }

    /**
     * Read TLV from input stream.
     *
     * @return TLV read from input stream.
     * @throws IOException
     */
    public TLV readTLV() throws IOException {

        byte tag = (byte) read();
        if (tag == -1) {
            throw new KeyDecodingException("Unexpected end of stream");
        }

        byte lenHdr = (byte) read();
        if (lenHdr == -1) {
            throw new KeyDecodingException("Unexpected end of stream");
        }
        int length = Byte.toUnsignedInt(lenHdr) & 0b01111111;

        /*
         * When bit 8 is not set it's short form (1 byte) length.
         * When bit 8 is set it's either long form or infinite.
         * With infinite form bits 7 to 1 are zero.
         */

        if ((Byte.toUnsignedInt(lenHdr) & 0b10000000) != 0) {
            if ((Byte.toUnsignedInt(lenHdr) & 0b01111111) == 0) {
                throw new KeyDecodingException("Infinite form unsupported");
            }
            if (length > 4) {
                throw new KeyDecodingException("Unsupported length");
            }
            byte[] lenArray = new byte[length];
            int readBytes = read(lenArray, 0, length);
            if (readBytes != length) {
                throw new KeyDecodingException("Unexpected end of stream");
            }
            length = new BigInteger(1, lenArray).intValue();
        }

        byte[] value = new byte[length];
        int readBytes = read(value, 0, length);
        if (readBytes != length) {
            throw new KeyDecodingException("Unexpected end of stream");
        }

        return new TLV(tag, value);
    }

}
