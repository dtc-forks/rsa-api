/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * X.690 DER encoded output stream.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class DEROutputStream extends ByteArrayOutputStream {

    /**
     * Write TLV.
     *
     * @param tlv TLV to write.
     * @throws IOException
     */
    public void writeTLV(TLV tlv) throws IOException {
        write(tlv.getType().getTag());
        write(tlv.getEncodedLength());
        if (tlv.getValue() != null) {
            write(tlv.getValue());
        }
    }
}
