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
 * ASN.1 type.
 *
 * @author Søren Thalbitzer Poulsen
 */
public enum ASN1Type {
    BOOL((byte) 0x01), INT((byte) 0x02), BITSTR((byte) 0x03), OCTSTR((byte) 0x04), NULL((byte) 0x05), OID((byte) 0x06), REAL((byte) 0x09), ENUM((byte) 0x10), SEQ((byte) 0x30), SET((byte) 0x31);

    /**
     * DER encoded tag value.
     */
    private byte tag;

    /**
     * Construct an ANS1Type.
     *
     * @param tag DER encoded tag of the ANS.1 type.
     */
    ASN1Type(byte tag) {
        this.tag = tag;
    }

    /**
     * Get tag DER encoded value.
     *
     * @return Tag.
     */
    public byte getTag() {
        return tag;
    }

    /**
     * Resolve ASN1Type from byte tag.
     *
     * @param tag Byte tag.
     * @return Resolved ASN1Type.
     */
    public static ASN1Type resolve(byte tag) {
        ASN1Type type;

        if (tag == SEQ.tag) {
            type = SEQ;
        } else if (tag == INT.tag) {
            type = INT;
        } else if (tag == OID.tag) {
            type = OID;
        } else if (tag == NULL.tag) {
            type = NULL;
        } else if (tag == OCTSTR.tag) {
            type = OCTSTR;
        } else {
            throw new IllegalArgumentException("Unsupported tag");
        }
        return type;
    }
}
