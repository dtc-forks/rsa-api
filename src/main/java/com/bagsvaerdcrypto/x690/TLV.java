/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.x690;

import java.math.BigInteger;

/**
 * X.690 type-length-value building block for DER encoding.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class TLV {

    /*
     * TLV ASN1Type.
     */
    private ASN1Type type;

    /*
     * Length DER encoded.
     */
    private byte[] lengthEncoded;

    /*
     * Raw byte array value.
     */
    private byte[] value;

    /**
     * Construct a TLV with a byte array value.
     *
     * @param type  ASN.1 type.
     * @param value Byte array value.
     */
    public TLV(ASN1Type type, byte[] value) {
        this.type = type;
        this.value = value;
        if (value != null) {
            this.lengthEncoded = encodeLength(value.length);
        } else {
            this.lengthEncoded = encodeLength(0);
        }
    }

    /**
     * Construct a TLV with an integer value.
     *
     * @param type  ASN.1 type.
     * @param value Integer value.
     */
    public TLV(ASN1Type type, int value) {
        this.type = type;
        this.value = DERInteger.toCompactByteArray(value);
        this.lengthEncoded = encodeLength(this.value.length);
    }

    /**
     * Construct a TLV with a BigInteger value.
     *
     * @param type  ASN.1 type.
     * @param value BigInteger value.
     */
    public TLV(ASN1Type type, BigInteger value) {
        this.type = type;
        this.value = value.toByteArray();
        this.lengthEncoded = encodeLength(this.value.length);
    }

    /**
     * Construct a TLV with an OID value.
     *
     * @param oid OID value.
     */
    public TLV(OID oid) {
        this.type = ASN1Type.OID;
        this.value = oid.getEncoded();
        this.lengthEncoded = encodeLength(this.value.length);
    }

    /**
     * Construct a NULL TLV. Its has length 0 and no value.
     *
     * @param type Only ASN1Type NULL supported with no value.
     */
    public TLV(ASN1Type type) {
        this.type = type;
        switch (type) {
            case NULL:
                this.lengthEncoded = encodeLength(0);
                break;
            default:
                throw new IllegalArgumentException("Unsupported no-value ASN1Type " + type.getTag());
        }
    }

    /**
     * Construct TLV from raw byte tag and value.
     *
     * @param tag   Byte tag
     * @param value Byte array value.
     */
    public TLV(byte tag, byte[] value) {
        this.type = ASN1Type.resolve(tag);
        this.value = value;
        if (value != null) {
            this.lengthEncoded = encodeLength(value.length);
        } else {
            this.lengthEncoded = encodeLength(0);
        }
    }

    /**
     * Get ASN1Type.
     *
     * @return TLV ASN1Type.
     */
    public ASN1Type getType() {
        return type;
    }

    /**
     * Get DER encoded length.
     *
     * @return DER encoded length.
     */
    public byte[] getEncodedLength() {
        return lengthEncoded;
    }

    /**
     * Get value as byte array.
     *
     * @return Value as byte array.
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * Get value as int.
     *
     * @return Value as int.
     */
    public int getIntValue() {
        int intValue;
        if (value != null) {
            intValue = new BigInteger(1, value).intValue();
        } else {
            throw new RuntimeException("Undefined value");
        }
        return intValue;
    }

    /**
     * Get value as BigInteger.
     *
     * @return Value as BigInteger.
     */
    public BigInteger getBigIntegerValue() {
        BigInteger bigIntValue;
        if (value != null) {
            bigIntValue = new BigInteger(1, value);
        } else {
            throw new RuntimeException("Undefined value");
        }
        return bigIntValue;
    }

    /**
     * Get DER encoded length.
     *
     * @param length Length to be DER encoded.
     * @return DER encoded length.
     */
    protected static byte[] encodeLength(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("TLV length must not be negative");
        }
        byte[] encodedLength;
        if (length <= 127) {
            encodedLength = new byte[]{(byte) length};
        } else {
            byte[] l = DERInteger.toCompactByteArray(length);
            encodedLength = new byte[l.length + 1];
            encodedLength[0] = (byte) (l.length | 0x80);
            System.arraycopy(l, 0, encodedLength, 1, l.length);
        }
        return encodedLength;
    }


}
