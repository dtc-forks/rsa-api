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
import java.util.Arrays;

/**
 * Object Identifier.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class OID {

    /*
     * DER encoded OID.
     */
    private byte[] oidEncoded;

    /*
     * String representation of OID.
     */
    private String oid;

    protected OID() {
    }

    /**
     * Construct a new OID.
     *
     * @param oid String representation of OID.
     */
    public OID(String oid) {
        this.oid = oid;

        String[] components = oid.split("\\.");

        if (components.length < 2) {
            throw new OIDException("OID too short");
        }

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            int firstComponent = Integer.valueOf(components[0]), secondComponent = Integer.valueOf(components[1]);
            if (firstComponent < 0 || secondComponent < 0) {
                throw new OIDException("Component must not be negative");
            }
            if (firstComponent > 2) {
                throw new OIDException("First component must not be greater than 2");
            }
            if (secondComponent > 39) {
                throw new OIDException("Second component must not be greater than 39");
            }
            os.write((byte) ((firstComponent * 40) + secondComponent));

            if (components.length > 2) {
                for (int i = 2; i < components.length; i++) {
                    int compval = Integer.valueOf(components[i]);
                    if (compval < 0) {
                        throw new OIDException("Component must not be negative");
                    }
                    os.write(encodeComponent(compval));
                }
            }
            oidEncoded = os.toByteArray();
        } catch (IOException e) {
            throw new OIDException("Failed to encode OID", e);
        }
    }

    /**
     * Encode an OID component as DER encoded subID.
     *
     * @param component OID component.
     * @return DER encoded subID.
     */
    protected static byte[] encodeComponent(int component) {

        byte[] componentBytes = DERInteger.toCompactByteArray(component);
        int componentBits = componentBytes.length * 8;
        int slices = componentBits / 7 + (componentBits % 7 > 0 ? 1 : 0);
        byte[] dest = new byte[slices];
        int destIdx = dest.length - 1;

        for (int i = 0; i < slices; i++) {

            byte slice = slice7bit(i * 7 + 7, componentBytes);

            if (i != 0) {
                /*
                 * All but the least significant byte have bit 8 set.
                 */
                slice = (byte) (Byte.toUnsignedInt(slice) | 0b10000000);
            }

            dest[destIdx--] = slice;
        }

        /*
         * If the remaining bits that were not a full 7 bit slice are all 0 then strip them from the result.
         */
        if (dest[0] == (byte) 0b10000000) {
            dest = Arrays.copyOfRange(dest, 1, dest.length);
        }

        return dest;
    }

    /**
     * Extract a 7 bit slice from a byte array.
     * <br>
     * The bitIdx may be up to 6 bits higher than the actual number of bits in the src array to extract the remainder
     * bits as a slice.
     *
     * @param bitIdx Upper bit index of slice. For instance bitIdx 7 would extract the slice from bit 7 to bit 0.
     * @param src    Byte array from which the 7 bit slice is extracted.
     * @return Extracted 7 bit slice.
     */
    protected static byte slice7bit(int bitIdx, byte[] src) {

        byte slice;

        int byteIdx = src.length - (bitIdx / 8) - 1;
        int lastByteIdx = src.length - ((bitIdx - 7) / 8) - 1;

        if (byteIdx == lastByteIdx) {

            /*
             * Extract a 7 bit slice that all contained in one byte.
             */

            byte mask = (byte) (0xFF >>> (8 - (bitIdx % 8)));
            slice = (byte) (src[byteIdx] & mask);
        } else {

            /*
             * Extract a 7 bit slice that's split over two bytes.
             */

            int merged = (byteIdx == -1 ? 0 : Byte.toUnsignedInt(src[byteIdx]) << 8) | Byte.toUnsignedInt(src[lastByteIdx]);
            int mask = 0b1111111 << (bitIdx % 8 + 1);
            slice = (byte) ((merged & mask) >>> (bitIdx % 8 + 1));
        }
        return slice;
    }

    /**
     * Get DER encoded OID.
     *
     * @return DER encoded OID.
     */
    public byte[] getEncoded() {
        return oidEncoded;
    }

    public String toString() {
        return oid;
    }
}
