/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import com.bagsvaerdcrypto.x690.ASN1Type;
import com.bagsvaerdcrypto.x690.DEROutputStream;
import com.bagsvaerdcrypto.x690.OID;
import com.bagsvaerdcrypto.x690.TLV;

import java.io.IOException;

/**
 * Key encoding.
 * <br>
 * Keys must be encoded through the {@link PublicKey#encode(PublicKeyEncodingScheme)} and
 * {@link PrivateKey#encode(PrivateKeyEncodingScheme)} methods. This is only a support class.
 *
 * @author Søren Thalbitzer Poulsen
 */
class KeyEncoding {

    /**
     * Encode a public key.
     *
     * @param pubKey         Public key to be encoded.
     * @param encodingScheme Key encoding scheme.
     * @return Encoded public key.
     */
    public static byte[] encodePublicKey(PublicKey pubKey, PublicKeyEncodingScheme encodingScheme) {
        byte[] encoded;
        switch (encodingScheme) {
            case DER_PKCS1:
                try {
                    encoded = encodePublicKeyDerPkcs1(pubKey);
                } catch (IOException e) {
                    throw new KeyEncodingException("Failed to encode public key", e);
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported public key encoding scheme");
        }

        return encoded;
    }

    /**
     * DER encode a PKCS1 public key.
     *
     * @param pubKey Public key to be encoded.
     * @return DER encoded PKCS1 public key.
     * @throws IOException
     */
    protected static byte[] encodePublicKeyDerPkcs1(PublicKey pubKey) throws IOException {

        byte[] encoded;

        /*
         * Write PKCS #1 "RSAPublicKey" sequence.
         */

        try (DEROutputStream inner = new DEROutputStream(); DEROutputStream outer = new DEROutputStream()) {
            inner.writeTLV(new TLV(ASN1Type.INT, pubKey.getN()));
            inner.writeTLV(new TLV(ASN1Type.INT, pubKey.getE()));
            outer.writeTLV(new TLV(ASN1Type.SEQ, inner.toByteArray()));
            encoded = outer.toByteArray();
        }
        return encoded;
    }

    /**
     * DER encode a private key.
     *
     * @param K              RSA private key.
     * @param encodingScheme Encoding scheme.
     * @return DER encoded private key.
     */
    public static byte[] encodePrivateKey(PrivateKey K, PrivateKeyEncodingScheme encodingScheme) {
        byte[] encoded;
        switch (encodingScheme) {
            case DER_PKCS1:
                try {
                    encoded = encodePrivateKeyDerPkcs1(K);
                } catch (IOException e) {
                    throw new KeyEncodingException("Failed to encode private key", e);
                }
                break;
            case DER_PKCS8:
                try {
                    encoded = encodePrivateKeyDerPkcs8(K);
                } catch (IOException e) {
                    throw new KeyEncodingException("Failed to encode private key", e);
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported private key encoding scheme");
        }
        return encoded;
    }

    /**
     * DER encode a PKCS1 private key.
     *
     * @return DER encoded PKCS1 private key.
     * @throws IOException
     */
    protected static byte[] encodePrivateKeyDerPkcs1(PrivateKey K) throws IOException {

        byte[] encoded;

        /*
         * Write PKCS #1 "RSAPrivateKey" sequence.
         */

        try (DEROutputStream inner = new DEROutputStream(); DEROutputStream outer = new DEROutputStream()) {

            inner.writeTLV(new TLV(ASN1Type.INT, 0)); // Version is 0 for two-prime factor keys.

            PrivateKeyCrt KCrt = null;
            if (K instanceof PrivateKeyCrt) {
                KCrt = (PrivateKeyCrt) K;
            }

            inner.writeTLV(new TLV(ASN1Type.INT, K.getN()));
            inner.writeTLV(new TLV(ASN1Type.INT, K.getE()));
            inner.writeTLV(new TLV(ASN1Type.INT, K.getD()));
            inner.writeTLV(new TLV(ASN1Type.INT, K.getP()));
            inner.writeTLV(new TLV(ASN1Type.INT, K.getQ()));
            inner.writeTLV(new TLV(ASN1Type.INT, KCrt != null ? KCrt.getdP() : null));
            inner.writeTLV(new TLV(ASN1Type.INT, KCrt != null ? KCrt.getdQ() : null));
            inner.writeTLV(new TLV(ASN1Type.INT, KCrt != null ? KCrt.getqInv() : null));
            outer.writeTLV(new TLV(ASN1Type.SEQ, inner.toByteArray()));
            encoded = outer.toByteArray();
        }

        return encoded;
    }

    /**
     * DER encode a PKCS8 private key.
     *
     * @param K Private key to be encoded.
     * @return DER PKCS8 encoded private key.
     * @throws IOException
     */
    protected static byte[] encodePrivateKeyDerPkcs8(PrivateKey K) throws IOException {

        byte[] encodedPkcs1 = encodePrivateKeyDerPkcs1(K), encodedPkcs8;

        /*
         * Write PKCS #8 "PrivateKeyInfo" sequence.
         */

        try (DEROutputStream inner = new DEROutputStream(); DEROutputStream outer = new DEROutputStream()) {
            inner.writeTLV(new TLV(ASN1Type.INT, 0));
            inner.writeTLV(new TLV(ASN1Type.SEQ, encodeAlgorithmIdentifierBody(new OID("1.2.840.113549.1.1.1"))));
            inner.writeTLV(new TLV(ASN1Type.OCTSTR, encodedPkcs1));
            outer.writeTLV(new TLV(ASN1Type.SEQ, inner.toByteArray()));
            encodedPkcs8 = outer.toByteArray();
        }

        return encodedPkcs8;
    }

    /**
     * DER encode algorithm identifier sequence body.
     *
     * @param oid OID.
     * @return DER encoded algorithm identifier sequence body.
     * @throws IOException
     */
    protected static byte[] encodeAlgorithmIdentifierBody(OID oid) throws IOException {
        try (DEROutputStream inner = new DEROutputStream()) {
            inner.writeTLV(new TLV(oid));
            inner.writeTLV(new TLV(ASN1Type.NULL));
            return inner.toByteArray();
        }
    }
}
