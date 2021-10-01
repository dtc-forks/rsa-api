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
import com.bagsvaerdcrypto.x690.DERInputStream;
import com.bagsvaerdcrypto.x690.TLV;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Key decoding.
 * <br>
 * Keys must be decoded through the {@link KeyFactory}. This is only a support class.
 *
 * @author Søren Thalbitzer Poulsen
 */
class KeyDecoding {

    /*
     * RSA OID.
     */
    protected static final byte[] OID_RSA = {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01};

    /**
     * Decode public key.
     *
     * @param key            Public key to decode.
     * @param encodingScheme Encoding scheme.
     * @return Decoded public key.
     */
    public static PublicKey decodePublicKey(byte[] key, PublicKeyEncodingScheme encodingScheme) {
        PublicKey publicKey;
        switch (encodingScheme) {
            case DER_PKCS1:
                publicKey = decodePublicKeyDerPkcs1(key);
                break;
            default:
                throw new IllegalArgumentException("Unsupported key encoding scheme");
        }
        return publicKey;
    }

    /**
     * DER decode PKCS1 public key.
     *
     * @param key Public key to be decoded.
     * @return Decoded public key.
     */
    protected static PublicKey decodePublicKeyDerPkcs1(byte[] key) {
        PublicKey publicKey;
        try (DERInputStream pkcs1IS = new DERInputStream(key)) {
            TLV seqTLV = pkcs1IS.readTLV();
            if (seqTLV.getType() != ASN1Type.SEQ) {
                throw new KeyDecodingException("Expected pkcs1 sequence tag");
            }
            try (DERInputStream pkcs1InnerIS = new DERInputStream(seqTLV.getValue())) {
                BigInteger n = readBigInteger(pkcs1InnerIS);
                BigInteger e = readBigInteger(pkcs1InnerIS);
                KeyFactory keyFactory = KeyFactory.getInstance();
                publicKey = keyFactory.createPublicKey(e, n);
            }
        } catch (IOException ex) {
            throw new KeyDecodingException("Failed to decode key", ex);
        }
        return publicKey;
    }

    /**
     * Decode a private key.
     * <br>
     * PKCS8 and PKCS1 encoded keys may contain both a public and private key but some frameworks only store the private
     * key.
     *
     * @param key            DER encoded private key.
     * @param encodingScheme Encoding scheme.
     * @return KeyPair containing the decoded key or keys.
     */
    public static KeyPair decodePrivateKey(byte[] key, PrivateKeyEncodingScheme encodingScheme) {
        KeyPair keyPair;
        switch (encodingScheme) {
            case DER_PKCS8:
                keyPair = decodePrivateKeyDerPkcs8(key);
                break;
            case DER_PKCS1:
                keyPair = decodePrivateKeyDerPkcs1(key);
                break;
            default:
                throw new IllegalArgumentException("Unsupported key encoding scheme");
        }
        return keyPair;
    }

    /**
     * Decode a DER encoded PKCS1 private key.
     *
     * @param key DER encoded PKCS1 private key.
     * @return Decoded KeyPair.
     */
    protected static KeyPair decodePrivateKeyDerPkcs1(byte[] key) {
        KeyPair keyPair;
        try (DERInputStream pkcs1IS = new DERInputStream(key)) {
            TLV seqTLV = pkcs1IS.readTLV();
            if (seqTLV.getType() != ASN1Type.SEQ) {
                throw new KeyDecodingException("Expected pkcs1 sequence tag");
            }
            try (DERInputStream pkcs1InnerIS = new DERInputStream(seqTLV.getValue())) {
                TLV pkcs1VersionTLV = pkcs1InnerIS.readTLV();
                if (pkcs1VersionTLV.getType() != ASN1Type.INT) {
                    throw new KeyDecodingException("Expected pkcs1 version");
                }
                if (pkcs1VersionTLV.getIntValue() != 0) {
                    throw new KeyDecodingException("Expected two-prime pkcs1 version key");
                }
                BigInteger n, e, d, p, q, dP, dQ, qInv;
                n = readBigInteger(pkcs1InnerIS);
                e = readBigInteger(pkcs1InnerIS);
                d = readBigInteger(pkcs1InnerIS);
                p = readBigInteger(pkcs1InnerIS);
                q = readBigInteger(pkcs1InnerIS);
                dP = readBigInteger(pkcs1InnerIS);
                dQ = readBigInteger(pkcs1InnerIS);
                qInv = readBigInteger(pkcs1InnerIS);
                KeyFactory keyFactory = KeyFactory.getInstance();
                keyPair = new KeyPair(keyFactory.createPrivateKey(d, e, n, p, q, dP, dQ, qInv), keyFactory.createPublicKey(e, n));
            }
        } catch (IOException ex) {
            throw new KeyDecodingException("Failed to decode key", ex);
        }
        return keyPair;
    }

    /**
     * Decode a DER encoded PKCS8 private key.
     *
     * @param key DER encoded PKCS8 private key.
     * @return Decoded KeyPair.
     */
    protected static KeyPair decodePrivateKeyDerPkcs8(byte[] key) {
        KeyPair keyPair;
        try (DERInputStream pkcs8IS = new DERInputStream(key)) {
            TLV tlv = pkcs8IS.readTLV();
            if (tlv.getType().getTag() == ASN1Type.SEQ.getTag()) {
                try (DERInputStream innerPkcs8IS = new DERInputStream(tlv.getValue())) {
                    TLV versionTLV = innerPkcs8IS.readTLV();
                    if (versionTLV.getType() != ASN1Type.INT) {
                        throw new KeyDecodingException("Expected version tag");
                    }
                    if (versionTLV.getIntValue() != 0) {
                        throw new KeyDecodingException("Unsupported version number");
                    }
                    TLV algoSeqTLV = innerPkcs8IS.readTLV();
                    if (algoSeqTLV.getType() != ASN1Type.SEQ) {
                        throw new KeyDecodingException("Expected algorithm sequence tag");
                    }
                    try (DERInputStream algoIS = new DERInputStream(algoSeqTLV.getValue())) {
                        TLV oidTLV = algoIS.readTLV();
                        if (oidTLV.getType().getTag() != ASN1Type.OID.getTag()) {
                            throw new KeyDecodingException("Expected algorithm OID");
                        }
                        if (!MessageDigest.isEqual(oidTLV.getValue(), OID_RSA)) {
                            throw new KeyDecodingException("Unsupported algorithm OID");
                        }
                    }
                    TLV octstrTLV = innerPkcs8IS.readTLV();
                    if (octstrTLV.getType() != ASN1Type.OCTSTR) {
                        throw new KeyDecodingException("Expected octet string with pkcs1 encoded key");
                    }
                    keyPair = decodePrivateKeyDerPkcs1(octstrTLV.getValue());
                }
            } else {
                throw new KeyDecodingException("Expected sequence tag");
            }
        } catch (IOException e) {
            throw new KeyDecodingException("Failed to decode key", e);
        }
        return keyPair;
    }

    /**
     * Read a BigInteger from a DER encoded input stream.
     *
     * @param derInputStream DER encoded input stream.
     * @return BigInteger.
     * @throws IOException
     */
    protected static BigInteger readBigInteger(DERInputStream derInputStream) throws IOException {
        TLV modulusTLV = derInputStream.readTLV();
        if (modulusTLV.getType() != ASN1Type.INT) {
            throw new KeyDecodingException("Expected integer");
        }
        return modulusTLV.getBigIntegerValue();
    }

}
