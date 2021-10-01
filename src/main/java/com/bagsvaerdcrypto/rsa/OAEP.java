/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Optimal Asymmetric Encryption Primitive encoding scheme.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class OAEP {

    private final SecureRandom rnd = new SecureRandom();

    /*
     * Mask generating function.
     */
    private final MGF mgf1;

    /*
     * Hash of the optional string L when its empty.
     */
    private final byte[] lHash;

    /*
     * Hash length in octets.
     */
    private final int hLen;

    /*
     * Sha of the optional label L. The optional label L is always empty in RFC 8017.
     */
    private static final byte[] SHA_1_EMPTY_L = Crypt.I2OSP(new BigInteger("da39a3ee5e6b4b0d3255bfef95601890afd80709", 16), 20),
            SHA_256_EMPTY_L = Crypt.I2OSP(new BigInteger("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 16), 32),
            SHA_384_EMPTY_L = Crypt.I2OSP(new BigInteger("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", 16), 48),
            SHA_512_EMPTY_L = Crypt.I2OSP(new BigInteger("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 16), 64),
            SHA_512_224_EMPTY_L = Crypt.I2OSP(new BigInteger("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", 16), 28),
            SHA_512_256_EMPTY_L = Crypt.I2OSP(new BigInteger("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", 16), 32);

    /**
     * Create an OAEP instance with a specified hash function for the optional label L and the default Mask Generating
     * Function MGF1SHA1.
     *
     * @param labelHashAlgorithm Hash function for the optional label L.
     */
    public OAEP(HashAlgorithm labelHashAlgorithm) {
        this(labelHashAlgorithm, HashAlgorithm.SHA1);
    }

    /**
     * Create an OAEP instance.
     *
     * @param labelHashAlgorithm Hash function for the optional label L.
     * @param mgfHashAlgorithm   Hash function for the Mask Generating Function.
     */
    public OAEP(HashAlgorithm labelHashAlgorithm, HashAlgorithm mgfHashAlgorithm) {
        mgf1 = new MGF(mgfHashAlgorithm);
        lHash = getHashOfOptionalL(labelHashAlgorithm);
        hLen = lHash.length;
    }

    /**
     * Encode message M.
     *
     * @param M Message, an octet string.
     * @param k Length in octets of the RSA modulus n.
     */
    public byte[] encode(byte[] M, int k) {

        /*
         * "If mLen > k - 2hLen - 2, output "message too long" and stop"
         */

        if (M.length > k - 2 * hLen - 2) {
            throw new IllegalArgumentException("Message too long");
        }

        /*
         * "Concatenate lHash, PS, a single octet with hexadecimal value 0x01, and the message M to form a data block DB
         * of length k - hLen - 1 octets as
         * DB = lHash || PS || 0x01 || M."
         */

        byte[] DB = new byte[k - hLen - 1];
        System.arraycopy(lHash, 0, DB, 0, hLen);
        DB[DB.length - M.length - 1] = 1;
        System.arraycopy(M, 0, DB, DB.length - M.length, M.length);

        /*
         * "Generate a random octet string seed of length hLen."
         */

        byte[] seed = new byte[hLen];
        rnd.nextBytes(seed);

        /*
         * "Let dbMask = MGF(seed, k - hLen - 1)."
         */

        byte[] dbMask = mgf1.generateMask(seed, k - hLen - 1);

        /*
         * "Let maskedDB = DB \xor dbMask."
         */

        byte[] maskedDB = ByteArray.xor(DB, dbMask);

        /*
         * "Let seedMask = MGF(maskedDB, hLen)."
         */

        byte[] seedMask = mgf1.generateMask(maskedDB, hLen);

        /*
         * "Let maskedSeed = seed \xor seedMask."
         */

        byte[] maskedSeed = ByteArray.xor(seed, seedMask);

        /*
         *  "Concatenate a single octet with hexadecimal value 0x00, maskedSeed, and maskedDB to form an encoded message
         *  EM of length k octets as
         *  EM = 0x00 || maskedSeed || maskedDB."
         */

        byte[] EM = new byte[k];
        System.arraycopy(maskedSeed, 0, EM, 1, maskedSeed.length);
        System.arraycopy(maskedDB, 0, EM, 1 + maskedSeed.length, maskedDB.length);

        return EM;
    }

    /**
     * Decode message EM.
     *
     * @param EM Encoded message, an octet string.
     * @param k  Length in octets of the RSA modulus n.
     * @return Message, an octet string of length mLen, where mLen &lt;= k - 2hLen - 2.
     */
    public byte[] decode(byte[] EM, int k) {

        /*
         * "Separate the encoded message EM into a single octet Y, an octet string maskedSeed of length hLen, and an
         * octet string maskedDB of length k - hLen - 1 as
         * EM = Y || maskedSeed || maskedDB."
         */

        byte[] maskedSeed = new byte[hLen];
        System.arraycopy(EM, 1, maskedSeed, 0, hLen);

        byte[] maskedDB = new byte[k - hLen - 1];
        System.arraycopy(EM, hLen + 1, maskedDB, 0, k - hLen - 1);

        /*
         * "Let seedMask = MGF(maskedDB, hLen)"
         */

        byte[] seedMask = mgf1.generateMask(maskedDB, hLen);

        /*
         * "Let seed = maskedSeed \xor seedMask"
         */

        byte[] seed = ByteArray.xor(maskedSeed, seedMask);

        /*
         * "Let dbMask = MGF(seed, k - hLen - 1)"
         */

        byte[] dbMask = mgf1.generateMask(seed, k - hLen - 1);

        /*
         * "Let DB = maskedDB \xor dbMask"
         */

        byte[] DB = ByteArray.xor(maskedDB, dbMask);

        /*
         * "Separate DB into an octet string lHash' of length hLen, a (possibly empty) padding string PS consisting of
         * octets with hexadecimal value 0x00, and a message M as
         *   DB = lHash' || PS || 0x01 || M"
         *
         * "If there is no octet with hexadecimal value 0x01 to separate PS from M, if lHash does not equal lHash', or if
         * Y is nonzero, output "decryption error" and stop.  (See the note below.)"
         *
         * "Note: Care must be taken to ensure that an opponent cannot distinguish the different error conditions"
         */

        boolean decryptionError = false;

        int mPos = -1;
        for (int i = hLen; i < DB.length; i++) {
            if (mPos == -1) {
                if (DB[i] == 1) {
                    mPos = i;
                } else if (DB[i] != 0) {
                    decryptionError = true;
                    // Do not terminate loop.
                }
            }
        }

        for (int i = 0; i < hLen; i++) {
            if (DB[i] != lHash[i]) {
                decryptionError = true;
                // Do not terminate loop
            }
        }

        if (EM[0] != 0) {
            decryptionError = true;
        }

        if (decryptionError) {
            throw new CryptException("decryption error");
        }

        return Arrays.copyOfRange(DB, mPos + 1, DB.length);
    }

    /**
     * Get hash of optional label L.
     *
     * @param labelHashAlgorithm Hash algorithm of the optional label L.
     * @return Hash of optional label L.
     */
    protected static byte[] getHashOfOptionalL(HashAlgorithm labelHashAlgorithm) {
        byte[] hash;
        switch (labelHashAlgorithm) {
            case SHA1:
                hash = SHA_1_EMPTY_L;
                break;
            case SHA256:
                hash = SHA_256_EMPTY_L;
                break;
            case SHA384:
                hash = SHA_384_EMPTY_L;
                break;
            case SHA512:
                hash = SHA_512_EMPTY_L;
                break;
            case SHA512_224:
                hash = SHA_512_224_EMPTY_L;
                break;
            case SHA512_256:
                hash = SHA_512_256_EMPTY_L;
                break;
            default:
                throw new CryptException("Unsupported hash " + labelHashAlgorithm.getFIPSName());
        }
        return hash;
    }

}
