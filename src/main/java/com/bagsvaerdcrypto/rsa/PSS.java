/*
 * Copyright (C) 2021, Søren Thalbitzer Poulsen. All rights reserved.
 *
 * This code is subject to the terms of the GNU General Public License Version 2
 * with "Classpath" exception. The terms are listed in the LICENSE file that
 * accompanies this work. You may not distribute and/or use this code except in
 * compliance with the license.
 */

package com.bagsvaerdcrypto.rsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Probabilistic Signature Scheme for encoding RSA signatures.
 *
 * @author Søren Thalbitzer Poulsen
 */
public class PSS {

    private final SignatureParameterPssImpl signParam;

    /*
     * Mask Generating Function.
     */
    private final MGF mgf;

    private final SecureRandom RND = new SecureRandom();

    private static final byte[] PADDING1 = new byte[8];

    /**
     * Create PSS instance.
     *
     * @param signParam PSS signature parameter.
     */
    public PSS(SignatureParameterPssImpl signParam) {
        this.signParam = signParam;
        mgf = new MGF(signParam.getMgfHashAlgorithm());
    }

    /**
     * Encode mHash which is the message M that has already been hashed.
     * <p>
     * RFS-8017: "Produce an encoded message EM of length ceil ((modBits - 1)/8) octets such that the bit length of the
     * integer OS2IP (EM) is at most modBits - 1, where modBits is the length in bits of the RSA modulus n".
     *
     * @param mHash  Hash of message M to be encoded.
     * @param emBits "modBits - 1" where modBits is the length in bits of the RSA modulus n.
     * @return PSS encoded message EM.
     */
    public byte[] encode(byte[] mHash, int emBits) {

        /*
         * "emLen = ceil(emBits/8)"
         */

        int emLen = (emBits + 7) / 8;

        /*
         * "Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string."
         */

        int sLen = signParam.getsLen();
        byte[] salt = new byte[sLen];
        this.RND.nextBytes(salt);

        /*
         * "Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt; M' is an octet string of length 8 + hLen + sLen with
         * eight initial zero octets"
         *
         * "Let H = Hash(M'), an octet string of length hLen"
         */

        MessageDigest hash;
        try {
            hash = MessageDigest.getInstance(signParam.getPssHashAlgorithm().getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("Failed to create hash", e);
        }

        hash.update(PADDING1);
        hash.update(mHash);
        hash.update(salt);
        byte[] H = hash.digest();

        /*
         * "Generate an octet string PS consisting of emLen - sLen - hLen - 2 zero octets. The length of PS may be 0"
         *
         * "Let DB = PS || 0x01 || salt; DB is an octet string of length emLen - hLen - 1"
         */

        int hLen = hash.getDigestLength();

        byte[] DB = new byte[emLen - hLen - 1];
        DB[DB.length - sLen - 1] = 1;

        System.arraycopy(salt, 0, DB, DB.length - sLen, sLen);

        /*
         * "Let dbMask = MGF(H, emLen - hLen - 1)"
         */

        byte[] dbMask = mgf.generateMask(H, emLen - hLen - 1);

        /*
         * "Let maskedDB = DB xor dbMask"
         */

        byte[] maskedDB = ByteArray.xor(DB, dbMask);

        /*
         * "Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero".
         *
         * Note that emLen was set to a whole multiple of 8 which might be up to 7 bits longer than emBits. This
         * simply zeroes out those extra bits.
         */

        int zeros = 8 * emLen - emBits;
        if (zeros != 0) {
            maskedDB[0] &= (byte) (0xFF >>> zeros);
        }

        /*
         * "Let EM = maskedDB || H || 0xbc"
         */

        byte[] EM = new byte[emLen];
        System.arraycopy(maskedDB, 0, EM, 0, maskedDB.length);
        System.arraycopy(H, 0, EM, maskedDB.length, hLen);
        EM[emLen - 1] = (byte) 0xBC;

        return EM;
    }

    /**
     * Verify the the PSS encoded message EM of the signature and mHash of the message M to be verified are consistent.
     *
     * @param mHash  Hash of the message M to be verified.
     * @param EM     PSS encoded message of the signature.
     * @param emBits "modBits - 1" where modBits is the length in bits of the RSA modulus n.
     * @return True if encoded message EM and mHash of the message M are consistent.
     */
    public boolean verify(byte[] mHash, byte[] EM, int emBits) {

        /*
         * "If emLen < hLen + sLen + 2, output "inconsistent" and stop".
         */

        int emLen = EM.length, hLen = mHash.length, sLen = signParam.getsLen();
        if (emLen < hLen + sLen + 2) {
            return false;
        }

        /*
         * "If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop".
         */

        if (EM[emLen - 1] != (byte) 0xBC) {
            return false;
        }

        /*
         * "Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets".
         */

        byte[] maskedDB = Arrays.copyOf(EM, emLen - hLen - 1);
        byte[] H = Arrays.copyOfRange(EM, emLen - hLen - 1, emLen - 1);

        /*
         * "If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not all equal to zero, output
         * 'inconsistent' and stop".
         */

        int zeros = 8 * emLen - emBits;
        if (zeros != 0) {
            if ((maskedDB[0] & (byte) (0xFF << (8 - zeros))) != 0) {
                return false;
            }
        }

        /*
         * "Let dbMask = MGF(H, emLen - hLen - 1)".
         */

        byte[] dbMask = mgf.generateMask(H, emLen - hLen - 1);

        /*
         * "Let DB = maskedDB \xor dbMask".
         */

        byte[] DB = ByteArray.xor(maskedDB, dbMask);

        /*
         * "Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero".
         */

        if (zeros != 0) {
            DB[0] &= (byte) (0xFF >>> zeros);
        }

        /*
         * "If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero or if the octet at position
         * emLen - hLen - sLen - 1 (the leftmost position is "position 1") does not have hexadecimal value 0x01,
         * output "inconsistent" and stop".
         */


        int l = emLen - hLen - sLen - 2;
        for (int i = 0; i < l; ++i) {
            if (DB[i] != 0) {
                return false;
            }
        }

        if (DB[emLen - hLen - sLen - 2] != 1) {
            return false;
        }

        /*
         * "Let salt be the last sLen octets of DB".
         */

        byte[] salt = Arrays.copyOfRange(DB, DB.length - sLen, DB.length);

        /*
         * "Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;M' is an octet string of length 8 + hLen + sLen with
         * eight initial zero octets".
         *
         * "Let H' = Hash(M'), an octet string of length hLen".
         */

        MessageDigest hash;
        try {
            hash = MessageDigest.getInstance(signParam.getPssHashAlgorithm().getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("failed to create hash", e);
        }

        hash.update(PADDING1);
        hash.update(mHash);
        hash.update(salt);
        byte[] Hmark = hash.digest();

        /*
         * "If H = H', output 'consistent'.  Otherwise, output 'inconsistent'".
         */

        return MessageDigest.isEqual(H, Hmark);
    }

}
