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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * RSA signature implementation based on Probabilistic Signature Scheme.
 *
 * @author Søren Thalbitzer Poulsen
 */
class SignaturePssImpl extends Signature {

    /*
     * Hash of message M.
     */
    private final MessageDigest mHash;

    /*
     * Probabilistic Signature Scheme encoding.
     */
    private final PSS pss;

    /**
     * Construct SignaturePssImpl.
     *
     * @param signParam PSS signature parameter.
     */
    public SignaturePssImpl(SignatureParameterPssImpl signParam) {
        this.pss = new PSS(signParam);
        try {
            mHash = MessageDigest.getInstance(signParam.getPssHashAlgorithm().getFIPSName());
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException("Failed to create hash", e);
        }
    }

    @Override
    public void update(byte[] M) {
        mHash.update(M);
    }

    @Override
    public byte[] sign(PrivateKey K) {

        /*
         * "Apply the EMSA-PSS encoding operation to the message M".
         */
        byte[] EM = pss.encode(mHash.digest(), K.getN().bitLength() - 1);

        /*
         * "Convert the encoded message EM to an integer message representative m".
         */

        BigInteger m = Crypt.OS2IP(EM);

        /*
         * Blind message m before signing to prevent timing attack.
         */

        Blinding blinding = K.getBlinding();
        m = blinding.blind(m);

        /*
         * "Apply the RSASP1 signature primitive to the RSA private key K and the message representative m to produce an
         * integer signature representative s".
         */

        BigInteger s = RSASP1(K, m);

        /*
         * Unblind after signing.
         */

        s = blinding.unblind(s);

        /*
         * "Convert the signature representative s to a signature S of length k octets".
         */
        return Crypt.I2OSP(s, K.getLengthInOctets());
    }

    @Override
    public boolean verify(PublicKey pubKey, byte[] S) {

        /*
         * "Length checking: If the length of the signature S is not k octets, output "invalid signature" and stop".
         */

        if (S.length != pubKey.getLengthInOctets()) {
            return false;
        }

        /*
         * "Convert the signature S to an integer signature representative s".
         */

        BigInteger s = Crypt.OS2IP(S);

        /*
         * "Apply the RSAVP1 verification primitive to the RSA public key (n, e) and the signature representative s to
         * produce an integer message representative m".
         */

        BigInteger m = RSAVP1(pubKey, s);

        /*
         * "Convert the message representative m to an encoded message EM of length emLen = ceil ((modBits - 1)/8)
         * octets, where modBits is the length in bits of the RSA modulus n".
         */

        int emLen = (pubKey.getN().bitLength() - 1 + 7) / 8;
        byte[] EM;
        try {
            EM = Crypt.I2OSP(m, emLen);
        } catch (CryptException e) {
            throw new SignatureException("Invalid signature");
        }

        /*
         * "EMSA-PSS verification: Apply the EMSA-PSS verification operation to the message M and the encoded message EM
         * to determine whether they are consistent".
         */

        return pss.verify(mHash.digest(), EM, pubKey.getN().bitLength() - 1);
    }

    /**
     * RSA signing primitive.
     *
     * @param m Message representative, an integer between 0 and n - 1.
     * @param K RSA private key.
     * @return Signature representative, an integer between 0 and n - 1.
     */
    protected BigInteger RSASP1(PrivateKey K, BigInteger m) {

        if (m.compareTo(K.getN()) >= 0) {
            throw new SignatureException("message representative out of range");
        }

        BigInteger s;

        if (K instanceof PrivateKeyCrt) {
            PrivateKeyCrt crtK = (PrivateKeyCrt) K;

            /*
             * "Let m_1 = c^dP mod p and m_2 = c^dQ mod q."
             */

            BigInteger m_1 = m.modPow(crtK.getdP(), crtK.getP());
            BigInteger m_2 = m.modPow(crtK.getdQ(), crtK.getQ());

            /*
             * "Let h = (m_1 - m_2) * qInv mod p."
             */

            BigInteger h = m_1.subtract(m_2).multiply(crtK.getqInv()).mod(crtK.getP());

            /*
             * "Let m = m_2 + q * h."
             */

            s = crtK.getQ().multiply(h).add(m_2);
        } else {
            s = m.modPow(K.getD(), K.getN());
        }
        return s;
    }

    /**
     * RSA verification primitive.
     *
     * @param pubKey RSA public key.
     * @param s      Signature representative, an integer between 0 and n - 1.
     * @return m message representative, an integer between 0 and n - 1.
     */
    protected BigInteger RSAVP1(PublicKey pubKey, BigInteger s) {
        if (s.compareTo(pubKey.getN()) >= 0) {
            throw new SignatureException("Invalid signature");
        }
        return s.modPow(pubKey.getE(), pubKey.getN());
    }

}
