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

/**
 * RSA key factory implementation based on Euler's Phi function to generate RSA key exponents e and d.
 * <p>
 * The use of Euler's Phi function is not prescribed in RFC 8017 "PKCS #1: RSA Cryptography Specifications" but if often
 * used in textbook examples of RSA. The Euler implementation can be used interchangeably with no loss of runtime
 * compatibility with other implementations of RFC 8017.
 * <p>
 * In addition to key exponent constraints set by RFC 8017, further constraints are applied to generated keys as
 * specified by {@link KeyFactorySpec }.
 * <p>
 *   <table>
 *     <tr><th>KeyFactorySpec</th><th>Permitted nlen*</th><th>Exponent e</th><th>Exponent d</th>
 *     <tr><td>DEFAULT</td><td>nlen >= 1024</td><td>e=65537.</td><td>2^(nlen/2) &lt; d &lt; phi(n)</td></tr>
 *     <tr><td>RANDOM</td><td>nlen >= 1024</td><td>Random number in range 2^16 < e < phi(n), satisfying gcd(e, phi(n)) == 1.</td><td>2^(nlen/2) &lt; d &lt; phi(n)<</td></tr>
 *     <tr><td>RANDOM_STRICT - Unsupported by the Euler key factory</td><td></td><td></td><td></td></tr>
 *   </table>
 * <p>
 *   * nlen is the length of the RSA modulus n.
 *
 * @author Søren Thalbitzer Poulsen
 */
class KeyFactoryEulerImpl extends KeyFactory {

    /*
     * Singleton instance.
     */
    private static final KeyFactoryEulerImpl INSTANCE = new KeyFactoryEulerImpl();

    protected KeyFactoryEulerImpl() {
    }

    /**
     * Get instance of Euler key factory.
     *
     * @return  Instance of Euler key factory.
     */
    protected static KeyFactoryEulerImpl getEulerInstance() {
        return INSTANCE;
    }

    @Override
    public KeyPair generateKeyPair(int nlen, KeyFactorySpec keyFactorySpec) {

        if (nlen < NLEN_MIN) {
            throw new KeyException("Key length must be greater or equal to " + NLEN_MIN);
        }

        if (keyFactorySpec == KeyFactorySpec.RANDOM_STRICT) {
            throw new KeyException("RSA public exponent spec RANDOM_STRICT is not supported with the Euler key factory");
        }

        BigInteger p, q, n, e, d;
        do {
            do {
                p = BigInteger.probablePrime(nlen / 2, rnd);
                q = BigInteger.probablePrime(nlen / 2, rnd);
                n = p.multiply(q);
            }
            while (n.bitLength() != nlen);
            BigInteger pOne = p.subtract(BigInteger.ONE), qOne = q.subtract(BigInteger.ONE);
            BigInteger phi = pOne.multiply(qOne);
            switch (keyFactorySpec) {
                case DEFAULT:
                    e = BigInteger.valueOf(65537);
                    break;
                case RANDOM: {
                    BigInteger eLowerBound = BigInteger.valueOf(65536);
                    do
                        e = new BigInteger(phi.bitLength(), rnd);
                    while (e.compareTo(eLowerBound) < 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
                    break;
                }
                default:
                    throw new KeyException("Unsupported public exponent spec");
            }
            d = e.modInverse(phi);
        }
        while (d.compareTo(BigInteger.valueOf(2).pow(n.bitLength() / 2)) <= 0);

        return new KeyPair(createPrivateKey(d, e, n, p, q), new PublicKey(e, n));
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey K) {
        BigInteger po = K.getP().subtract(BigInteger.ONE), qo = K.getQ().subtract(BigInteger.ONE);
        BigInteger phi = po.multiply(qo);
        return this.createPublicKey(K.getD().modInverse(phi), K.getN());
    }
}
