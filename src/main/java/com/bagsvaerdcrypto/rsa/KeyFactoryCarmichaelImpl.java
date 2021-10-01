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
 * RSA key factory implementation based on Carmichael's lambda function to generate RSA key exponents e and d.
 * <p>
 * The use of lambda is prescribed in RFC 8017 "PKCS #1: RSA Cryptography Specifications".
 * <p>
 * In addition to key exponent constraints set by RFC 8017, further constraints are applied to generated keys as
 * determined by the {@link KeyFactorySpec }.
 * <p>
 *   <table>
 *     <tr><th>KeyFactorySpec</th><th>Permitted nlen*</th><th>Exponent e</th><th>Exponent d</th>
 *     <tr><td>DEFAULT</td><td>nlen >= 1024.</td><td>e=65537.</td><td>2^(nlen/2) &lt; d &lt; lambda(n)</td></tr>
 *     <tr><td>RANDOM</td><td>nlen >= 1024.</td><td>Random, odd number in range 2^16 < e < n-1, satisfying gcd(e, lambda(n)) == 1.</td><td>2^(nlen/2) &lt; d &lt; lambda(n)</td></tr>
 *     <tr><td>RANDOM_STRICT</td><td>Either 1024, 2048, 3072 or 4096.</td><td>Random, odd number in range 2^16 < e < 2^256, satisfying gcd(e, lambda(n)) == 1.</td><td>2^(nlen/2) &lt; d &lt; lambda(n)</td></tr>
 *   </table>
 * <p>
 *     * nlen is the length of the RSA modulus n.
 *
 * @author Søren Thalbitzer Poulsen
 */
class KeyFactoryCarmichaelImpl extends KeyFactory {

    private static final int[] LENGTH_PERMITTED_STRICT = {1024, 2048, 3072, 4096};

    /*
     * Singleton instance.
     */
    private static final KeyFactoryCarmichaelImpl INSTANCE = new KeyFactoryCarmichaelImpl();

    protected KeyFactoryCarmichaelImpl() {
    }

    /**
     * Get instance of Carmichael key factory.
     *
     * @return  Instance of Carmichael key factory.
     */
    protected static KeyFactoryCarmichaelImpl getCarmichaelInstance() {
        return INSTANCE;
    }

    @Override
    public KeyPair generateKeyPair(int nlen, KeyFactorySpec keyFactorySpec) {

        if (nlen < NLEN_MIN) {
            throw new KeyException("Key length must be greater or equal to " + NLEN_MIN);
        }

        if (keyFactorySpec == KeyFactorySpec.RANDOM_STRICT) {
            if (!isValidStrictLength(nlen)) {
                throw new KeyException("Unsupported key length for RANDOM_STRICT");
            }
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
            BigInteger lambda = BigMath.lcm(pOne, qOne);
            switch (keyFactorySpec) {
                case DEFAULT:
                    e = BigInteger.valueOf(65537);
                    break;
                case RANDOM: {
                    BigInteger eLowerBound = BigInteger.valueOf(65536);
                    BigInteger eUpperBound = n.subtract(BigInteger.ONE);
                    do {
                        e = new BigInteger(eUpperBound.bitLength(), rnd);
                    }
                    while (!e.testBit(0) || e.compareTo(eLowerBound) <= 0 || e.compareTo(eUpperBound) > 0 || !e.gcd(lambda).equals(BigInteger.ONE));
                    break;
                }
                case RANDOM_STRICT: {
                    BigInteger eLowerBoundStrict = BigInteger.valueOf(65536);
                    BigInteger eUpperBoundStrict = BigInteger.valueOf(2).pow(256);
                    do {
                        e = new BigInteger(eUpperBoundStrict.bitLength(), rnd);
                    }
                    while (!e.testBit(0) || e.compareTo(eLowerBoundStrict) <= 0 || e.compareTo(eUpperBoundStrict) >= 0 || !e.gcd(lambda).equals(BigInteger.ONE));
                    break;
                }
                default:
                    throw new KeyException("Unsupported public exponent spec");
            }
            d = e.modInverse(lambda);
        }
        while (d.compareTo(BigInteger.valueOf(2).pow(n.bitLength() / 2)) <= 0);

        return new KeyPair(createPrivateKey(d, e, n, p, q), new PublicKey(e, n));
    }

    /**
     * Determine if the length of the RSA modulus n is a value permitted with strict rules.
     *
     * @param nlen RSA modulus n length.
     * @return True if nlen is a permitted with strict rules.
     */
    protected boolean isValidStrictLength(int nlen) {
        boolean validStrictLength = false;
        for (int l : LENGTH_PERMITTED_STRICT) {
            if (nlen == l) {
                validStrictLength = true;
                break;
            }
        }
        return validStrictLength;
    }

    @Override
    public PublicKey derivePublicKey(PrivateKey K) {
        BigInteger pOne = K.getP().subtract(BigInteger.ONE), qOne = K.getQ().subtract(BigInteger.ONE);
        BigInteger lambda = BigMath.lcm(pOne, qOne);
        return this.createPublicKey(K.getD().modInverse(lambda), K.getN());
    }
}

