/*
MIT License

Copyright (c) 2021 Marco Tröster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Numerics;

namespace PrimeGen
{
    /// <summary>
    /// Representing a key pair that can be used for RSA encryption.
    /// </summary>
    public struct RsaKeypair
    {
        /// <summary>
        /// Representing the public RSA key, commonly called e.
        /// </summary>
        public BigInteger PubKey { get; set; }

        /// <summary>
        /// Representing the private RSA key, commonly called d.
        /// </summary>
        public BigInteger PrivKey { get; set; }

        /// <summary>
        /// Representing the RSA modul, commonly called N.
        /// </summary>
        public BigInteger Modul { get; set; }
    }

    /// <summary>
    /// This class provides basic RSA key pair generation functionality.
    /// </summary>
    public static class RsaUtils
    {
        /// <summary>
        /// Perform the standard RSA encryption for the given plain text (as bytes).
        /// </summary>
        /// <param name="plain">The plain text to be encrypted.</param>
        /// <param name="pubKey">The public key used for encryption.</param>
        /// <param name="modul">The RSA modul used for encryption.</param>
        /// <returns>the cipher text (as bytes)</returns>
        public static byte[] Encrypt(byte[] plain, BigInteger pubKey, BigInteger modul)
        {
            // encrypt the plain message using RSA such that c = m^e
            return BigInteger.ModPow(new BigInteger(plain), pubKey, modul).ToByteArray();
        }

        /// <summary>
        /// Perform the standard RSA decryption for the given cipher text (as bytes).
        /// </summary>
        /// <param name="cipher">The cipher text to be decrypted.</param>
        /// <param name="privKey">The private key used for decryption.</param>
        /// <param name="modul">The RSA modul used for decryption.</param>
        /// <returns>the plain text (as bytes)</returns>
        public static byte[] Decrypt(byte[] cipher, BigInteger privKey, BigInteger modul)
        {
            // decrypt the cipher message using RSA such that m = c^d, where c = m^e
            return BigInteger.ModPow(new BigInteger(cipher), privKey, modul).ToByteArray();
        }

        /// <summary>
        /// Create a RSA key pair of the given key length using the standard RSA procedure.
        /// </summary>
        /// <param name="keylen">The key length of the RSA keys to be generated.</param>
        /// <returns>a RSA key pair consisting of (d, e, N)</returns>
        public static RsaKeypair GenerateKeypair(int keylen)
        {
            Console.WriteLine($"Generating keys for RSA encryption (keylen={ keylen } bits):");
            Console.WriteLine("====================================================");

            // use always the same public key e (e.g. for SSL certificates)
            int e = 65537;

            // generate the private key d and the RSA modul N
            BigInteger d, N;
            do
            {
                // generate two primes with about half of the modul's key length
                var p = PrimeGenUtils.GeneratePrime(keylen / 2);
                var q = PrimeGenUtils.GeneratePrime(keylen / 2);
                if (p == q) { continue; }
                Console.WriteLine($"p={ p }\nq={ q }");

                // compute N and phi(N) such that N = p * q and phi(N) = (p - 1) * (q - 1)
                N = p * q;
                var phiN = (p - 1) * (q - 1);
                Console.WriteLine($"N={ N }\nphi(N)={ phiN }");

                // determine d as mult. inverse of e, i.e. d * e = 1 (mod phi(N))
                d = computeMultInverse(phiN, e);
                if (d < 0) { continue; }
                Console.WriteLine($"e={ e }\nd={ d }");
                Console.WriteLine("====================================================");

                // return the generated RSA key pair
                return new RsaKeypair() { PubKey = e, PrivKey = d, Modul = N };

            } while (true);
        }

        private static BigInteger computeMultInverse(BigInteger phiN, BigInteger e)
        {
            // Perform the extended Euclidean algorithm for a = phi(N) and b = e.
            // By the simple Euclidean algorithm, the final value of a is the greatest
            // common multiple of phi(N) and e. Moreover, the extended part of the algorithm
            // provides an additional Bêzout identity GCN(phi(N), e) = u * phi(N) + v * e.
            // As d is supposed to be the mult. inverse of e, i.e. d * e = 1 (mod phi(N)),
            // u * phi(N) (mod phi(N)) = 0 and v * e = GCN(a, b) (mod phi(N)), so v = d.

            // initialize a and b
            var a = phiN;
            var b = e;

            // initialize cache variables
            var q = BigInteger.Zero;
            var u = BigInteger.One;
            var s = BigInteger.Zero;
            var v = BigInteger.Zero;
            var t = BigInteger.One;

            // loop until a mod b = 0
            while (b > 0)
            {
                // compute q = a div b and r = a mod b
                q = a / b;
                var r = a % b;

                // update a and b
                a = b;
                b = r;

                // update helper variables u, v, s, t
                var sNew = u - q * s;
                var tNew = v - q * t;
                u = s; v = t;
                s = sNew; t = tNew;
            }

            // only return v = d if the GCN(phi(N), e) = 1 and d > 0
            return a.IsOne ? v : -1;
        }
    }
}