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

            // generate prime numbers p, q with p != q
            BigInteger p, q;
            do {
                p = PrimeGenUtils.GeneratePrime(keylen);
                q = PrimeGenUtils.GeneratePrime(keylen);
            } while (p == q);
            Console.WriteLine($"p={ p }\nq={ q }");

            // compute N and phi(N) such that N = p * q and phi(N) = (p - 1) * (q - 1)
            var N = p * q;
            var phiN = (p - 1) * (q - 1);
            Console.WriteLine($"N={ N }\nphi(N)={ phiN }");

            // choose e such that it is rel. prime to phi(N) and within 1 < e < phi(N)
            // then, determine d as mult. inverse of e, i.e. d * e = 1 (mod phi(N))
            BigInteger d, e;
            do {
                e = PrimeGenUtils.GeneratePrime(keylen);
                d = computeMultInverse(phiN, e);
            } while (e >= phiN || e == 1 || d < 0);
            Console.WriteLine($"e={ e }\nd={ d }");
            Console.WriteLine("====================================================");

            // return the generated RSA key pair
            return new RsaKeypair() { PubKey = e, PrivKey = d, Modul = N };
        }

        private static BigInteger computeMultInverse(BigInteger phiN, BigInteger e)
        {
            // algorithm source: Dirk Hachenberger - 'Mathematik für Informatiker', ISBN 3827373204

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

            // determine d such that d * e (mod phi(N)) = 1:
            // by ext. euclid: GCN(e, phi(N)) = u * phi(N) + v * e
            //                 ~> d = v if GCN(e, phi(N)) = a = 1
            return a.IsOne ? v : -1;
        }
    }
}