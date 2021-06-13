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
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace PrimeGen
{
    /// <summary>
    /// This class provides prime generation functionality using the Miller-Rabin algorithm.
    /// </summary>
    public static class PrimeGenUtils
    {
        // initialize a strong cryptographic number generator
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        /// <summary>
        /// Create a prime number of the given length (as bits).
        /// </summary>
        /// <param name="length">The length of the prime to be generated.</param>
        /// <param name="numChecks">The number of Miller-Rabin checks to verify the prime (default: 1000).</param>
        /// <returns>a prime number with prob. >= 1 - (1/2)^numChecks</returns>
        public static BigInteger GeneratePrime(int length, int numChecks=1000)
        {
            BigInteger candidate;
            int passedChecks = 0;

            do
            {
                // generate a random prime candidate of the given length
                candidate = randBigint(length, primeCandidate: true);

                // perform a given number of primality checks
                for (passedChecks = 0; passedChecks < numChecks; passedChecks++)
                {
                    // check for primality (probably prime, Miller-Rabin)
                    if (!isProbablyPrime(candidate, length)) { break; }
                }
            }
            // continue until a number passes all checks 
            while (passedChecks < numChecks);

            return candidate;
        }

        public static bool isProbablyPrime(BigInteger m, int length)
        {
            // determine the least significant bit index k for m-1 = 2^k * u
            int k = naiveLsb(m - 1);

            // determine the remaining odd part u = (m-1) / 2^k
            var u = (m - 1) >> k;

            // draw a random witness x = rand({ 0, ..., m-1 })^u mod m
            var x = randBigint(length);
            x = BigInteger.ModPow(x, u, m);

            BigInteger y = 0;
            int i;

            // perform the root test for x^(2^i) with i in { 0, ..., k-1 }
            for (i = k-1; i >= 0; i--)
            {
                y = x;
                x = BigInteger.ModPow(x, 2, m);
                if (x == 1) { break; }
            }

            // evaluate the result of the root test
            bool isProbPrime = (y == 1 || y == (m - 1)) && i >= 0;
            return isProbPrime;
        }

        private static int naiveLsb(BigInteger value)
        {
            // make sure that any bit is set
            if (value == 0) { return -1; }

            // shift bit-by-bit until the first set bit was found
            int k = 0;
            while (value.IsEven) { value >>= 1; k++; }
            return k;
        }

        private static BigInteger randBigint(int length, bool primeCandidate=false)
        {
            // create a random sequence of the given length
            int bytesCount = (int)Math.Ceiling(length / 8.0);
            var bytes = new byte[bytesCount];
            rngCsp.GetBytes(bytes);

            // convert the sequence to a BigInt
            var value = new BigInteger(bytes);

            // make sure that the number is positive
            value = (value.Sign == -1) ? BigInteger.Negate(value) : value;

            // only for prime candidates: make sure that the candidate is at least 
            // not divisible by 2, 3 and 5 ~> ensure only trying promising candidates
            if (primeCandidate)
            {
                BigInteger lastValue;

                do
                {
                    // snapshot the value before executing the next iteration
                    // each iteration only changes the value if any of the checks fail
                    lastValue = value;

                    // make sure that the parity bit is set ~> not divisible by 2
                    value = value.IsEven ? value + 1 : value;

                    // make sure that the checksum is not divisible by 3 ~> not divisible by 3
                    int checksum = value.ToString().Select(x => x - '0').Sum();
                    value = (checksum % 3 == 0) ? value + 2 : value;

                    // make sure that the decimal representation does not end with 0 or 5
                    // ~> not divisible by 5 (info: parity check already handles 0 case)
                    value = value.ToString().Last() == '5' ? value + 2 : value;

                    // TODO: add some more checks to facilitate hardening the candidate space
                    //       -> test if this allows to improve the prime generator's performance
                }
                // continue until all 3 checks pass, i.e. the value was not changed anymore
                while (lastValue != value);
            }

            return value;
        }
    }
}
