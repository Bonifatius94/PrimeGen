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
using System.Collections.Generic;
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

        // initialize cached groups of small primes used for prime candidate hardening
        private static long[] smallPrimeGroups = 
            partitionPrimeGroups(eratosthenesSieve(10000)).ToArray();

        /// <summary>
        /// Create a prime number of the given length (as bits).
        /// </summary>
        /// <param name="length">The length of the prime to be generated.</param>
        /// <param name="numChecks">The number of Miller-Rabin checks to verify the prime (default: 1000).</param>
        /// <returns>a prime number with prob. >= 1 - (1/2)^numChecks</returns>
        public static BigInteger GeneratePrime(int length, int numChecks=1000)
        {
            // TODO: use multi-core programming

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
            // not divisible by small primes ~> ensure only trying promising candidates
            value = primeCandidate ? hardenPrimeCandidate(value) : value;

            return value;
        }

        private static int[] eratosthenesSieve(int bound)
        {
            // initialize the result set indicating whether the number at its index
            // is prime; every number is assumed to be prime (not not prime)
            var notPrime = new bool[bound];

            // test all numbers i in { 2, ..., sqrt(bound) }
            for (int i = 2; i <= (int)Math.Sqrt(bound); i++)
            {
                // continue if i is already crossed out, i.e. i is composite
                if (notPrime[i]) { continue; }

                // otherwise, i is prime because it is not divisible by any smaller primes
                else 
                {
                    // cross out all multiples of i within the search bound
                    var multiples = Enumerable.Range(2, (bound / i) - 2).Select(x => x * i);
                    foreach (var m in multiples) { notPrime[m] = true; }
                }
            }

            // convert the boolean field into an integer array
            return Enumerable.Range(2, bound - 2).Where(x => !notPrime[x]).ToArray();
        }

        private static IEnumerable<long> partitionPrimeGroups(
            int[] primes, long limit=long.MaxValue)
        {
            BigInteger t = 1;

            // loop through all cached small primes
            foreach (int p in primes)
            {
                // if applying p to the prime group would exceed the limit
                if (t * p > limit)
                {
                    // write the prime group to the output
                    // p is the first member of the new prime group
                    yield return (long)t;
                    t = p;
                }
                // otherwise apply p to the current prime group
                else { t *= p; }
            }

            // yield the remaining primes
            yield return (long)t;
        }

        private static BigInteger hardenPrimeCandidate(BigInteger candidate)
        {
            BigInteger temp;

            // make sure the candidate is odd
            candidate = candidate.IsEven ? candidate + 1 : candidate;

            do
            {
                // snapshot the value before executing the next iteration
                // each iteration only changes the value if any of the checks fail
                temp = candidate;

                // make sure the candidate is not divisible by small primes
                // to do so, ensure that GCN(cand, p_1 * p_2 * ... * p_n) = 1
                // which can be easily carried out in chunks of primes { p_i, ..., p_j }
                foreach (long group in smallPrimeGroups)
                {
                    // make sure the primes group is rel. prime to the candidate
                    // otherwise decrement the candidate by two and repeat all checks
                    var gcd = BigInteger.GreatestCommonDivisor(candidate, group);
                    if (!gcd.IsOne) { candidate = candidate - 2; break; }
                }
            }
            // continue until all 3 checks pass, i.e. the value was not changed anymore
            while (temp != candidate);

            return candidate;
        }
    }
}
