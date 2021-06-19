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
using System.Threading;
using System.Threading.Tasks;

namespace PrimeGen
{
    /// <summary>
    /// This class provides prime generation functionality using the Miller-Rabin algorithm.
    /// </summary>
    public static class PrimeGenUtils
    {
        // initialize a strong cryptographic number generator
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        // initialize cached small primes used for prime candidate hardening
        private static int[] smallPrimes = eratosthenesSieve(100000).ToArray();

        /// <summary>
        /// Create a prime number of the given length (as bits).
        /// </summary>
        /// <param name="length">The length of the prime to be generated.</param>
        /// <param name="numChecks">The number of Miller-Rabin checks to verify the prime (default: 25).</param>
        /// <param name="maxCores">The amout of CPU cores to be used (default: max. available).</param>
        /// <returns>a prime number with prob. >= 1 - (1/2)^numChecks</returns>
        public static BigInteger GeneratePrime(int length, 
            int numChecks=25, int? maxCores=null)
        {
            // determine the amount of CPU cores to be used in parallel
            int cores = maxCores ?? Environment.ProcessorCount;

            // prepare a cancellation token source to kill the threads gracefully
            // after the first task successfully found a prime
            var callback = new CancellationTokenSource();

            // start all tasks searching for primes simultaneously
            var tasks = Enumerable.Range(0, cores)
                .Select(x => Task.Run(() => generatePrime(length, numChecks, callback.Token)))
                .ToArray();

            // wait until the first prime was found
            int taskId = Task.WaitAny(tasks);
            var prime = tasks[taskId].Result;

            // make sure to kill all dangling tasks
            callback.Cancel();

            return prime;
        }

        private static BigInteger generatePrime(
            int length, int numChecks, CancellationToken token)
        {
            BigInteger candidate;
            int passedChecks = 0;

            do
            {
                // generate a random prime candidate of the given length
                candidate = randBigint(length);

                // make sure that the candidate is at least not divisible
                // by small primes ~> try only promising candidates
                candidate = hardenPrimeCandidate(candidate);

                // perform a given number of primality checks
                for (passedChecks = 0; passedChecks < numChecks; passedChecks++)
                {
                    // check for primality (probably prime, Miller-Rabin)
                    if (!isProbablyPrime(candidate, length)) { break; }
                }
            }
            // continue until a number passes all checks or the cancellation is requested
            while (passedChecks < numChecks && !token.IsCancellationRequested);

            return candidate;
        }

        private static BigInteger hardenPrimeCandidate(BigInteger candidate)
        {
            BigInteger temp;

            // make sure the candidate is odd (otherwise the loop won't terminate)
            candidate = candidate.IsEven ? candidate + 1 : candidate;

            do
            {
                // snapshot the value before executing the next iteration
                // each iteration only changes the value if any of the checks fail
                temp = candidate;

                // // make sure the candidate is not divisible by small primes
                foreach (int prime in smallPrimes)
                {
                    if (candidate % prime == 0) { candidate += 2; break; }
                }
            }
            // continue until the candidate is not divisible by any of the small primes
            while (temp != candidate);

            return candidate;
        }

        private static bool isProbablyPrime(BigInteger m, int length)
        {
            // Perform the Miller-Rabin primality test based on Fermat's little theorem 
            // saying that m is probably prime if a^(m-1) = 1 (mod m). Probably prime means that
            // m is prime in at least 50% of cases by number theory. For efficiency, the
            // test is carried out using the so-called root test.

            // The root test is based on following lemma:
            // If a^(m-1) mod m = 1, then the sqrt(m-1) has to be 1 or -1 (with -1 = m-1 (mod m)).

            // By interpreting m-1 as m-1 = u * 2^k, a^u can be squared exactly k times.
            // If any of those squares (a^u)^(2^i) for i in { 0, ..., k-1 } is equal to 1 or m-1,
            // then squaring it at least one more time results in a value of 1 (mod m).
            // So by Fermat, a^(u * 2^k) = a^(m-1) = 1 (mod m) indicates that m is prob. prime.

            // draw a random witness a = rand({ 0, ..., m-1 })
            var a = randBigint(length) % m;

            // determine the least significant bit index k for m-1 = 2^k * u
            // and the remaining odd part u = (m-1) / 2^k
            int k = 0;
            var u = m - 1;
            while (u.IsEven) { u >>= 1; k++; }

            // apply the non-squarable exponent part u to a, i.e. x = a^u mod m
            BigInteger x, y;
            x = BigInteger.ModPow(a, u, m);

            // square a^u (mod m) k times (the root test)
            for (int i = 0; i < k; i++)
            {
                // compute the next square x = (a^u)^(2^i)
                y = x;
                x = BigInteger.ModPow(x, 2, m);

                // return prob. prime if y^2 = x, with y in { -1, 1 }
                if (x == 1) { return (y == 1 || y == m - 1); }
            }

            // return composite if the root test failed
            return false;
        }

        private static BigInteger randBigint(int length)
        {
            // create a random sequence of the given length
            int bytesCount = (int)Math.Ceiling((length + 1) / 8.0);
            var bytes = new byte[bytesCount];
            rngCsp.GetBytes(bytes);
            bytes[bytesCount - 1] = 0x00;
            bytes[bytesCount - 2] |= 0x80;

            // convert the sequence to a BigInt
            var value = new BigInteger(bytes);

            // make sure that the number is positive
            value = (value.Sign == -1) ? BigInteger.Negate(value) : value;

            return value;
        }

        private static IEnumerable<int> eratosthenesSieve(int bound)
        {
            // initialize the result set indicating whether the number at its index
            // is prime; every number is assumed to be prime (not not prime)
            var notPrime = new bool[bound];
            int checkBound = (int)Math.Sqrt(bound);

            // test all numbers i in { 2, ..., sqrt(bound) }
            for (int i = 2; i <= checkBound; i++)
            {
                // skip i if it is already crossed out, i.e. i is composite
                if (notPrime[i]) { continue; }

                // otherwise, i is prime because it is not divisible by any
                // smaller primes ~> write i to the output stream
                yield return i;

                // cross out all multiples of i within the search bound
                for (int m = i + i; m < bound; m += i) { notPrime[m] = true; }
            }

            // process all remaining numbers greater than the check bound
            for (int i = checkBound + 1; i < bound; i++)
            {
                // if i is a prime ~> write i to the output stream 
                if (!notPrime[i]) { yield return i; }
            }
        }
    }
}
