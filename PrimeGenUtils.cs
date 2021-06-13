using System;
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
            BigInteger m;
            int passedChecks = 0;

            do
            {
                // generate a random integer of the given length
                m = randBigint(length);

                // make sure to avoid division by zero
                if (m.IsZero) { continue; }

                // perform a given number of primality checks
                passedChecks = 0;
                for (; passedChecks < numChecks; passedChecks++)
                {
                    // check for primality (probably prime, Miller-Rabin)
                    if (!isProbablyPrime(m, length)) { break; }
                }
            }
            // continue until a number passes all checks 
            while (passedChecks < numChecks);

            return m;
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

            // perform the root test for x^(2^i) with i in { 0, k-1 }
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

        private static BigInteger randBigint(int length)
        {
            // create random sequence of the given length
            int bytesCount = (int)Math.Ceiling(length / 8.0);
            var bytes = new byte[bytesCount];
            rngCsp.GetBytes(bytes);

            // convert the sequence to a BigInt
            var value = new BigInteger(bytes);

            // make sure that the number is positive
            value = (value.Sign == -1) ? BigInteger.Negate(value) : value;

            return value;
        }
    }
}