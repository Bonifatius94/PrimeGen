﻿using System;
using System.Numerics;
using System.Text;

namespace PrimeGen
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // define the key length to be generated
            int keylen = 16;

            // generate prime numbers and use them for some RSA
            var p = KeyGenUtils.GeneratePrime(keylen);
            var q = KeyGenUtils.GeneratePrime(keylen);
            Console.WriteLine($"p={ p }, q={ q }");

            // compute N and phi(N)
            var N = p * q;
            var phiN = (p - 1) * (q - 1);
            Console.WriteLine($"N={ N }, phi(N)={ phiN }");

            // choose e such that it is rel. prime to phi(N) and within 1 < e < phi(N)
            // then, determine d as mult. inverse of e, i.e. d * e = 1 (mod phi(N))
            BigInteger d, e;
            do {
                e = KeyGenUtils.GeneratePrime(keylen);
                d = computeMultInverse(phiN, e);
            }
            while (e >= phiN || e == 1 || d < 0);

            Console.WriteLine($"e={ e }, d={ d }");
            Console.WriteLine($"{ e } * { d } (mod { phiN }) = { e * d % phiN }");

            // create a message and encrypt it
            string message = "123";
            var plain = Encoding.ASCII.GetBytes(message);
            var cipher = BigInteger.ModPow(new BigInteger(plain), e, N).ToByteArray();
            Console.WriteLine($"original message: '{ message }'");
            Console.WriteLine($"encrypted message: '{ Encoding.ASCII.GetString(cipher) }'");

            // decrypt the message again using RSA
            var decrypted = BigInteger.ModPow(new BigInteger(cipher), d, N).ToByteArray();
            message = Encoding.ASCII.GetString(decrypted);
            Console.WriteLine($"decrypted message: '{ message }'");
        }

        private static BigInteger computeMultInverse(BigInteger phiN, BigInteger e)
        {
            // initialize a and b
            var a = phiN;
            var b = e;

            // initialize cache variables
            var q = BigInteger.Zero;
            var u = BigInteger.Zero;
            var s = BigInteger.One;
            var v = BigInteger.One;
            var t = BigInteger.Zero;

            // loop until a mod b = 0
            while (b > 0)
            {
                Console.WriteLine($"a={ a }, b={ b }");

                // compute q = a div b and r = a mod b
                q = a / b;
                var r = a % b;

                // update a and b
                a = b;
                b = r;

                // update helper variables u, v, s, t
                var sNew = u - q * s;
                var tNew = v - q * t;
                u = s;
                v = t;
                s = sNew;
                t = tNew;

                Console.WriteLine($"q={ q }, r={ r }, u={ u }, v={ v }, s={ s }, t={ t }");
            }

            // determine d: 1 = u * phi(N) + v * e => v = d
            var d = v;

            // only return d if GCN(a, b) = 1, otherwise d=-1
            return a == 1 ? d : -1;
        }
    }
}
