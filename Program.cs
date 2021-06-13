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
using System.Text;

namespace PrimeGen
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // define the RSA key length to be generated
            int keylen = 1024; // tested with keylen up to 1024
            var rsaKeys = RsaUtils.GenerateKeypair(keylen);

            // create a message
            string message = "Hello World, RSA encryption!";
            var encoding = Encoding.ASCII;
            var plain = encoding.GetBytes(message);
            Console.WriteLine($"original message:  '{ message }'");

            // encrypt the message using RSA
            var cipher = RsaUtils.Encrypt(plain, rsaKeys.PubKey, rsaKeys.Modul);
            Console.WriteLine($"encrypted message: '{ encoding.GetString(cipher) }'");

            // decrypt the message back again using RSA
            var decrypted = RsaUtils.Decrypt(cipher, rsaKeys.PrivKey, rsaKeys.Modul);
            message = encoding.GetString(decrypted);
            Console.WriteLine($"decrypted message: '{ message }'");
        }
    }
}
