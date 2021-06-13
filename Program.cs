using System;
using System.Numerics;
using System.Text;

namespace PrimeGen
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // define the RSA key length to be generated
            int keylen = 128; // tested with keylen up to 512
            var rsaKeys = RsaUtils.GenerateKeypair(keylen);

            // create a message and encrypt it using RSA
            string message = "Hello World, RSA encryption!";
            var plain = Encoding.ASCII.GetBytes(message);
            var cipher = RsaUtils.Encrypt(plain, rsaKeys.PubKey, rsaKeys.Modul);
            Console.WriteLine($"original message:  '{ message }'");
            Console.WriteLine($"encrypted message: '{ Encoding.ASCII.GetString(cipher) }'");

            // decrypt the message back again using RSA
            var decrypted = RsaUtils.Decrypt(cipher, rsaKeys.PrivKey, rsaKeys.Modul);
            message = Encoding.ASCII.GetString(decrypted);
            Console.WriteLine($"decrypted message: '{ message }'");
        }
    }
}
