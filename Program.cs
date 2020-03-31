using System;
using System.IO;
using System.Text;

namespace Cryspy
{
    class Program
    {

        public static readonly int ArgumentCount = 1;

        public static Cipher cipher;

        static int Main(string[] args)
        {
            if (args.Length < ArgumentCount)
                return Exit("Bad arguments", -1);

            String file = args[0];

            if (!File.Exists(file))
                return Exit("File not found", -2);

            byte[] plaintext;

            try
            {
                plaintext = File.ReadAllBytes(file);
            } catch (UnauthorizedAccessException e)
            {
                return Exit("Insufficient acces to file", -3);
            } catch (NotSupportedException e)
            {
                return Exit("Reading file not supported", -3);
            }

            String key = args[1];

            cipher = new Cipher(key);

            byte[] encrypted = cipher.Encrypt(plaintext);

            String saveFile = "C:\\Users\\yveem\\Documents\\saveFile.txt";
            String decryptFile = "C:\\Users\\yveem\\Documents\\decFile.txt";

            if (!File.Exists(saveFile))
                File.CreateText(saveFile).Close();

            if (!File.Exists(decryptFile))
                File.CreateText(decryptFile).Close();

            File.WriteAllBytes(saveFile, encrypted);
            File.WriteAllBytes(decryptFile, cipher.Decrypt(encrypted));

            return 0;
        }

        private static int Exit(String msg, int code)
        {
            Console.WriteLine(msg);
            return code;
        }

        private static String Encrypt1(String s)
        {
            StringBuilder builder = new StringBuilder();

            foreach (char c in s.ToCharArray())
            {
                char shifted = (char)((byte)c + 1);
                builder.Append(shifted);
            }

            return builder.ToString();
        }

        private static String Encrypt(String s, String key)
        {
            StringBuilder builder = new StringBuilder();

            byte[] bytes = new byte[s.Length];

            for (int i = 0; i < s.Length; i++)
                bytes[i] = (byte)s.ToCharArray()[i];


            int index = 10000;

            while (index < bytes.Length - 1)
            {
             //   bytes.
            }

            return builder.ToString();
        }

        private byte[] EncryptBlock(byte[] data)
        {
            return null;
        }

        private static String Decrypt(String s)
        {
            StringBuilder builder = new StringBuilder();

            foreach (char c in s.ToCharArray())
            {
                char shifted = (char)((byte)c - 1);
                builder.Append(shifted);
            }

            return builder.ToString();
        }
    }
}
