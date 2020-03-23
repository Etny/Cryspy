using System;
using System.IO;
using System.Text;

namespace Cryspy
{
    class Program
    {

        public static readonly int ArgumentCount = 1;

        static int Main(string[] args)
        {
            if (args.Length < ArgumentCount)
                return Exit("Bad arguments", -1);

            String file = args[0];

            if (!File.Exists(file))
                return Exit("File not found", -2);

            String text;

            try
            {
                text = File.ReadAllText(file);
            }catch(UnauthorizedAccessException e)
            {
                return Exit("Insufficient acces to file", -3);
            }catch(NotSupportedException e)
            {
                return Exit("Reading file not supported", -3);
            }

            String encrypted = Encrypt(text);

            String saveFile = "C:\\Users\\yveem\\Documents\\saveFile.txt";

            if (!File.Exists(saveFile))
                File.CreateText(saveFile).Close();

            File.WriteAllText(saveFile, encrypted);

            Console.WriteLine(encrypted);
            Console.WriteLine(Decrypt(encrypted));

            return 0;
        }

        private static int Exit(String msg, int code)
        {
            Console.WriteLine(msg);
            return code;
        }

        private static String Encrypt(String s)
        {
            StringBuilder builder = new StringBuilder();

            foreach(char c in s.ToCharArray())
            {
                char shifted = (char)((byte)c + 1);
                builder.Append(shifted);
            }

            return builder.ToString();
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
