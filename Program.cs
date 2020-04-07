using System;
using System.IO;
using System.Text;

namespace Cryspy
{
    class Program
    {

        public static readonly int ArgumentCount = 2;

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

            VirtualFile encrypted = cipher.Encrypt(plaintext, file);

            OutputFile(encrypted);

            GC.Collect();

            VirtualFile decrypted = cipher.Decrypt(encrypted.data, encrypted.path);

            decrypted.path = "C:\\Users\\yveem\\Documents\\decypted"+decrypted.name;

            OutputFile(decrypted);

            return 0;
        }

        private static void OutputFile(VirtualFile f)
        {
            if (File.Exists(f.path))
            {
                Console.WriteLine("\'{0}\' already exists, do you wish to override it? (y/n)", f.name);
                char input;
            tryAgain: input = Console.ReadKey(true).KeyChar;
                if (input != 'y' && input != 'n') goto tryAgain;

                if (input != 'n')
                    return;
            }
            else
            {
                File.Create(f.path).Close();
            }

            File.WriteAllBytes(f.path, f.data);
        }

        private static int Exit(String msg, int code)
        {
            Console.WriteLine(msg);
            return code;
        }

    
    }
}
