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
            Console.WriteLine("Cryspy encryption program v1");
            Console.WriteLine();

            if (args.Length < ArgumentCount)
            {
                Console.WriteLine("Enter file and key. You can also enter them as arguments (Crypsy -file -key).");

                args = new String[ArgumentCount];

                Console.Write("File: ");
                args[0] = Console.ReadLine();

                Console.Write("Key: ");
                args[1] = Console.ReadLine();
            }

            String file = args[0];

            if (!File.Exists(file))
                return Exit("File not found", -2);

            String key = args[1];

            cipher = new Cipher();

            while(!cipher.SetKey(key))
            {
                Console.Write("Please enter a valid key: ");
                key = Console.ReadLine();
            }

            if(Path.GetExtension(file).ToLower() == ".ryce")
            {
                OutputFile(cipher.Decrypt(file));
            }
            else
            {
                OutputFile(cipher.Encrypt(file));
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey(true);

            return 0;
        }

        private static void OutputFile(VirtualFile f)
        {
            Console.WriteLine();

            if (File.Exists(f.path))
            {
                Console.WriteLine("\'{0}\' already exists, do you wish to override it? If you don't you can store it under a different name. (y/n)", f.name);

                char input;

                do
                    input = Console.ReadKey(true).KeyChar;
                while (input != 'y' && input != 'n');

                if (input == 'n') 
                {
                    Console.WriteLine("Do you wish to store it under a different name? (y/n)");

                    do
                        input = Console.ReadKey(true).KeyChar;
                    while (input != 'y' && input != 'n');

                    if (input == 'n')
                        return;

                    Console.Write("Enter new name (without extension): ");

                    String extension = Path.GetExtension(f.path);
                    String newName = Console.ReadLine() + extension;
                    f.SetName(newName);
                    OutputFile(f);
                    return;
                }
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
