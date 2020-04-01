using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Cryspy
{
    class Cipher
    {
        private BigInteger key;

        public static readonly int BlockSize = 16;
        public static readonly int Rounds = 16;

        private byte[] lastBlock;

        private int SBoxInputSize = 4;
        private SBox[] SubBoxes = new SBox[16];
        private SBox[] SubBoxes1 = { new SBox(0, 2), new SBox(1, 0), new SBox(2, 3), new SBox(3, 1) };


        public Cipher(String key)
        { /*
            this.key = new byte[key.Length / 2];

            for(int i = 0; i < key.Length / 2; i++)
                this.key[i] = Byte.Parse(key.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
                */

            this.key = BigInteger.Parse(key, System.Globalization.NumberStyles.HexNumber);

            GenerateSubBoxArray();
        }

        private void GenerateSubBoxArray()
        {
            for(byte i = 0; i<16; i++)
            {
                byte piece = (byte)((key >> (i * SBoxInputSize)) & 15); 

                while(SubBoxes[piece] != null)
                {
                    piece++;
                    if (piece >= 15) piece -= 15;
                }

                SubBoxes[piece] = new SBox(i, piece);
            }
            
           /* for (int i = 0; i < 16; i++)
                Console.WriteLine("{0}: {1} to {2}", i, SubBoxes[i].Input, SubBoxes[i].Output);*/
        }

        public byte[] Encrypt(byte[] data)
        {
            byte[] bytes = data.Length % BlockSize != 0 ? new byte[data.Length + (BlockSize - (data.Length % BlockSize))] : new byte[data.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                if (i < data.Length) bytes[i] = data[i];
                else bytes[i] = 0;
            }

            lastBlock = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            int index = 0;
            byte[] block = new byte[BlockSize];
            byte[] encrypted;

            while (index < bytes.Length)
            {
                Array.Copy(bytes, index, block, 0, BlockSize);

                for (int i = 0; i < block.Length; i++)
                    block[i] = (byte)(block[i] ^ lastBlock[i]);

                encrypted = PermutateBlock(block, true) ;

                lastBlock = (byte[])encrypted.Clone();

                encrypted.CopyTo(bytes, index);

                index += BlockSize;
            }

            return bytes;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] bytes = data.Length % BlockSize != 0 ? new byte[data.Length + (BlockSize - (data.Length % BlockSize))] : new byte[data.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                if (i < data.Length) bytes[i] = data[i];
                else bytes[i] = 0;
            }

            lastBlock = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            int index = 0;
            byte[] block = new byte[BlockSize];
            byte[] decrypted;

            while (index < bytes.Length)
            {
                Array.Copy(bytes, index, block, 0, BlockSize);

                decrypted = PermutateBlock(block, false);

                for (int i = 0; i < decrypted.Length; i++)
                    decrypted[i] = (byte)(decrypted[i] ^ lastBlock[i]);

                lastBlock = (byte[])block.Clone();

                decrypted.CopyTo(bytes, index);

                index += BlockSize;
            }

            return bytes;
        }

        private byte[] PermutateBlock(byte[] data, bool encrypt)
        {
            if (data.Length != BlockSize)
                throw new Exception("Data not of block size");

            //Split the data into two 64-bit sections
            long L;
            long R;

            L = BitConverter.ToInt64(data.AsSpan(0, 8));
            R = BitConverter.ToInt64(data.AsSpan(8, 8));

            //Perform the Rounds
            for (int i = 0; i < Rounds; i++)
            {
                if (encrypt)
                    EncryptionRound(ref L, ref R, i);
                else
                    DecryptionRound(ref L, ref R, i);
            }

            //Concatenate the two parts into a single array and return it
            byte[] result = new byte[BlockSize];
            BitConverter.GetBytes(L).CopyTo(result, 0);
            BitConverter.GetBytes(R).CopyTo(result, 8);
            return result;
        }

        private void EncryptionRound(ref long L, ref long R, int i)
        {
            long roundKey = Subkey(i);

            R = R ^ roundKey;
            R = Subsistute(R, true);
            L = L ^ R;

            if (i < Rounds - 1)
            {
                long temp = L;
                L = R;
                R = temp;
            }
        }

        private void DecryptionRound(ref long L, ref long R, int i)
        {
            i = (Rounds - 1) - i;

            long roundKey = Subkey(i);

            L = L ^ R;
            R = Subsistute(R, false);
            R = R ^ roundKey;

            if (i > 0)
            {
                long temp = L;
                L = R;
                R = temp;
            }
        }

        private long Subsistute(long D, bool forwards)
        {
            byte[] bytes = BitConverter.GetBytes(D);

            byte maxPieceValue = (byte)(Math.Pow(2, SBoxInputSize) - 1);

            for (int j = 0; j < bytes.Length; j++)
            {
                byte b = bytes[j];

                byte result = 0;
                byte piece;
                byte sub = 0;

                for (int i = 0; i < (8 / SBoxInputSize); i++)
                {
                    piece = (byte)((b >> (i * SBoxInputSize)) & maxPieceValue);

                    foreach (SBox s in SubBoxes)
                    {
                        if (forwards && s.Input == piece)
                        {
                            sub = s.Output;
                            break;
                        }
                        else if (!forwards && s.Output == piece)
                        {
                            sub = s.Input;
                            break;
                        }
                    }

                    result += (byte)(sub << (i * SBoxInputSize));
                }

                bytes[j] = result;
            }

            return BitConverter.ToInt64(bytes);
        }

        private long Subkey(int i)
        {
            byte[] subBytes = (key << i).ToByteArray();
            byte[] longBytes = new byte[8];
            Array.Copy(subBytes, 0, longBytes, 0, 8);
            return BitConverter.ToInt64(longBytes);
        }


        private class SBox
        {
            public byte Input, Output;

            public SBox(byte input, byte output)
            {
                this.Input = input;
                this.Output = output;
            }
        }
   
    }
}
