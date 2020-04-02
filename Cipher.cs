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
        private uint lastBlockLPopCount = 10, lastBlockRPopCount = 10;

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

            lastBlock = new byte[]{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            lastBlockLPopCount = 10;
            lastBlockRPopCount = 10;

            byte[] block = new byte[BlockSize];
            byte[] encrypted;

            for (int index = 0; index < bytes.Length; index += BlockSize)
            {
                Array.Copy(bytes, index, block, 0, BlockSize);

                for (int i = 0; i < BlockSize; i++)
                    block[i] = (byte)(block[i] ^ lastBlock[i]);

                 encrypted = PermutateBlock(block, true) ;

                lastBlock = (byte[])encrypted.Clone();
              
                encrypted.CopyTo(bytes, index);
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

            lastBlock = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            lastBlockLPopCount = 10;
            lastBlockRPopCount = 10;

            byte[] block = new byte[BlockSize];
            byte[] decrypted;

            for (int index = 0; index < bytes.Length; index += BlockSize)
            {
                Array.Copy(bytes, index, block, 0, BlockSize);

                decrypted = PermutateBlock(block, false);

                for (int i = 0; i < BlockSize; i++)
                    decrypted[i] = (byte)(decrypted[i] ^ lastBlock[i]);

                lastBlock = (byte[])block.Clone();

                decrypted.CopyTo(bytes, index);
            }

            return bytes;
        }

        private byte[] PermutateBlock(byte[] data, bool encrypt)
        {
            if (data.Length != BlockSize)
                throw new Exception("Data not of block size");

            //Split the data into two 64-bit sections
            UInt64 L;
            UInt64 R;

            L = (UInt64) BitConverter.ToInt64(data.AsSpan(0, 8));
            R = (UInt64) BitConverter.ToInt64(data.AsSpan(8, 8));

            //If encrypting, rotate the two halves left and the store their set bit counts
            if (encrypt)
            {
                L = BitwiseRotateLeft(L, (int)lastBlockRPopCount);
                R = BitwiseRotateLeft(R, (int)lastBlockLPopCount);

                lastBlockLPopCount = System.Runtime.Intrinsics.X86.Popcnt.PopCount((uint)L);
                lastBlockRPopCount = System.Runtime.Intrinsics.X86.Popcnt.PopCount((uint)R);
            }

            //Perform the Rounds
            for (int i = 0; i < Rounds; i++)
            {
                if (encrypt)
                    EncryptionRound(ref L, ref R, i);
                else
                    DecryptionRound(ref L, ref R, i);
            }

            //If decrypting, store the set bit counts and then rotate both halves right
            if (!encrypt)
            {
                UInt64 tempL = lastBlockLPopCount;
                UInt64 tempR = lastBlockRPopCount;

                lastBlockLPopCount = System.Runtime.Intrinsics.X86.Popcnt.PopCount((uint)L);
                lastBlockRPopCount = System.Runtime.Intrinsics.X86.Popcnt.PopCount((uint)R);

                L = BitwiseRotateRight(L, (int)tempR);
                R = BitwiseRotateRight(R, (int)tempL);
            }


            //Concatenate the two parts into a single array and return it
            byte[] result = new byte[BlockSize];
            BitConverter.GetBytes(L).CopyTo(result, 0);
            BitConverter.GetBytes(R).CopyTo(result, 8);
            return result;
        }

        private void EncryptionRound(ref UInt64 L, ref UInt64 R, int i)
        {
            UInt64 roundKey = Subkey(i);

            R = R ^ roundKey;
            R = Subsistute(R, true);
            L = L ^ R;

            if (i < Rounds - 1)
            {
                UInt64 temp = L;
                L = R;
                R = temp;
            }
        }

        private void DecryptionRound(ref UInt64 L, ref UInt64 R, int i)
        {
            i = (Rounds - 1) - i;

            UInt64 roundKey = Subkey(i);

            L = L ^ R;
            R = Subsistute(R, false);
            R = R ^ roundKey;

            if (i > 0)
            {
                UInt64 temp = L;
                L = R;
                R = temp;
            }
        }

        private UInt64 Subsistute(UInt64 D, bool forwards)
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

            return (UInt64) BitConverter.ToInt64(bytes);
        }

        private UInt64 BitwiseRotateLeft(UInt64 l, int bits)
        {
            return l << bits | (l >> (64 - bits));
        }

        private UInt64 BitwiseRotateRight(UInt64 l, int bits)
        {
            return l >> bits | (l << (64 - bits));
        }

        private UInt64 Subkey(int i)
        {
            byte[] subBytes = (key << i).ToByteArray();
            byte[] UInt64Bytes = new byte[8];
            Array.Copy(subBytes, 0, UInt64Bytes, 0, 8);
            return (UInt64) BitConverter.ToInt64(UInt64Bytes);
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
