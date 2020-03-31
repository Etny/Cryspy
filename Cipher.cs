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


        public Cipher(String key)
        { /*
            this.key = new byte[key.Length / 2];

            for(int i = 0; i < key.Length / 2; i++)
                this.key[i] = Byte.Parse(key.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
                */

            this.key = BigInteger.Parse(key, System.Globalization.NumberStyles.HexNumber);
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

                encrypted = EncryptBlock(block);

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

                decrypted = DecryptBlock(block);

                for (int i = 0; i < decrypted.Length; i++)
                    decrypted[i] = (byte)(decrypted[i] ^ lastBlock[i]);

                lastBlock = (byte[])block.Clone();

                decrypted.CopyTo(bytes, index);

                index += BlockSize;
            }

            return bytes;
        }

        private byte[] EncryptBlock(byte[] data) 
        {
            if (data.Length != BlockSize)
                throw new Exception("Data Not Block Size");

            long L;
            long R;

            long temp; //Used for swapping L and R and for combining them for the final return

            //Split the data into two 64-bit sections
            L = BitConverter.ToInt64(data.AsSpan(0, 8));
            R = BitConverter.ToInt64(data.AsSpan(8, 8));

            for (int i = 0; i < Rounds; i++)
            {
                long roundKey = Subkey(i);

                R = R ^ roundKey;
                L = L ^ R;

                if(i < Rounds - 1)
                {
                    temp = L;
                    L = R;
                    R = temp;
                }
            }

            //Concatenate the two parts into a single array and return it
            byte[] result = new byte[BlockSize];
            BitConverter.GetBytes(L).CopyTo(result, 0);
            BitConverter.GetBytes(R).CopyTo(result, 8);
            return result;

        }

        private byte[] DecryptBlock(byte[] data)
        {
            if (data.Length != BlockSize)
                throw new Exception("Data Not Block Size");

            long L;
            long R;

            long temp; //Used for swapping L and R and for combining them for the final return

            //Split the data into two 64-bit sections
            L = BitConverter.ToInt64(data.AsSpan(0, 8));
            R = BitConverter.ToInt64(data.AsSpan(8, 8));

            for (int i = Rounds - 1; i >= 0; i--)
            {
                long roundKey = Subkey(i);

                L = L ^ R;
                R = R ^ roundKey;  

                if (i > 0)
                {
                    temp = L;
                    L = R;
                    R = temp;
                }
            }

            //Concatenate the two parts into a single array and return it
            byte[] result = new byte[BlockSize];
            BitConverter.GetBytes(L).CopyTo(result, 0);
            BitConverter.GetBytes(R).CopyTo(result, 8);
            return result;

        }

        private long Subkey(int i)
        {
            byte[] subBytes = (key << i).ToByteArray();
            byte[] longBytes = new byte[8];
            Array.Copy(subBytes, 0, longBytes, 0, 8);
            return BitConverter.ToInt64(longBytes);
        }

   
    }
}
