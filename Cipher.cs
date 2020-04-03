using System;
using System.Collections.Generic;
using System.IO;
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

        private UInt32 currentMetaDataIndex = 0;

        private int SBoxInputSize = 4;
        private SBox[] SubBoxes = new SBox[16];
        private SBox[] SubBoxes1 = { new SBox(0, 2), new SBox(1, 0), new SBox(2, 3), new SBox(3, 1) };

        private Random rng = new Random();


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

        public VirtualFile Encrypt(byte[] data, String path)
        {
            int dataLength = data.Length;
            int finalBlockSize = BlockSize;

            if(dataLength % BlockSize != 0)
            {
                finalBlockSize = dataLength % BlockSize;
                dataLength += BlockSize - finalBlockSize;
            }

            int blockCount = dataLength / BlockSize;

            byte[] headerBlock = GenerateHeaderBlock(path, blockCount, (byte)finalBlockSize);
            byte[] metaDataBlocks = GenerateMetaDataBlocks(path);

            int nameLength = Path.GetFileName(path).Length * 2;

            int metaDataLength = nameLength;
            if (metaDataLength % BlockSize != 0) metaDataLength += BlockSize - (metaDataLength % BlockSize);
            metaDataLength /= BlockSize;


            byte[] fullData = new byte[data.Length + ((1 + metaDataLength) * BlockSize)];

            Array.Copy(headerBlock, 0, fullData, 0, BlockSize);
            Array.Copy(data, 0, fullData, BlockSize, currentMetaDataIndex * BlockSize);
            Array.Copy(metaDataBlocks, 0, fullData, currentMetaDataIndex * BlockSize + BlockSize, metaDataLength * BlockSize);
            Array.Copy(data, currentMetaDataIndex * BlockSize, fullData, (currentMetaDataIndex * BlockSize) + BlockSize + (metaDataLength * BlockSize), data.Length - (currentMetaDataIndex * BlockSize));

            String fileName = Path.GetFileNameWithoutExtension(path) + ".ryce";

            Console.WriteLine("Encryption Name: {0}, mdLength: {1}, mdIndex: {2}", nameLength, metaDataLength, currentMetaDataIndex);

            return new VirtualFile() { data = PermutateData(fullData, true), name = fileName, path = path.Replace(Path.GetFileName(path), fileName)};
        }
        
        public VirtualFile Decrypt(byte[] data, String path)
        {
            byte[] rawData = PermutateData(data, false);

            byte finalBlockLength = rawData[rawData[0]];
            byte nameLength = rawData[rawData[0] + 1];

            byte[] metaDataIndexBytes = new byte[4];
            Array.Copy(rawData, BlockSize - 4, metaDataIndexBytes, 0, 4);
            currentMetaDataIndex = BitConverter.ToUInt32(metaDataIndexBytes);

            int metaDataLength = nameLength;
            if (metaDataLength % BlockSize != 0) metaDataLength += BlockSize - (metaDataLength % BlockSize);
            metaDataLength /= BlockSize;

            int rawBlockCount = rawData.Length / BlockSize;

            byte[] finalData = new byte[((rawBlockCount - 1 - metaDataLength) * BlockSize)-(BlockSize - finalBlockLength)];

            Console.WriteLine("Decryption Name: {0}, mdLength: {1}, mdIndex: {2}", nameLength, metaDataLength, currentMetaDataIndex);

            Array.Copy(rawData, BlockSize, finalData, 0, currentMetaDataIndex * BlockSize);
            Array.Copy(rawData, BlockSize + (currentMetaDataIndex * BlockSize) + (metaDataLength * BlockSize), finalData, currentMetaDataIndex * BlockSize, finalData.Length - (currentMetaDataIndex * BlockSize));

            byte[] metaData = new byte[metaDataLength * BlockSize];
            Array.Copy(rawData, BlockSize + (currentMetaDataIndex * BlockSize), metaData, 0, metaDataLength * BlockSize);

            StringBuilder builder = new StringBuilder();

            for(int i = 0; i < nameLength; i += 2)      
                builder.Append((char)(metaData[i] | (metaData[i + 1] << 8)));

            String fileName = builder.ToString();

            return new VirtualFile() { data = finalData, name = fileName, path = path.Replace(Path.GetFileName(path), fileName)};
        }

        public byte[] PermutateData(byte[] data, bool encrypt)
        {
            if (encrypt) Console.WriteLine("Starting Encryption");
            else Console.WriteLine("Starting Decryption");

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
            byte[] permutated;

            for (int index = 0; index < bytes.Length; index += BlockSize)
            {
                Array.Copy(bytes, index, block, 0, BlockSize);

                if (encrypt)
                {
                    for (int i = 0; i < BlockSize; i++)
                        block[i] = (byte)(block[i] ^ lastBlock[i]);
                }

                permutated = PermutateBlock(block, encrypt);

                if (!encrypt)
                {
                    for (int i = 0; i < BlockSize; i++)
                        permutated[i] = (byte)(permutated[i] ^ lastBlock[i]);

                    lastBlock = (byte[])block.Clone();
                }
                else
                {
                    lastBlock = (byte[])permutated.Clone();
                }


                permutated.CopyTo(bytes, index);

                /*
                if (encrypt) Console.WriteLine("Finished Encrypting Block " + index / BlockSize);
                else Console.WriteLine("Finished Decrypting Block " + index / BlockSize);
                */
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
            R = BitwiseRotateLeft(R, (int)(L % 64));
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
            R = BitwiseRotateRight(R, (int)(L % 64));
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

        private byte[] GenerateHeaderBlock(String path, int blockCount, byte finalBlockLength)
        {
            byte nameLength = (byte)(Path.GetFileName(path).Length * 2);
            currentMetaDataIndex = (UInt32) (blockCount == 0 ? 0 : rng.Next(0, blockCount - 2));
            byte dataIndex = (byte)(rng.Next(1, BlockSize - 6));

            byte[] headerBlock = new byte[BlockSize];

            headerBlock[0] = dataIndex;
            headerBlock[dataIndex] = finalBlockLength;
            headerBlock[dataIndex + 1] = nameLength;

            Array.Copy(BitConverter.GetBytes(currentMetaDataIndex), 0, headerBlock, BlockSize - 4, 4);

            for(int i = 1; i < BlockSize - 4; i++)
            {
                if (i == dataIndex || i - 1 == dataIndex) continue;
                headerBlock[i] = (byte)(rng.Next(0, 255));
            }

            return headerBlock;
        }

        private byte[] GenerateMetaDataBlocks(String path)
        {
            String name = Path.GetFileName(path);
            char[] chars = name.ToCharArray();

            int metaDataLength = name.Length * 2;
            if (metaDataLength % BlockSize != 0) metaDataLength += BlockSize - (metaDataLength % BlockSize);

            byte[] metaDataBlocks = new byte[metaDataLength];

            for(int i = 0; i<chars.Length; i++)
            {
                char c = chars[i];

                metaDataBlocks[i * 2] = (byte)(c & 255);
                metaDataBlocks[i * 2 + 1] = (byte)((c & 65280) >> 8);
            }

            if (metaDataLength != (name.Length * 2))
            {
                for (int i = name.Length * 2; i < metaDataLength; i++)
                    metaDataBlocks[i] = (byte)(rng.Next(0, 255));
            }

            return metaDataBlocks;
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

    class VirtualFile
    {
        public byte[] data;
        public String name;
        public String path;
    }
}
