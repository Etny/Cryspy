using Dirichlet.Numerics;
using System;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Text;

namespace Cryspy
{
    class Cipher
    {
        //The block size that this cipher uses
        public static readonly int BlockSize = 16;

        //The amount of encryption rounds performed on each block
        public static readonly int Rounds = 16;

        //The key used for encryption and decryption
        private UInt128 key;
        //The key's 32-bit segments
        private UInt32[] keySegments = new UInt32[4];
        //The round keys organized by round
        private UInt64[] Subkeys = new UInt64[Rounds];

        //The last encrypted block, used for CBC
        private byte[] lastBlock;
        //The population counts of the last block's 64-bit halves. Used to create diffusion between blocks
        private uint lastBlockLPopCount = 10, lastBlockRPopCount = 10;

        //The index for of the meta data block(s) of the current encrypted/decrypted file
        private UInt32 currentMetaDataIndex = 0;

        //The size of the input/outputs of each SBox in bits
        private int SBoxInputSize = 4;
        //The list of current SBoxes, based on the key
        private byte[] SubBoxesForwards = new byte[16];
        private byte[] SubBoxesBackwards = new byte[16];


        //Used for padding with random bytes
        private Random rng = new Random();

        //Used for tracking time
        Stopwatch timer;


        public Cipher()
        {
            //Initialize timer
            this.timer = new Stopwatch();  
        }

        public bool SetKey(String keyArg)
        {
            if (!ParseKey(keyArg)) return false;

            //Create the rounds keys for this key
            GenerateKeySchedule();
            //Create the SBoxes for this key
            GenerateSubBoxArray();

            return true;
        }

        private bool ParseKey(String keyString)
        {
            KeyEncoding encoding = KeyEncoding.UNKNOWN;

            String nums = "0123456789";
            String hexNums = "abcdefABCDEFxX";

            foreach(char c in keyString.ToCharArray())
            {
                switch (encoding)
                {
                    case KeyEncoding.UNKNOWN:
                        if (nums.Contains(c))
                            encoding = KeyEncoding.DECIMAL;
                        else if (hexNums.Contains(c))
                            encoding = KeyEncoding.HEX;
                        else if ((short)c <= 255)
                            encoding = KeyEncoding.ASCII;
                        else
                            encoding = KeyEncoding.UNICODE;
                            break;

                    case KeyEncoding.DECIMAL:
                        if (nums.Contains(c))
                            continue;
                        else if (hexNums.Contains(c))
                            encoding = KeyEncoding.HEX;
                        else if ((short)c <= 255)
                            encoding = KeyEncoding.ASCII;
                        else
                            encoding = KeyEncoding.UNICODE;
                        break;

                    case KeyEncoding.HEX:
                        if (nums.Contains(c) || hexNums.Contains(c))
                            continue;
                        else if ((short)c <= 255)
                            encoding = KeyEncoding.ASCII;
                        else
                            encoding = KeyEncoding.UNICODE;
                        break;

                    case KeyEncoding.ASCII:
                        if ((short)c <= 255)
                            continue;
                        else
                            encoding = KeyEncoding.UNICODE;
                        break;
                }
            }

            switch (encoding)
            {
                case KeyEncoding.DECIMAL:
                    try
                    {
                        key = UInt128.Parse(keyString);
                        return true;
                    } catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        return false;
                    }

                case KeyEncoding.HEX:
                    try
                    {
                        UInt128.TryParse(keyString, System.Globalization.NumberStyles.HexNumber, System.Globalization.NumberFormatInfo.CurrentInfo, out this.key);
                        return true;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        return false;
                    }

                case KeyEncoding.ASCII:
                    if (keyString.Length > BlockSize)
                    {
                        Console.WriteLine("Key too long, maximum of 16 ASCII characters allowed");
                        return false;
                    }

                    key = 0;

                    for (int i = 0; i < keyString.Length; i++)
                        key |= (UInt128)((byte)keyString.ToCharArray()[i] << (i * 8));

                    return true;

                case KeyEncoding.UNICODE:
                    if (keyString.Length*2 > BlockSize)
                    {
                        Console.WriteLine("Key too long, maximum of 8 Unicode characters allowed");
                        return false;
                    }

                    key = 0;

                    for (int i = 0; i < keyString.Length; i++)
                        key |= (UInt128)((short)(keyString.ToCharArray()[i]) << (i * 16));

                    return true;

            }

            return false;
        }

        /// <summary>
        /// Generates a 64-bit round key for each round, based on the main key
        /// </summary>
        private void GenerateKeySchedule()
        {
            //Split the key into 4 32-bit segments
            for(int i = 0; i < 4; i++)    
                keySegments[i] = (key >> (i * 32)) & UInt32.MaxValue;

            //Generate the round keys and store them in the appropriate array
            for (int i = 0; i < Rounds; i++)
                Subkeys[i] = GenerateSubkey(i);
        }

        /// <summary>
        /// Generates a round key for a single round
        /// </summary>
        /// <param name="round">The round to generate a key for</param>
        /// <returns></returns>
        private UInt64 GenerateSubkey(int round)
        {
            //For rounds 0 through 2, take a 64-bit segment from the main key
            if (round < 3)       
                return (UInt64)keySegments[round] | ((UInt64)keySegments[round + 1] << 32);

            //For rounds 3 through 5, take a 64-bit segment from the flipped main key
            if (round < 6)
                return (UInt64)keySegments[3 - (round - 3)] | ((UInt64)keySegments[2 - (round - 3)] << 32);

            //Used for the rest of the rounds
            else
                return GenerateSubkey(round - 1) ^ GenerateSubkey(round - 2);
        }

        /// <summary>
        /// Generates a list of SBoxes based on the main key
        /// </summary>
        private void GenerateSubBoxArray()
        {
            //Create an array to keep track of the SBoxes we've alread yset
            bool[] SubBoxSet = new bool[16];

            for(byte i = 0; i<16; i++)
            {
                //Take a 4-bit piece of the key
                byte piece = (byte)((key >> (i * SBoxInputSize)) & 15); 

                //Find the next empty space in the SBox array from index piece forwards
                while(SubBoxSet[piece] == true)
                {
                    piece++;
                    if (piece >= 15) piece -= 15;
                }

                SubBoxSet[piece] = true;

                //Fill it with an SBox
                SubBoxesForwards[piece] = i;
                SubBoxesBackwards[i] = piece;
            }
           }

        /// <summary>
        /// Encrypts a file of any type
        /// </summary>
        /// <param name="data">The raw byte data of the file to encrypt</param>
        /// <param name="path">The path of the file to encrypt</param>
        /// <returns>A VirtualFile containing the encrypted data and appropraite file name</returns>
        public VirtualFile Encrypt(byte[] data, String path)
        {
            //Start the timer to track time taken after encryption is finished
            timer.Restart();

            Console.WriteLine("Starting Encryption...");

            //Establish the total length of the data and the non-padded length of the final block
            int dataLength = data.Length;
            int finalBlockSize = BlockSize;

            if(dataLength % BlockSize != 0)
            {
                finalBlockSize = dataLength % BlockSize;
                dataLength += BlockSize - finalBlockSize;
            }

            //The amount of blocks to encrypt
            int blockCount = dataLength / BlockSize;

            //Create a header block, containing the length of the final block, the length of our file name and the index of our metadata block(s)
            byte[] headerBlock = GenerateHeaderBlock(path, blockCount, (byte)finalBlockSize);

            //Create the metadata block(s) for our file, containg it's original name and filetype
            byte[] metaDataBlocks = GenerateMetaDataBlocks(path);

            //Establish the length of the original filename in bytes
            int nameLength = Path.GetFileName(path).Length * 2;

            //Establish the length of our metadata block(s) in blocks
            int metaDataLength = metaDataBlocks.Length / BlockSize;

            //Create an array used to store the correctly ordered raw data
            byte[] fullData = new byte[data.Length + ((1 + metaDataLength) * BlockSize)];

            //Copy over our data into the appropriate parts or the array
            Array.Copy(headerBlock, 0, fullData, 0, BlockSize);
            Array.Copy(data, 0, fullData, BlockSize, currentMetaDataIndex * BlockSize);
            Array.Copy(metaDataBlocks, 0, fullData, currentMetaDataIndex * BlockSize + BlockSize, metaDataLength * BlockSize);
            Array.Copy(data, currentMetaDataIndex * BlockSize, fullData, (currentMetaDataIndex * BlockSize) + BlockSize + (metaDataLength * BlockSize), data.Length - (currentMetaDataIndex * BlockSize));

            data = null;
            GC.Collect();

            //Establish the name of the encrypted file
            String fileName = Path.GetFileNameWithoutExtension(path) + ".ryce";

            //Encrypt the data and store it in a VirtualFile with it's new file name
            VirtualFile encryptedFile = new VirtualFile() { data = PermutateData(fullData, true), name = fileName, path = path.Replace(Path.GetFileName(path), fileName) };

            //Stop the timer and print the elapsed time
            timer.Stop();

            float seconds = ((float)timer.ElapsedMilliseconds % 60000)/1000f;
            int minutes = (int)((timer.ElapsedMilliseconds - (timer.ElapsedMilliseconds % 60000)) / 60000);

            if (minutes > 0)
                Console.WriteLine("Finished Encryption in {0} minutes and {1} seconds", minutes, seconds);
            else
                Console.WriteLine("Finished Encryption in {0} seconds", seconds);

            //Return the encrypted file
            return encryptedFile;
        }

        /// <summary>
        /// Decrypts a .ryce file
        /// </summary>
        /// <param name="data">The raw byte data of the encrypted file to decrypt</param>
        /// <param name="path">The path of the encrypted file</param>
        /// <returns>A VirtualFile containing the decrypted data and original file name</returns>
        public VirtualFile Decrypt(byte[] data, String path)
        {
            //Start the timer to track time taken after decryption is finished
            timer.Restart();

            Console.WriteLine("Starting Decryption...");

            //Decrypt the raw encrypted data
            byte[] rawData = PermutateData(data, false);

            //Establish the index of the basic data in the header block
            byte dataIndex = (byte)(rawData[0] & 15);

            //Get the length of the final block and the length of the original file name
            byte finalBlockLength = (byte)((rawData[dataIndex] & 15) + 1);
            byte nameLength = rawData[dataIndex + 1];

            //Get the index of the metadata block(s) from the header block
            byte[] metaDataIndexBytes = new byte[4];
            Array.Copy(rawData, BlockSize - 4, metaDataIndexBytes, 0, 4);
            currentMetaDataIndex = BitConverter.ToUInt32(metaDataIndexBytes);

            //Establish the length of the metadata in blocks based on the filename length
            int metaDataLength = nameLength;
            if (metaDataLength % BlockSize != 0) metaDataLength += BlockSize - (metaDataLength % BlockSize);
            metaDataLength /= BlockSize;

            //The block count of the raw decrypted data
            int rawBlockCount = rawData.Length / BlockSize;

            //Create an array used to store the decrypted data of the original file
            byte[] finalData = new byte[((rawBlockCount - 1 - metaDataLength) * BlockSize)-(BlockSize - finalBlockLength)];

            //Copy over the decrypted file data
            Array.Copy(rawData, BlockSize, finalData, 0, currentMetaDataIndex * BlockSize);
            Array.Copy(rawData, BlockSize + (currentMetaDataIndex * BlockSize) + (metaDataLength * BlockSize), finalData, currentMetaDataIndex * BlockSize, finalData.Length - (currentMetaDataIndex * BlockSize));

            //Copy the decrypted metadata into a sepperate array
            byte[] metaData = new byte[metaDataLength * BlockSize];
            Array.Copy(rawData, BlockSize + (currentMetaDataIndex * BlockSize), metaData, 0, metaDataLength * BlockSize);

            //Generate the original file name
            StringBuilder builder = new StringBuilder();

            for(int i = 0; i < nameLength; i += 2)      
                builder.Append((char)(metaData[i] | (metaData[i + 1] << 8)));

            String fileName = builder.ToString();

            //Store the decrypted file data and original file name in a VirtualFile
            VirtualFile decryptedFile = new VirtualFile() { data = finalData, name = fileName, path = path.Replace(Path.GetFileName(path), fileName) };

            //Stop the timer and print the elapsed time
            timer.Stop();

            float seconds = ((float)timer.ElapsedMilliseconds % 60000) / 1000f;
            int minutes = (int)((timer.ElapsedMilliseconds - (timer.ElapsedMilliseconds % 60000)) / 60000);

            if (minutes > 0)
                Console.WriteLine("Finished Decryption in {0} minutes and {1} seconds", minutes, seconds);
            else
                Console.WriteLine("Finished Decryption in {0} seconds", seconds);

            //Return the decrypted file
            return decryptedFile;
        }

        /// <summary>
        /// Splits the raw data into blocks and encrypts of decrypts it
        /// </summary>
        /// <param name="data">The data to permutate</param>
        /// <param name="encrypt">Whether or not to encrypt the data</param>
        /// <returns>The encrypted/decrypted bytes</returns>
        public byte[] PermutateData(byte[] data, bool encrypt)
        {
            //Create an array with the smallest possible size to store data that is also a multiple of the block size
            byte[] bytes = data.Length % BlockSize != 0 ? new byte[data.Length + (BlockSize - (data.Length % BlockSize))] : new byte[data.Length];


            for (int i = 0; i < bytes.Length; i++)
            {
                //Copy over data into the array
                if (i < data.Length) bytes[i] = data[i];
                //Or pad it out with random bytes
                else bytes[i] = (byte)rng.Next(0, 256);
            }

            //Establish the Initializing Vectors for our CBC
            lastBlock = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            lastBlockLPopCount = 10;
            lastBlockRPopCount = 10;

            byte[] block = new byte[BlockSize];
            byte[] permutated;

            for (int index = 0; index < bytes.Length; index += BlockSize)
            {
                //Copy 1 block of data into the block array
                Array.Copy(bytes, index, block, 0, BlockSize);

                //If we are encrypting, Xor the block with the last encrypted block for CBC
                if (encrypt)
                {
                    for (int i = 0; i < BlockSize; i++)
                        block[i] = (byte)(block[i] ^ lastBlock[i]);
                }
                    
                //Encrypt/Decrypt the block
                permutated = PermutateBlock(block, encrypt);

                //If we are decrypting, Xor the decrypted block with the last encrypted block and then store the encrypted version of this block as the last block
                if (!encrypt)
                {
                    for (int i = 0; i < BlockSize; i++)
                        permutated[i] = (byte)(permutated[i] ^ lastBlock[i]);

                    lastBlock = (byte[])block.Clone();
                }
                //If we are encrypting, store the encrypted version of this block as the last block
                else
                {
                    lastBlock = (byte[])permutated.Clone();
                }

                //Copy the encrypted/decrypted block into our final array
                permutated.CopyTo(bytes, index);
            }

            //Return the encrypted block
            return bytes;
        }
        
        /// <summary>
        /// Encrypts or Decrypts a single block of data
        /// </summary>
        /// <param name="data">The block of data to encrypt/decrypt</param>
        /// <param name="encrypt">Whether or not to encrypt the data</param>
        /// <returns>The encrypted/decrypted block</returns>
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
                BitwiseRotateLeft(ref L, (int)lastBlockRPopCount);
                BitwiseRotateLeft(ref R, (int)lastBlockLPopCount);

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

                BitwiseRotateRight(ref L, (int)tempR);
                BitwiseRotateRight(ref R, (int)tempL);
            }


            //Concatenate the two parts into a single array and return it
            byte[] result = new byte[BlockSize];
            BitConverter.GetBytes(L).CopyTo(result, 0);
            BitConverter.GetBytes(R).CopyTo(result, 8);
            return result;
        }

        /// <summary>
        /// Performs a single round of the encryption function
        /// </summary>
        /// <param name="L">The left half of the data to encrypt</param>
        /// <param name="R">The right half of the data to encrypt</param>
        /// <param name="round">The current round of the encryption</param>
        private void EncryptionRound(ref UInt64 L, ref UInt64 R, int round)
        {
            //The round key for this round
            UInt64 roundKey = Subkeys[round];

            //Xor R with the round key
            R = R ^ roundKey;

            //Rotate R left based on the value of L to create diffusion
            BitwiseRotateLeft(ref R, (int)(L % 64));

            //Put R through the SBoxes
            R = Substitute(R, true);

            //Xor L with R
            L = L ^ R;

            //Swap L and R, unless this is the final round of encryption
            if (round < Rounds - 1)
            {
                UInt64 temp = L;
                L = R;
                R = temp;
            }
        }

        /// <summary>
        /// Performs a single round of the decryption function
        /// </summary>
        /// <param name="L">The left half of the data to decrypt</param>
        /// <param name="R">The right half of the data to decrypt</param>
        /// <param name="round">The current round of the decrypt</param>
        private void DecryptionRound(ref UInt64 L, ref UInt64 R, int i)
        {
            //Because we are decrypting we have to perform the round oppperations in the opposite order, so mirror the current round 
            i = (Rounds - 1) - i;

            //The round key for this round
            UInt64 roundKey = Subkeys[i];

            //Perform the same functions performed during an encryption round, but backwards

            //Xor L with R
            L = L ^ R;

            //Put R through the SBoxes, but this time backwards
            R = Substitute(R, false);
            
            //Rotate R right based on the value of L
            BitwiseRotateRight(ref R, (int)(L % 64));

            //Xor R with the round key
            R = R ^ roundKey;

            //Swap L and R, unless this is the final round of decryption
            if (i > 0)
            {
                UInt64 temp = L;
                L = R;
                R = temp;
            }
        }

        /// <summary>
        /// Puts a 64-bit int through the substitute boxes
        /// </summary>
        /// <param name="D">The value to substitute</param>
        /// <param name="forwards">Whether to perform the substitutions forwards or backwards</param>
        /// <returns>The substituted value</returns>
        private UInt64 Substitute(UInt64 D, bool forwards)
        {
            //The amount of substitutions to do
            int subs = 64 / SBoxInputSize;

            UInt64 piece;
            UInt64 sub;
            UInt64 result = 0;

            for(int i = 0; i < subs; i++)
            {
                //Get a 4-bit piece of D
                piece = (D >> (i * SBoxInputSize)) & 15;

                //Find it's substitute
                if (forwards)
                    sub = SubBoxesForwards[piece];
                else
                    sub = SubBoxesBackwards[piece];

                //Add it to the result
                result |= (sub << (i * SBoxInputSize));
            }

            return result;
        }

        /// <summary>
        /// Rotates the bits of a 64-bit int left
        /// </summary>
        /// <param name="l">The value to rotate</param>
        /// <param name="bits">the amount of bits to rotate by</param>
        private void BitwiseRotateLeft(ref UInt64 l, int bits)
        {
            l = (l << bits | (l >> (64 - bits)));
        }

        /// <summary>
        /// Rotates the bits of a 64-bit int right
        /// </summary>
        /// <param name="l">The value to rotate</param>
        /// <param name="bits">the amount of bits to rotate by</param>
        private void BitwiseRotateRight(ref UInt64 l, int bits)
        {
            l = (l >> bits | (l << (64 - bits)));
        }

        /// <summary>
        /// Generates a header block for encryption containing the length of the final block,
        /// the length of the original file name and the index of the metadata block(s)
        /// </summary>
        /// <param name="path">The path of the file to generate a header block for</param>
        /// <param name="blockCount">The amount of blocks of data the file consists of</param>
        /// <param name="finalBlockLength">The length of the final blocks</param>
        /// <returns>A block of data containing the header information</returns>
        private byte[] GenerateHeaderBlock(String path, int blockCount, byte finalBlockLength)
        {
            //Establish the length of the file's original name in bytes
            byte nameLength = (byte)(Path.GetFileName(path).Length * 2);

            //Randomly pick a 32-bit value to be the starting index for the metadata block(s)
            currentMetaDataIndex = (UInt32) (blockCount == 0 ? 0 : rng.Next(0, blockCount - 2));

            //Randomly pick and offset to store the final block length and name length at to fight known-plaintext attacks
            byte dataIndex = (byte)(rng.Next(1, BlockSize - 5));

            //Create an array to store our header block in
            byte[] headerBlock = new byte[BlockSize];

            //Set the first byte to the data index salted with 4 random bits to fight known-plaintext attacks
            headerBlock[0] = (byte)(dataIndex | (rng.Next(0, 16) << 4));
            //Store the final block length at the data index salted with 4 random bits to fight know-plaintext attacks
            headerBlock[dataIndex] = (byte)((finalBlockLength - 1) | (rng.Next(0, 16) << 4));
            //Store the filename length after the final block length 
            headerBlock[dataIndex + 1] = nameLength;

            //Copy over the metadata index to the block's final 4 bytes
            Array.Copy(BitConverter.GetBytes(currentMetaDataIndex), 0, headerBlock, BlockSize - 4, 4);

            //Fill the empty space with random bytes
            for(int i = 1; i < BlockSize - 4; i++)
            {
                if (i == dataIndex || i - 1 == dataIndex) continue;
                headerBlock[i] = (byte)(rng.Next(0, 256));
            }

            //return the header block
            return headerBlock;
        }

        /// <summary>
        /// Generates one or more block(s) containing the files original name
        /// </summary>
        /// <param name="path">The path of the file to generate metadata for</param>
        /// <returns>One or more block(s) of metadata</returns>
        private byte[] GenerateMetaDataBlocks(String path)
        {
            //Split the filename into chars
            String name = Path.GetFileName(path);
            char[] chars = name.ToCharArray();

            //Establish the amount of blocks needed to store the filename
            int metaDataLength = name.Length * 2;
            if (metaDataLength % BlockSize != 0) metaDataLength += BlockSize - (metaDataLength % BlockSize);

            //Create an array to store the metadata in
            byte[] metaDataBlocks = new byte[metaDataLength];

            //Store the file name
            for(int i = 0; i<chars.Length; i++)
            {
                char c = chars[i];

                metaDataBlocks[i * 2] = (byte)(c & 255);
                metaDataBlocks[i * 2 + 1] = (byte)((c & 65280) >> 8);
            }

            //If length of the name in bytes is not a multiple of the block size, pad out the data with random bytes
            if (metaDataLength != (name.Length * 2))
            {
                for (int i = name.Length * 2; i < metaDataLength; i++)
                    metaDataBlocks[i] = (byte)(rng.Next(0, 256));
            }

            //Return the metadata block(s)
            return metaDataBlocks;
        }


        private enum KeyEncoding
        {
            DECIMAL, ASCII, UNICODE, HEX, UNKNOWN
        }
    }

    class VirtualFile
    {
        public byte[] data;
        public String name;
        public String path;


        public void SetName(String newName)
        {
            this.name = newName;
            this.path = Path.GetDirectoryName(path) + "\\" + name;
        }
    }
}
