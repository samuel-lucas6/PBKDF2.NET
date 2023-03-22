/*
    PBKDF2.NET: A .NET implementation of PBKDF2 with HMAC-SHA-2.
    Copyright (c) 2023 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Pbkdf2DotNet;

public static class PBKDF2
{
    public const int KeySize = 32;
    public const int SaltSize = 16;
    
    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, HashAlgorithmName hashAlgorithm)
    {
        int hashLength = GetHashAlgorithmLength(hashAlgorithm);
        if (hashLength == 0) { throw new NotSupportedException($"{hashAlgorithm.Name} is not supported because SHA-2 should be used today."); }
        if (iterations < 1) { throw new ArgumentOutOfRangeException(nameof(iterations), iterations, $"{nameof(iterations)} must be greater than 0."); }
        
        int blockCount = (outputKeyingMaterial.Length + hashLength - 1) / hashLength;
        int lastBlockLength = outputKeyingMaterial.Length - (blockCount - 1) * hashLength;
        Span<byte> counter = stackalloc byte[sizeof(int)];
        Span<byte> block = stackalloc byte[hashLength];
        Span<byte> previousHash = stackalloc byte[hashLength];
        using var hmac = IncrementalHash.CreateHMAC(hashAlgorithm, password);
        for (int i = 1; i <= blockCount; i++) {
            BinaryPrimitives.WriteInt32BigEndian(counter, i);
            hmac.AppendData(salt);
            hmac.AppendData(counter);
            hmac.GetHashAndReset(block);
            block.CopyTo(previousHash);
            for (int j = 2; j <= iterations; j++) {
                hmac.AppendData(previousHash);
                hmac.GetHashAndReset(previousHash);
                for (int z = 0; z < previousHash.Length; z++) {
                    block[z] ^= previousHash[z];
                }
            }
            int length = i == blockCount ? lastBlockLength : hashLength;
            block[..length].CopyTo(outputKeyingMaterial.Slice(start: (i - 1) * hashLength, length));
        }
        CryptographicOperations.ZeroMemory(counter);
        CryptographicOperations.ZeroMemory(previousHash);
        CryptographicOperations.ZeroMemory(block);
    }
    
    private static int GetHashAlgorithmLength(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256) { return 32; }
        if (hashAlgorithm == HashAlgorithmName.SHA384) { return 48; }
        return hashAlgorithm == HashAlgorithmName.SHA512 ? 64 : 0;
    }
}