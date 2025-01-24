using System;
using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;

public static class Aes256GcmRandomKeyEncryption
{
    /// <summary>
    /// Encrypts data using a completely random 256-bit key and AES-GCM.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <returns>
    /// A tuple containing Key, IV, Tag, and Ciphertext.
    /// Keep the Key safe (e.g. in a secure vault), and the IV and Tag need
    /// to be stored or transmitted alongside the Ciphertext to decrypt.
    /// </returns>
    public static (byte[] Key, byte[] IV, byte[] Tag, byte[] Ciphertext) Encrypt(byte[] plaintext)
    {
        if (plaintext == null || plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be null or empty.", nameof(plaintext));

        // 1. Generate a random 256-bit key (32 bytes).
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // 2. Generate a random 96-bit IV (12 bytes).
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);

        // 3. Create AES-GCM and encrypt.
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16]; // GCM tag = 128 bits = 16 bytes

        using (var aesGcm = new AesGcm(key, tag.Length))
        {
            aesGcm.Encrypt(
                nonce: iv,
                plaintext: plaintext,
                ciphertext: ciphertext,
                tag: tag
            );
        }

        return (key, iv, tag, ciphertext);
    }

    /// <summary>
    /// Decrypts AES-256-GCM ciphertext given the random Key, IV, and Tag.
    /// </summary>
    /// <param name="key">The 256-bit key that was used to encrypt.</param>
    /// <param name="iv">The 96-bit IV used during encryption.</param>
    /// <param name="tag">The 128-bit authentication tag from encryption.</param>
    /// <param name="ciphertext">The encrypted bytes.</param>
    /// <returns>The decrypted plaintext bytes.</returns>
    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] tag, byte[] ciphertext)
    {
        if (key == null || key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes for AES-256.", nameof(key));
        if (iv == null || iv.Length != 12)
            throw new ArgumentException("IV must be 12 bytes for GCM.", nameof(iv));
        if (tag == null || tag.Length != 16)
            throw new ArgumentException("Tag must be 16 bytes for GCM.", nameof(tag));
        if (ciphertext == null || ciphertext.Length == 0)
            throw new ArgumentException("Ciphertext cannot be null or empty.", nameof(ciphertext));

        byte[] plaintext = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(key, tag.Length))
        {
            aesGcm.Decrypt(
                nonce: iv,
                ciphertext: ciphertext,
                tag: tag,
                plaintext: plaintext
            );
        }

        return plaintext;
    }

    /// <summary>
    /// Encrypts the specified plaintext using a password-based key (derived with Argon2) and AES-256-GCM.
    /// </summary>
    /// <param name="plaintext">The data you want to encrypt.</param>
    /// <param name="password">The password used to derive the encryption key via Argon2.</param>
    /// <returns>
    /// An object containing the random salt, IV, authentication tag, and ciphertext as byte arrays.
    /// You must keep these pieces together in order to decrypt later.
    /// </returns>
    public static (byte[] Salt, byte[] IV, byte[] Tag, byte[] Ciphertext) Encrypt(byte[] plaintext, string password)
    {
        if (plaintext == null || plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        // 1. Generate a random salt for Argon2.
        byte[] salt = new byte[16]; // 128-bit salt
        RandomNumberGenerator.Fill(salt);

        // 2. Derive a 256-bit (32 bytes) key using Argon2id.
        byte[] key = DeriveKeyArgon2(password, salt, 32);

        // 3. Generate a random IV (96 bits recommended for GCM).
        byte[] iv = new byte[12]; // 96-bit IV is typical for GCM
        RandomNumberGenerator.Fill(iv);

        // 4. Encrypt using AesGcm
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16]; // 128-bit authentication tag

        using (var aesGcm = new AesGcm(key, tag.Length))
        {
            aesGcm.Encrypt(
                nonce: iv,
                plaintext: plaintext,
                ciphertext: ciphertext,
                tag: tag
            );
        }

        // Return salt, IV, tag, ciphertext
        return (salt, iv, tag, ciphertext);
    }

    /// <summary>
    /// Decrypts ciphertext using Argon2-derived key and AES-256-GCM.
    /// </summary>
    /// <param name="salt">The salt originally used for Argon2.</param>
    /// <param name="iv">The IV (nonce) used for AES-GCM.</param>
    /// <param name="tag">The authentication tag from encryption.</param>
    /// <param name="ciphertext">The ciphertext produced during encryption.</param>
    /// <param name="password">The same password that was used during encryption.</param>
    /// <returns>The plaintext as a byte array.</returns>
    public static byte[] Decrypt(byte[] salt, byte[] iv, byte[] tag, byte[] ciphertext, string password)
    {
        if (salt == null || salt.Length == 0)
            throw new ArgumentException("Salt cannot be empty.", nameof(salt));
        if (iv == null || iv.Length == 0)
            throw new ArgumentException("IV cannot be empty.", nameof(iv));
        if (tag == null || tag.Length == 0)
            throw new ArgumentException("Tag cannot be empty.", nameof(tag));
        if (ciphertext == null || ciphertext.Length == 0)
            throw new ArgumentException("Ciphertext cannot be empty.", nameof(ciphertext));
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        // 1. Re-derive the key using the same salt and password.
        byte[] key = DeriveKeyArgon2(password, salt, 32);

        byte[] plaintext = new byte[ciphertext.Length];

        // 2. Decrypt using AesGcm
        using (var aesGcm = new AesGcm(key, tag.Length))
        {
            aesGcm.Decrypt(
                nonce: iv,
                ciphertext: ciphertext,
                tag: tag,
                plaintext: plaintext
            );
        }

        return plaintext;
    }

    /// <summary>
    /// Helper method to derive key using Argon2id (recommended).
    /// </summary>
    private static byte[] DeriveKeyArgon2(string password, byte[] salt, int keySizeBytes)
    {
        var config = new Argon2Config
        {
            //Type = Argon2Type.Argon2id,       // Argon2id is preferred
            //Version = Argon2Version.Number13, // Latest version (1.3)
            Password = System.Text.Encoding.UTF8.GetBytes(password),
            Salt = salt,

            // The following parameters should be tuned depending on your environment:
            TimeCost = 4,      // Number of iterations
            MemoryCost = 1 << 16, // 64MB - adjust based on your memory/requirements
            Lanes = 4,         // Degree of parallelism
            Threads = 4,       // Threads to use (ideally match Lanes)

            HashLength = keySizeBytes // 32 bytes for a 256-bit key
        };

        using (var argon2A = new Argon2(config))
        {
            return argon2A.Hash().Buffer;
        }
    }
}