using System.Security.Cryptography;
using System.Text;
using AltShare.Models;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using Newtonsoft.Json;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace AltShare.Services
{
    public class SharedAccountService
    {
        private readonly IMongoCollection<EncryptedSharedAccount> _sharedAccounts;
        private readonly IMongoCollection<SharedAccountMapping> _masterKeyMappings;
        private readonly Argon2Settings _argonSettings;

        public SharedAccountService(
            IMongoCollection<EncryptedSharedAccount> sharedAccounts,
            IMongoCollection<SharedAccountMapping> masterKeyMappings,
            IOptions<Argon2Settings> argonSettings)
        {
            _sharedAccounts = sharedAccounts;
            _masterKeyMappings = masterKeyMappings;
            _argonSettings = argonSettings.Value;
        }

        public List<EncryptedSharedAccount> GetAll() => _sharedAccounts.Find(account => true).ToList();

        public EncryptedSharedAccount Get(string id) => _sharedAccounts.Find(account => account.Id.ToString() == id).FirstOrDefault();
        public void Delete(EncryptedSharedAccount accountForDeletion) => _sharedAccounts.DeleteOne(account => account.Id == accountForDeletion.Id);

        public void Delete(string id) => _sharedAccounts.DeleteOne(account => account.Id.ToString() == id);

        public byte[] DeriveKeyWithArgon2(string password, byte[] salt)
        {
            var config = new Argon2Config {
                TimeCost = 3,
                MemoryCost = 65536,
                Lanes = 2,
                Password = Encoding.UTF8.GetBytes(password),
                Salt = salt,
                HashLength = 32
            };
            
            using var argon2 = new Argon2(config);
            return argon2.Hash().Buffer;
        }

        public byte[] EncryptMasterKey(byte[] masterKey, string password, out byte[] salt, out byte[] iv, out byte[] tag)
        {
            salt = new byte[16];
            iv = new byte[12];
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(iv);

            // Derive key using Argon2
            var derivedKey = DeriveKeyWithArgon2(password, salt);

            using var aes = new AesGcm(derivedKey);
            var ciphertext = new byte[masterKey.Length];
            tag = new byte[16];

            aes.Encrypt(iv, masterKey, ciphertext, tag);
            return ciphertext;
        }

        public byte[] DecryptMasterKey(byte[] encryptedMasterKey, byte[] salt, byte[] iv, byte[] tag, string password)
        {
            var derivedKey = DeriveKeyWithArgon2(password, salt);
            var plaintext = new byte[encryptedMasterKey.Length];

            using var aes = new AesGcm(derivedKey);
            aes.Decrypt(iv, encryptedMasterKey, tag, plaintext);

            return plaintext;
        }

        public async Task<byte[]> GetDecryptedMasterKeyAsync(string email, string password)
        {
            var mapping = await _masterKeyMappings.Find(m => m.Email == email)
                                                .FirstOrDefaultAsync();

            if (mapping == null) throw new InvalidOperationException("Master key not found");

            return DecryptMasterKey(
                mapping.EncryptedMasterKey,
                mapping.Salt,
                mapping.IV,
                mapping.Tag,
                password
            );
        }
    }
}
    