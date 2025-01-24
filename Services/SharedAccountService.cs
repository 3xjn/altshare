using AltShare.Models;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AltShare.Services
{
    public class SharedAccountService
    {
        private readonly IMongoCollection<EncryptedSharedAccount> _shared;
        private readonly IMongoCollection<SharedAccountMapping> _mapping;

        public SharedAccountService(MongoClient mongoClient, IOptions<AccountDatabaseSettings> settings)
        {
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _shared = database.GetCollection<EncryptedSharedAccount>(nameof(EncryptedSharedAccount));
            _mapping = database.GetCollection<SharedAccountMapping>(nameof(SharedAccountMapping));
        }

        public List<EncryptedSharedAccount> GetAll() => _shared.Find(account => true).ToList();

        public EncryptedSharedAccount Get(string id) => _shared.Find(account => account.Id.ToString() == id).FirstOrDefault();

        public void Create(string email, string password, List<DecryptedSharedAccount> decryptedAccounts)
        {
            var (masterKey, encryptedJson) = EncryptAccount(email, password, decryptedAccounts);

            var encryptedSharedAccount = new EncryptedSharedAccount
            {
                OwnerEmail = email,
                EncryptedJson = encryptedJson,
                Id = ObjectId.GenerateNewId(),
            };

            _shared.InsertOne(encryptedSharedAccount);

            var encryptedMasterKey = Aes256GcmRandomKeyEncryption.Encrypt(masterKey, password);
            var combinedUserKey = CombineIvTagCiphertext(encryptedMasterKey.IV, encryptedMasterKey.Tag, encryptedMasterKey.Ciphertext);

            var accountMapping = new SharedAccountMapping
            {
                Email = email,
                SharedAccountId = encryptedSharedAccount.Id,
                UserKey = Convert.ToBase64String(combinedUserKey),
            };
        }

        private (byte[], string) EncryptAccount(string email, string password, List<DecryptedSharedAccount> decryptedAccounts)
        {
            var decryptedJson = decryptedAccounts.ToJson();
            var encrypted = Aes256GcmRandomKeyEncryption.Encrypt(System.Text.Encoding.UTF8.GetBytes(decryptedJson));
            var combined = CombineIvTagCiphertext(encrypted.IV, encrypted.Tag, encrypted.Ciphertext);

            return (encrypted.Key, Convert.ToBase64String(combined));
        }

        byte[] CombineIvTagCiphertext(byte[] iv, byte[] tag, byte[] ciphertext)
        {
            // Example sizes:
            // iv.Length = 12, tag.Length = 16, ciphertext.Length = variable
            var combined = new byte[iv.Length + tag.Length + ciphertext.Length];

            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(tag, 0, combined, iv.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, iv.Length + tag.Length, ciphertext.Length);

            return combined;
        }

        void SplitIvTagCiphertext(byte[] combined, out byte[] iv, out byte[] tag, out byte[] ciphertext)
        {
            // Known GCM sizes (if you used the defaults):
            int ivLength = 12;
            int tagLength = 16;

            iv = new byte[ivLength];
            tag = new byte[tagLength];
            ciphertext = new byte[combined.Length - ivLength - tagLength];

            Buffer.BlockCopy(combined, 0, iv, 0, ivLength);
            Buffer.BlockCopy(combined, ivLength, tag, 0, tagLength);
            Buffer.BlockCopy(combined, ivLength + tagLength, ciphertext, 0, ciphertext.Length);
        }

        public void Delete(EncryptedSharedAccount accountForDeletion) => _shared.DeleteOne(account => account.Id == accountForDeletion.Id);

        public void Delete(string id) => _shared.DeleteOne(account => account.Id.ToString() == id);
    }
}
