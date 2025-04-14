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
    }
}
    