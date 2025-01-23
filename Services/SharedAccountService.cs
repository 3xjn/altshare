using AltShare.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AltShare.Services
{
    public class SharedAccountService
    {
        private readonly IMongoCollection<SharedAccount> _shared;

        public SharedAccountService(MongoClient mongoClient, IOptions<AccountDatabaseSettings> settings)
        {
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _shared = database.GetCollection<SharedAccount>(nameof(SharedAccount));
        }

        //async public Task<UserAccount> GetAccountByEmail(string email)
        //{
        //    var filter = Builders<SharedAccount>.Filter.Eq(account => account.Email, email);
        //    var results = await _shared.Find(filter).ToListAsync();

        //    return results[0];
        //}

        public List<SharedAccount> GetAll() => _shared.Find(account => true).ToList();

        //public async Task<bool> EmailExists(string value)
        //{
        //    var filter = Builders<SharedAccount>.Filter.Eq(account => account.Email, value);
        //    return await _shared.Find(filter).AnyAsync();
        //}

        //public async Task<bool> UsernameExists(string value)
        //{
        //    var filter = Builders<SharedAccount>.Filter.Eq(account => account.Username, value);
        //    return await _shared.Find(filter).AnyAsync();
        //}

        public SharedAccount Get(string id) => _shared.Find(Account => Account.Id.ToString() == id).FirstOrDefault();

        public SharedAccount Create(SharedAccount Account)
        {
            _shared.InsertOne(Account);
            return Account;
        }

        //public void Update(AccountUpdateDto updateAccount)
        //{
        //    var updates = typeof(AccountUpdateDto)
        //        .GetProperties()
        //        .Where(p => p.Name != "Id" && p.GetValue(updateAccount) != null)
        //        .Select(p => Builders<Account>.Update.Set(p.Name, p.GetValue(updateAccount)));

        //    var combinedUpdate = Builders<Account>.Update.Combine(updates);
        //    _shared.UpdateOneAsync(account => account.Id == updateAccount.Id, combinedUpdate);
        //}

        public void Delete(SharedAccount AccountForDeletion) => _shared.DeleteOne(Account => Account.Id == AccountForDeletion.Id);

        public void Delete(string id) => _shared.DeleteOne(Account => Account.Id.ToString() == id);
    }
}
