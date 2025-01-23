using AltShare.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AltShare.Services
{
    public class UserAccountService
    {
        private readonly IMongoCollection<UserAccount> _accounts;

        public UserAccountService(MongoClient mongoClient, IOptions<AccountDatabaseSettings> settings)
        {
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _accounts = database.GetCollection<UserAccount>(nameof(UserAccount));
        }

        async public Task<UserAccount> GetAccountByEmail(string email)
        {
            var filter = Builders<UserAccount>.Filter.Eq(account => account.Email, email);
            var results = await _accounts.Find(filter).ToListAsync();

            return results[0];
        }

        public List<UserAccount> GetAll() => _accounts.Find(account => true).ToList();

        public async Task<bool> EmailExists(string value)
        {
            var filter = Builders<UserAccount>.Filter.Eq(account => account.Email, value);
            return await _accounts.Find(filter).AnyAsync();
        }

        public async Task<bool> UsernameExists(string value)
        {
            var filter = Builders<UserAccount>.Filter.Eq(account => account.Username, value);
            return await _accounts.Find(filter).AnyAsync();
        }

        //public IEnumerable<AccountDto> GetAllForUser(string userId)
        //{
        //    return _accounts
        //        .ToList()
        //        .Select(Account => new AccountDto
        //        {
        //            Id = Account.Id,
        //            Title = Account.Title,
        //            Content = Account.Content,
        //            Order = Account.Order
        //        });
        //}

        public UserAccount Get(string id) => _accounts.Find(Account => Account.Id.ToString() == id).FirstOrDefault();

        public UserAccount Create(UserAccount Account)
        {
            _accounts.InsertOne(Account);
            return Account;
        }

        //public void Update(AccountUpdateDto updateAccount)
        //{
        //    var updates = typeof(AccountUpdateDto)
        //        .GetProperties()
        //        .Where(p => p.Name != "Id" && p.GetValue(updateAccount) != null)
        //        .Select(p => Builders<Account>.Update.Set(p.Name, p.GetValue(updateAccount)));

        //    var combinedUpdate = Builders<Account>.Update.Combine(updates);
        //    _accounts.UpdateOneAsync(account => account.Id == updateAccount.Id, combinedUpdate);
        //}

        public void Delete(UserAccount AccountForDeletion) => _accounts.DeleteOne(Account => Account.Id == AccountForDeletion.Id);

        public void Delete(string id) => _accounts.DeleteOne(Account => Account.Id.ToString() == id);
    }
}
