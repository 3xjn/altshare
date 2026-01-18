using AltShare.Models;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;

namespace AltShare.Services
{
    public class GroupService
    {
        private const string DefaultGroupName = "Personal";
        private readonly IMongoCollection<AccountGroup> _groups;
        private readonly IMongoCollection<EncryptedSharedAccount> _accounts;
        private readonly IMongoCollection<SharingRelationship> _relationships;

        public GroupService(MongoClient mongoClient, IOptions<AccountDatabaseSettings> settings)
        {
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _groups = database.GetCollection<AccountGroup>(nameof(AccountGroup));
            _accounts = database.GetCollection<EncryptedSharedAccount>(nameof(EncryptedSharedAccount));
            _relationships = database.GetCollection<SharingRelationship>(nameof(SharingRelationship));
        }

        public async Task<AccountGroup> EnsureDefaultGroupAsync(string email)
        {
            var filter = Builders<AccountGroup>.Filter.And(
                Builders<AccountGroup>.Filter.Eq(g => g.OwnerEmail, email),
                Builders<AccountGroup>.Filter.Eq(g => g.UsesMasterKey, true)
            );

            var group = await _groups.Find(filter).FirstOrDefaultAsync();
            if (group == null)
            {
                group = new AccountGroup
                {
                    OwnerEmail = email,
                    Name = DefaultGroupName,
                    UsesMasterKey = true,
                    EncryptedGroupKey = null
                };
                await _groups.InsertOneAsync(group);
            }

            await BackfillGroupIdsAsync(email, group.Id);
            return group;
        }

        public async Task<ObjectId?> TryResolveGroupIdAsync(string email, string? groupId)
        {
            var defaultGroup = await EnsureDefaultGroupAsync(email);

            if (string.IsNullOrWhiteSpace(groupId))
            {
                return defaultGroup.Id;
            }

            if (!ObjectId.TryParse(groupId, out var parsedId))
            {
                return null;
            }

            var exists = await _groups.Find(g => g.OwnerEmail == email && g.Id == parsedId).AnyAsync();
            if (!exists)
            {
                return null;
            }

            return parsedId;
        }

        public async Task<List<AccountGroup>> GetGroupsAsync(string email)
        {
            await EnsureDefaultGroupAsync(email);
            var filter = Builders<AccountGroup>.Filter.Eq(g => g.OwnerEmail, email);
            return await _groups.Find(filter).ToListAsync();
        }

        public async Task<AccountGroup?> CreateGroupAsync(string email, string name, string encryptedGroupKey)
        {
            var normalizedName = name.Trim();
            if (string.IsNullOrWhiteSpace(normalizedName) ||
                string.IsNullOrWhiteSpace(encryptedGroupKey))
            {
                return null;
            }

            var existing = await _groups.Find(g => g.OwnerEmail == email && g.Name == normalizedName).AnyAsync();
            if (existing)
            {
                return null;
            }

            var group = new AccountGroup
            {
                OwnerEmail = email,
                Name = normalizedName,
                UsesMasterKey = false,
                EncryptedGroupKey = encryptedGroupKey
            };

            await _groups.InsertOneAsync(group);
            return group;
        }

        private async Task BackfillGroupIdsAsync(string email, ObjectId groupId)
        {
            var accountFilter = Builders<EncryptedSharedAccount>.Filter.And(
                Builders<EncryptedSharedAccount>.Filter.Eq(a => a.OwnerEmail, email),
                Builders<EncryptedSharedAccount>.Filter.Or(
                    Builders<EncryptedSharedAccount>.Filter.Exists("groupId", false),
                    Builders<EncryptedSharedAccount>.Filter.Eq(a => a.GroupId, ObjectId.Empty)
                )
            );

            var accountUpdate = Builders<EncryptedSharedAccount>.Update.Set(a => a.GroupId, groupId);
            await _accounts.UpdateManyAsync(accountFilter, accountUpdate);

            var relationshipFilter = Builders<SharingRelationship>.Filter.And(
                Builders<SharingRelationship>.Filter.Eq(r => r.OwnerEmail, email),
                Builders<SharingRelationship>.Filter.Or(
                    Builders<SharingRelationship>.Filter.Exists("groupId", false),
                    Builders<SharingRelationship>.Filter.Eq(r => r.GroupId, ObjectId.Empty)
                )
            );

            var relationshipUpdate = Builders<SharingRelationship>.Update.Set(r => r.GroupId, groupId);
            await _relationships.UpdateManyAsync(relationshipFilter, relationshipUpdate);
        }
    }
}
