using System.Security.Claims;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.Extensions.Options;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("api/account")]
    [Tags("account")]
    [Authorize]
    public class AccountController : Controller
    {
        private readonly SharedAccountService _sharedService;
        private readonly IMongoCollection<EncryptedSharedAccount> _shared;
        private readonly IMongoCollection<SharedAccountMapping> _mapping;
        private readonly IMongoCollection<SharingRelationship> _relationships;

        public AccountController(
            MongoClient mongoClient,
            IOptions<AccountDatabaseSettings> settings,
            SharedAccountService sharedService)
        {
            _sharedService = sharedService;
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _shared = database.GetCollection<EncryptedSharedAccount>(nameof(EncryptedSharedAccount));
            _mapping = database.GetCollection<SharedAccountMapping>(nameof(SharedAccountMapping));
            _relationships = database.GetCollection<SharingRelationship>(nameof(SharingRelationship));
        }

        [HttpGet]
        public async Task<IActionResult> GetAccounts()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            var emailFilter = Builders<SharedAccountMapping>.Filter.Eq(account => account.Email, email);
            var mappings = await _mapping.Find(emailFilter).ToListAsync();

            var encryptedAccounts = new List<Dictionary<string, string>>();

            foreach (var mapping in mappings)
            {
                try
                {
                    var filter = Builders<EncryptedSharedAccount>.Filter.Eq("_id", mapping.SharedAccountId);
                    var sharedAccount = await _shared.Find(filter).FirstOrDefaultAsync();

                    if (sharedAccount == null)
                    {
                        Console.WriteLine($"Shared account with ID {mapping.SharedAccountId} not found.");
                        continue;
                    }

                    encryptedAccounts.Add(new Dictionary<string, string> {
                        { "encryptedData", sharedAccount.EncryptedJson },
                        { "userKey", Convert.ToBase64String(sharedAccount.IV) },
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error retrieving shared account: {ex.Message}");
                }
            }

            return Ok(new { encryptedAccounts });
        }

        [HttpPost]
        public async Task<IActionResult> AddAccount([FromBody] AddAccountRequest request)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email)) return Unauthorized();
            
            var accountId = ObjectId.GenerateNewId();
            
            var encryptedAccount = new EncryptedSharedAccount {
                Id = accountId,
                OwnerEmail = email,
                EncryptedJson = request.encryptedData,
                IV = Convert.FromBase64String(request.userKey)
            };

            var mapping = new SharedAccountMapping {
                Email = email,
                SharedAccountId = accountId,
                UserKey = request.userKey
            };

            await _shared.InsertOneAsync(encryptedAccount);
            await _mapping.InsertOneAsync(mapping);
            
            return Ok();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteAccount(string id)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            try
            {
                var filter = Builders<EncryptedSharedAccount>.Filter.And(
                    Builders<EncryptedSharedAccount>.Filter.Eq("_id", ObjectId.Parse(id)),
                    Builders<EncryptedSharedAccount>.Filter.Eq("OwnerEmail", email)
                );

                var result = await _shared.DeleteOneAsync(filter);
                if (result.DeletedCount == 0)
                {
                    return NotFound(new { message = "Account not found or unauthorized." });
                }

                var mappingFilter = Builders<SharedAccountMapping>.Filter.Eq("SharedAccountId", ObjectId.Parse(id));
                await _mapping.DeleteOneAsync(mappingFilter);

                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> EditAccount(string id, [FromBody] AddAccountRequest request)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email)) return Unauthorized();

            try
            {
                var filter = Builders<EncryptedSharedAccount>.Filter.And(
                    Builders<EncryptedSharedAccount>.Filter.Eq("_id", ObjectId.Parse(id)),
                    Builders<EncryptedSharedAccount>.Filter.Eq("OwnerEmail", email)
                );

                var existingAccount = await _shared.Find(filter).FirstOrDefaultAsync();
                if (existingAccount == null)
                {
                    return NotFound(new { message = "Account not found or unauthorized." });
                }

                var update = Builders<EncryptedSharedAccount>.Update
                    .Set(a => a.EncryptedJson, request.encryptedData)
                    .Set(a => a.IV, Convert.FromBase64String(request.userKey));

                await _shared.UpdateOneAsync(filter, update);

                var mappingFilter = Builders<SharedAccountMapping>.Filter.Eq("SharedAccountId", ObjectId.Parse(id));
                var mappingUpdate = Builders<SharedAccountMapping>.Update
                    .Set(m => m.UserKey, request.userKey);

                await _mapping.UpdateOneAsync(mappingFilter, mappingUpdate);

                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("share")]
        public async Task<IActionResult> CreateSharingRelationship([FromBody] CreateSharingRequest request)
        {
            var ownerEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(ownerEmail))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            var relationship = new SharingRelationship
            {
                OwnerEmail = ownerEmail,
                SharedWithEmail = request.SharedWithEmail,
                EncryptedMasterKey = Convert.FromBase64String(request.EncryptedMasterKey),
                IV = Convert.FromBase64String(request.IV),
                Salt = Convert.FromBase64String(request.Salt),
                Tag = Convert.FromBase64String(request.Tag)
            };

            var existingRelationshipCount = await _relationships.CountDocumentsAsync(sr => sr.OwnerEmail == ownerEmail && sr.SharedWithEmail == request.SharedWithEmail);

            if (existingRelationshipCount > 0)
            {
                return BadRequest("Account already shared");
            }
                
            await _relationships.InsertOneAsync(relationship);
            return Ok();
        }

        [HttpGet("share")]
        public async Task<IActionResult> GetSharedAccounts()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            };

            Console.WriteLine($"Getting shared accounts for email: {email}");

            var emailFilter = Builders<SharingRelationship>.Filter.Eq(account => account.SharedWithEmail, email);
            var invites = await _relationships.Find(emailFilter).ToListAsync();
            Console.WriteLine($"Found {invites.Count} sharing relationships");

            var encryptedAccounts = new List<Dictionary<string, string>>();

            foreach (var invite in invites)
            {
                try
                {
                    Console.WriteLine($"Looking for accounts from owner: {invite.OwnerEmail}");
                    var filter = Builders<EncryptedSharedAccount>.Filter.Eq(a => a.OwnerEmail, invite.OwnerEmail);
                    var sharedAccounts = await _shared.Find(filter).ToListAsync();
                    Console.WriteLine($"Found {sharedAccounts.Count} accounts from this owner");

                    foreach (var sharedAccount in sharedAccounts)
                    {
                        encryptedAccounts.Add(new Dictionary<string, string> {
                            { "encryptedData", sharedAccount.EncryptedJson },
                            { "accountIv", Convert.ToBase64String(sharedAccount.IV) },
                            { "encryptedMasterKey", Convert.ToBase64String(invite.EncryptedMasterKey) },
                            { "iv", Convert.ToBase64String(invite.IV) },
                            { "salt", Convert.ToBase64String(invite.Salt) },
                            { "tag", Convert.ToBase64String(invite.Tag) }
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error retrieving shared account: {ex.Message}");
                }
            }

            Console.WriteLine($"Returning {encryptedAccounts.Count} total shared accounts");
            return Ok(new { encryptedAccounts });
        }
    }

    public class CreateSharingRequest
    {
        public string SharedWithEmail { get; set; } = null!;
        public string EncryptedMasterKey { get; set; } = null!;
        public string IV { get; set; } = null!;
        public string Salt { get; set; } = null!;
        public string Tag { get; set; } = null!;
    }
}