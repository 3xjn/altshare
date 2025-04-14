using System.Security.Claims;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.Extensions.Options;
using System.Xml.Linq;
using System.Text.Json;

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
        private readonly HttpClient _httpClient;

        public AccountController(
            MongoClient mongoClient,
            IOptions<AccountDatabaseSettings> settings,
            SharedAccountService sharedService,
            HttpClient httpClient)
        {
            _sharedService = sharedService;
            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _shared = database.GetCollection<EncryptedSharedAccount>(nameof(EncryptedSharedAccount));
            _mapping = database.GetCollection<SharedAccountMapping>(nameof(SharedAccountMapping));
            _relationships = database.GetCollection<SharingRelationship>(nameof(SharingRelationship));
            _httpClient = httpClient;
        }

        [HttpGet]
        public async Task<IActionResult> GetAccounts()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token." });
            }

            var emailFilter = Builders<EncryptedSharedAccount>.Filter.Eq(account => account.OwnerEmail, email);
            var accounts = await _shared.Find(emailFilter).ToListAsync();
            var accountResponse = new List<Dictionary<string, string>>();

            foreach (var account in accounts)
            {
                accountResponse.Add(new Dictionary<string, string> { { "encryptedData", account.EncryptedJson } });
            }

            return Ok(accountResponse);
        }

        [HttpPost]
        public async Task<IActionResult> AddAccount([FromBody] AddAccountRequest request)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email)) return Unauthorized();

            var accountId = ObjectId.GenerateNewId();

            var encryptedAccount = new EncryptedSharedAccount
            {
                Id = accountId,
                OwnerEmail = email,
                EncryptedJson = request.encryptedData
            };

            await _shared.InsertOneAsync(encryptedAccount);

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
                    .Set(a => a.EncryptedJson, request.encryptedData);

                await _shared.UpdateOneAsync(filter, update);

                //var mappingFilter = Builders<SharedAccountMapping>.Filter.Eq("SharedAccountId", ObjectId.Parse(id));
                //var mappingUpdate = Builders<SharedAccountMapping>.Update
                //    .Set(m => m.EncryptedMasterKey, request.userKey);

                //await _mapping.UpdateOneAsync(mappingFilter, mappingUpdate);

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

        [HttpGet("rank")]
        public async Task<IActionResult> GetRank([FromQuery] RankRequest request)
        {
            _httpClient.DefaultRequestHeaders.Add("x-api-key", "6e0a773201e199d9889dc8c8c0147ff033a6c841af7e6a4b6fd739a876e7937d");
            await _httpClient.GetAsync($"https://marvelrivalsapi.com/api/v1/player/{request.Username}/update");

            var response = await _httpClient.GetAsync($"https://marvelrivalsapi.com/api/v1/player/{request.Username}?season=2");
            response.EnsureSuccessStatusCode();

            var jsonString = await response.Content.ReadAsStringAsync();
            using (JsonDocument doc = JsonDocument.Parse(jsonString))
            {
                var rank = doc.RootElement
                                  .GetProperty("player")
                                  .GetProperty("rank")
                                  .GetProperty("rank")
                                  .GetString();

                return Ok(new { rank });
            }
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