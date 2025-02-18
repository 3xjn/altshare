using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using MongoDB.Bson;
using System.Text.Json;
using System.Net.Http;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("api/auth")]
    [Tags("auth")]
    public class AuthController : Controller
    {
        private readonly UserAccountService _accountService;
        private readonly SharedAccountService _sharedAccountService;
        private readonly PasswordHasherService _passwordHasherService;
        private readonly IConfiguration _configuration;
        private readonly IMongoCollection<EncryptedSharedAccount> _shared;
        private readonly IMongoCollection<SharedAccountMapping> _mapping;
        private readonly HttpClient _httpClient;

        public AuthController(
            MongoClient mongoClient,
            IOptions<AccountDatabaseSettings> settings,
            UserAccountService accountService,
            SharedAccountService sharedAccountService,
            PasswordHasherService passwordHasherService,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory)
        {
            _accountService = accountService;
            _sharedAccountService = sharedAccountService;
            _passwordHasherService = passwordHasherService;
            _configuration = configuration;
            _httpClient = httpClientFactory.CreateClient();

            var database = mongoClient.GetDatabase(settings.Value.DatabaseName);
            _shared = database.GetCollection<EncryptedSharedAccount>(nameof(EncryptedSharedAccount));
            _mapping = database.GetCollection<SharedAccountMapping>(nameof(SharedAccountMapping));
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterRequest request)
        {
            Console.WriteLine($"Registration attempt for email: {request.Email}");
            
            if (request.Password != request.PasswordConfirmation)
            {
                return StatusCode(400, new { error = "Passwords do not match" });
            }

            var userNameTaken = await _accountService.UsernameExists(request.Username);
            if (userNameTaken)
            {
                return Conflict(new { error = "An account with this username already exists." });
            }

            var isEmailTaken = await _accountService.EmailExists(request.Email);
            if (isEmailTaken)
            {
                return Conflict(new { error = "An account with this email already exists." });
            }

            try {
                Console.WriteLine("Creating user account...");
                // Hash the password with Argon2 (this generates its own salt)
                var passwordHash = _passwordHasherService.HashPassword(request.Password);
                var token = GenerateJwtToken(request.Email);

                // Create the user account
                _accountService.Create(new UserAccount
                {
                    Username = request.Username,
                    Email = request.Email,
                    HashedPassword = passwordHash,
                });

                Console.WriteLine("Creating account mapping...");
                var accountMapping = new SharedAccountMapping
                {
                    Email = request.Email,
                    EncryptedMasterKey = Convert.FromBase64String(request.MasterKeyEncrypted),
                    IV = Convert.FromBase64String(request.IV),
                    Salt = Convert.FromBase64String(request.Salt),
                    Tag = Array.Empty<byte>() // Not used in new flow
                };

                await _mapping.InsertOneAsync(accountMapping);
                Console.WriteLine("Account mapping created successfully");

                var response = new { 
                    token,
                    masterKeyEncrypted = Convert.ToBase64String(accountMapping.EncryptedMasterKey),
                    masterKeyIv = Convert.ToBase64String(accountMapping.IV),
                    salt = Convert.ToBase64String(accountMapping.Salt),
                    tag = Convert.ToBase64String(accountMapping.Tag)
                };
                Console.WriteLine($"Registration complete. Response: {System.Text.Json.JsonSerializer.Serialize(response)}");
                return Ok(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Registration failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                return StatusCode(500, new { error = "Registration failed. Please try again." });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            Console.WriteLine($"Login attempt for email: {request.Email}");
            var emailExists = await _accountService.EmailExists(request.Email);

            if (!emailExists)
            {
                Console.WriteLine("email not found");
                return Unauthorized(new { message = "Invalid email or password." });
            }

            var account = await _accountService.GetAccountByEmail(request.Email);
            var isValid = _passwordHasherService.VerifyPassword(account.HashedPassword, request.Password);

            if (!isValid)
            {
                Console.WriteLine("password incorrect");
                return Unauthorized(new { message = "Invalid email or password." });
            }

            var token = GenerateJwtToken(request.Email);
            
            // Get the user's encrypted master key info
            var emailFilter = Builders<SharedAccountMapping>.Filter.Eq(account => account.Email, request.Email);
            var mapping = await _mapping.Find(emailFilter).FirstOrDefaultAsync();
            
            Console.WriteLine($"Found mapping: {mapping != null}");
            if (mapping == null || mapping.EncryptedMasterKey == null || mapping.EncryptedMasterKey.Length == 0)
            {
                Console.WriteLine("No valid master key found - user must register");
                return Unauthorized(new { 
                    message = "Account not properly configured. Please contact support."
                });
            }
            
            // Return existing mapping
            var response = new { 
                token,
                masterKeyEncrypted = Convert.ToBase64String(mapping.EncryptedMasterKey),
                masterKeyIv = Convert.ToBase64String(mapping.IV),
                salt = Convert.ToBase64String(mapping.Salt),
                tag = Convert.ToBase64String(mapping.Tag)
            };
            
            return Ok(response);
        }

        [Authorize]
        [HttpGet("validate")]
        public IActionResult Validate()
        {
            return Ok();
        }

        [Authorize]
        [HttpGet("user-security-profile")]
        public async Task<IActionResult> GetUserSecurityProfile()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { error = "User not authenticated" });
            }

            var emailFilter = Builders<SharedAccountMapping>.Filter.Eq(m => m.Email, email);
            var mapping = await _mapping.Find(emailFilter).FirstOrDefaultAsync();
            if (mapping == null)
            {
                return NotFound(new { error = "User security profile not found" });
            }

            var response = new {
                encryptedMasterKey = Convert.ToBase64String(mapping.EncryptedMasterKey),
                masterKeyIv = Convert.ToBase64String(mapping.IV),
                salt = Convert.ToBase64String(mapping.Salt),
                tag = Convert.ToBase64String(mapping.Tag)
            };

            return Ok(response);
        }

        private string GenerateJwtToken(string email)
        {
            var privateKey = _configuration["Jwt:PrivateKey"]?.Replace("\\n", "\n").Trim();

            if (string.IsNullOrEmpty(privateKey))
            {
                throw new InvalidOperationException("JWT private key must be provided.");
            }

            RSA rsaPrivate = RSA.Create();
            rsaPrivate.ImportFromPem(privateKey);

            var signingCredentials = new SigningCredentials(
                key: new RsaSecurityKey(rsaPrivate),
                algorithm: SecurityAlgorithms.RsaSha256
            );

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT issuer must be configured")),
                new Claim(ClaimTypes.Email, email)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: signingCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // Update LoginRequest model to include security parameters
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
