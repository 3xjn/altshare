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
using System.IO;
using System.Net;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("api/auth")]
    [Tags("auth")]
    public class AuthController : Controller
    {
        private const string AuthCookieName = "altshare_auth";
        private readonly UserAccountService _accountService;
        private readonly SharedAccountService _sharedAccountService;
        private readonly PasswordHasherService _passwordHasherService;
        private readonly IConfiguration _configuration;
        private readonly IMongoCollection<EncryptedSharedAccount> _shared;
        private readonly IMongoCollection<SharedAccountMapping> _mapping;
        private readonly HttpClient _httpClient;
        private readonly SigningCredentials _signingCredentials;

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

            var privateKeyPath =
                IsRunningInKubernetes()
                    ? "/run/secrets/altshare/jwt_private_key.pem"
                    : "private_key.pem";

            if (!System.IO.File.Exists(privateKeyPath))
            {
                throw new InvalidOperationException("JWT private key file not found.");
            }

            var privateKeyPem = System.IO.File.ReadAllText(privateKeyPath).Trim();

            RSA rsaPrivate = RSA.Create();
            // Import the key in PEM format
            rsaPrivate.ImportFromPem(privateKeyPem.ToCharArray());

            _signingCredentials = new SigningCredentials(
                key: new RsaSecurityKey(rsaPrivate),
                algorithm: SecurityAlgorithms.RsaSha256
            );
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterRequest request)
        {
            Console.WriteLine($"Registration attempt for email: {request.Email}");

            if (request.Password != request.PasswordConfirmation)
            {
                return StatusCode(400, new { error = "Passwords do not match" });
            }

            if (string.IsNullOrWhiteSpace(request.MasterKeyEncrypted))
            {
                return BadRequest(new { error = "Encrypted master key is required." });
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

                var passwordHash = _passwordHasherService.HashPassword(request.Password);
                var token = GenerateJwtToken(request.Email);

                _accountService.Create(new UserAccount
                {
                    Username = request.Username,
                    Email = request.Email,
                    HashedPassword = passwordHash,
                });

                Console.WriteLine("Creating account mapping...");
                byte[] encryptedMasterKey;
                try
                {
                    encryptedMasterKey = Convert.FromBase64String(request.MasterKeyEncrypted);
                }
                catch (FormatException)
                {
                    return BadRequest(new { error = "Encrypted master key is invalid." });
                }

                var accountMapping = new SharedAccountMapping
                {
                    Email = request.Email,
                    EncryptedMasterKey = encryptedMasterKey,
                };

                await _mapping.InsertOneAsync(accountMapping);
                Console.WriteLine("Account mapping created successfully");

                var response = new {
                    masterKeyEncrypted = Convert.ToBase64String(accountMapping.EncryptedMasterKey),
                };
                SetAuthCookie(token);
                Console.WriteLine($"Registration complete for email: {request.Email}");
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
            if (mapping is not { EncryptedMasterKey: not null } || mapping.EncryptedMasterKey.Length == 0)
            {
                Console.WriteLine("No valid master key found - user must register");
                return Unauthorized(new {
                    message = "Account not properly configured. Please contact support."
                });
            }

            // Return existing mapping
            var response = new {
                masterKeyEncrypted = Convert.ToBase64String(mapping.EncryptedMasterKey),
            };

            SetAuthCookie(token);
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
                encryptedMasterKey = Convert.ToBase64String(mapping.EncryptedMasterKey)
            };

            return Ok(response);
        }

        [Authorize]
        [HttpGet("me")]
        public IActionResult GetCurrentUser()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { error = "User not authenticated" });
            }

            return Ok(new { email });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            ClearAuthCookie();
            return Ok();
        }

        [Authorize]
        [HttpPut("user-security-profile")]
        public async Task<IActionResult> UpdateUserSecurityProfile([FromBody] UpdateUserSecurityProfileRequest request)
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { error = "User not authenticated" });
            }

            if (string.IsNullOrWhiteSpace(request.EncryptedMasterKey))
            {
                return BadRequest(new { error = "Encrypted master key is required." });
            }

            byte[] encryptedMasterKey;
            try
            {
                encryptedMasterKey = Convert.FromBase64String(request.EncryptedMasterKey);
            }
            catch (FormatException)
            {
                return BadRequest(new { error = "Encrypted master key is invalid." });
            }

            var emailFilter = Builders<SharedAccountMapping>.Filter.Eq(m => m.Email, email);
            var update = Builders<SharedAccountMapping>.Update
                .Set(m => m.EncryptedMasterKey, encryptedMasterKey);

            var result = await _mapping.UpdateOneAsync(emailFilter, update);
            if (result.MatchedCount == 0)
            {
                return NotFound(new { error = "User security profile not found" });
            }

            return Ok();
        }

        private string GenerateJwtToken(string email)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT issuer must be configured")),
                new Claim(ClaimTypes.Email, email)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: _signingCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        bool IsRunningInKubernetes()
        {
            return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST"));
        }

        private void SetAuthCookie(string token)
        {
            Response.Cookies.Append(
                AuthCookieName,
                token,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTimeOffset.UtcNow.AddHours(1),
                    Path = "/"
                }
            );
        }

        private void ClearAuthCookie()
        {
            Response.Cookies.Delete(
                AuthCookieName,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Lax,
                    Path = "/"
                }
            );
        }
    }

}
