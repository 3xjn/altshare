using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("auth")]
    [Tags("auth")]
    public class AuthController : Controller
    {
        private readonly UserAccountService _accountService;
        private readonly PasswordHasherService _passwordHasherService;
        private readonly IConfiguration _configuration;

        public AuthController(UserAccountService accountService, PasswordHasherService passwordHasherService, IConfiguration configuration)
        {
            _accountService = accountService;
            _passwordHasherService = passwordHasherService;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterRequest request)
        {
            if (request.password != request.passwordConfirmation)
            {
                return StatusCode(400, new
                {
                    error = "Passwords do not match"
                });
            }

            var userNameTaken = await _accountService.UsernameExists(request.username);
            if (userNameTaken)
            {
                return Conflict(new
                {
                    error = "An account with this username already exists."
                });
            }

            var isEmailTaken = await _accountService.EmailExists(request.email);
            if (isEmailTaken)
            {
                return Conflict(new
                {
                    error = "An account with this email already exists."
                });
            }

            var passwordHash = _passwordHasherService.HashPassword(request.password);

            Console.WriteLine("Creating an account!");
            _accountService.Create(new UserAccount
            {
                Username = request.username,
                Email = request.email,
                HashedPassword = passwordHash,
            });

            var token = GenerateJwtToken(request.email);
            return Ok(token);
        }

        [HttpPost("login")]
        async public Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var emailExists = await _accountService.EmailExists(request.email);

            if (!emailExists)
            {
                Console.WriteLine("email not found");
                return Unauthorized(new { message = "Invalid email or password." });
            }

            var account = await _accountService.GetAccountByEmail(request.email);
            var isValid = _passwordHasherService.VerifyPassword(account.HashedPassword, request.password);

            if (!isValid)
            {
                Console.WriteLine("password incorrect");
                return Unauthorized(new { message = "Invalid email or password." });
            } else
            {
                return Ok(GenerateJwtToken(request.email));
            }
        }

        [Authorize]
        [HttpGet("validate")]
        public IActionResult Validate()
        {
            return Ok();
        }

        private string GenerateJwtToken(string email)
        {
            var privateKey = _configuration["Jwt:PrivateKey"].Replace("\r\n", "");

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
                //new Claim(ClaimTypes.NameIdentifier, googleId),
                //new Claim(ClaimTypes.Email, email),
                //new Claim(ClaimTypes.Name, givenName),
                //new Claim("picture_url", pfp)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: signingCredentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
