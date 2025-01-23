using System.Security.Cryptography;
using System.Text;
using AltShare.Models;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;

namespace AltShare.Services
{
    public class PasswordHasherService
    {
        private readonly Argon2Options _options;

        public PasswordHasherService(IOptions<Argon2Options> options)
        {
            _options = options.Value;
            Console.WriteLine($"Argon2 Options: MemorySize={_options.MemorySize}, Iterations={_options.Iterations}, Parallelism={_options.Parallelism}, HashLength={_options.HashLength}");
        }

        public string HashPassword(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(16);

            var config = new Argon2Config
            {
                Type = Argon2Type.DataDependentAddressing,
                Version = Argon2Version.Nineteen,
                MemoryCost = _options.MemorySize,
                TimeCost = _options.Iterations,
                Lanes = _options.Parallelism,
                Threads = _options.Parallelism,
                HashLength = _options.HashLength,
                Salt = salt,
                Password = Encoding.UTF8.GetBytes(password)
            };

            using (var argon2 = new Argon2(config))
            {
                using (var hashBytes = argon2.Hash())
                {
                    return config.EncodeString(hashBytes.Buffer);
                }
            }
        }

        public bool VerifyPassword(string hashedPassword, string inputPassword)
        {
            return Argon2.Verify(hashedPassword, inputPassword);
        }
    }
}