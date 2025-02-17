using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;

namespace AltShare.Services
{
    public class PasswordHasherService
    {
        private readonly Argon2Config _config;

        public PasswordHasherService(IOptions<Argon2Settings> settings)
        {
            _config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                TimeCost = settings.Value.TimeCost,
                MemoryCost = settings.Value.MemoryCost,
                Lanes = settings.Value.Parallelism,
                HashLength = 32
            };
        }

        public string HashPassword(string password)
        {
            _config.Password = System.Text.Encoding.UTF8.GetBytes(password);
            _config.Salt = new byte[16];
            RandomNumberGenerator.Fill(_config.Salt);

            using var argon2 = new Argon2(_config);
            {
                using (var hashBytes = argon2.Hash())
                {
                    return _config.EncodeString(hashBytes.Buffer);
                }
            }
        }

        public bool VerifyPassword(string hash, string password)
        {
            return Argon2.Verify(hash, password);
        }
    }

    public class Argon2Settings
    {
        public int TimeCost { get; set; } = 4;
        public int MemoryCost { get; set; } = 65536; // 64MB
        public int Parallelism { get; set; } = 4;
    }
}