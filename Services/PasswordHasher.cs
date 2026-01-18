using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using Microsoft.Extensions.Options;

namespace AltShare.Services
{
    public class PasswordHasherService
    {
        private readonly Argon2Settings _settings;

        public PasswordHasherService(IOptions<Argon2Settings> settings)
        {
            _settings = settings.Value;
        }

        public string HashPassword(string password)
        {
            var config = new Argon2Config
            {
                Type = Argon2Type.HybridAddressing,
                Version = Argon2Version.Nineteen,
                TimeCost = _settings.TimeCost,
                MemoryCost = _settings.MemoryCost,
                Lanes = _settings.Parallelism,
                HashLength = 32,
                Password = System.Text.Encoding.UTF8.GetBytes(password),
                Salt = new byte[16]
            };
            RandomNumberGenerator.Fill(config.Salt);

            using var argon2 = new Argon2(config);
            {
                using (var hashBytes = argon2.Hash())
                {
                    return config.EncodeString(hashBytes.Buffer);
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
