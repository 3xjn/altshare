using System.ComponentModel.DataAnnotations;
using MongoDB.Bson;

namespace AltShare.Models
{
    public class RegisterRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(3)]
        [MaxLength(15)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [Compare("Password")]
        public string PasswordConfirmation { get; set; } = string.Empty;

        public string MasterKeyEncrypted { get; set; }
    }

    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
    }

    public class UploadAccountRequest
    {
        public string Password { get; set; }
        public DecryptedSharedAccount Account { get; set; }
    }

    public class AddAccountRequest
    {
        public string encryptedData { get; set; } = "";
        public string userKey { get; set; } = "";
    }
}
