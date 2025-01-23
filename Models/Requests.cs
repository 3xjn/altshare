namespace AltShare.Models
{
    public class RegisterRequest
    {
        public string email { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string passwordConfirmation { get; set; }
    }

    public class LoginRequest
    {
        public string email { get; set; }
        public string password { get; set; }
    }
}
