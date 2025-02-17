namespace AltShare.Models
{
    public class EncryptedAccountResponse
    {
        public string EncryptedData { get; set; }
        public byte[] IV { get; set; }
        public byte[] Tag { get; set; }
    }
}