using AltShare.Models;

public class AddAccountRequest
{
    public string encryptedData { get; set; }
    public string userKey { get; set; }
    //public List<DecryptedSharedAccount> sharedAccounts { get; set; }
} 