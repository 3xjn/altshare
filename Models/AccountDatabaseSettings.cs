namespace AltShare.Models
{
    public class AccountDatabaseSettings
    {
        public string ConnectionString { get; set; } = string.Empty;
        public string DatabaseName { get; set; } = string.Empty;
        public string UserCollectionName { get; set; } = string.Empty;
        public string AccountCollectionName { get; set; } = string.Empty;
    }
}
