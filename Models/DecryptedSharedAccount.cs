using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace AltShare.Models
{
    public class DecryptedSharedAccount
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Notes { get; set; }
    }

    public class EncryptedSharedAccount
    {
        [BsonId]
        public ObjectId Id { get; set; }

        public string OwnerEmail { get; set; }
        public string EncryptedJson { get; set; }
    }
}
