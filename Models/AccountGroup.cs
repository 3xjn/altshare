using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AltShare.Models
{
    public class AccountGroup
    {
        [BsonId]
        public ObjectId Id { get; set; }

        [BsonElement("ownerEmail")]
        public string OwnerEmail { get; set; } = null!;

        [BsonElement("name")]
        public string Name { get; set; } = "Personal";

        [BsonElement("encryptedGroupKey")]
        public string? EncryptedGroupKey { get; set; }

        [BsonElement("usesMasterKey")]
        public bool UsesMasterKey { get; set; }

        [BsonElement("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
