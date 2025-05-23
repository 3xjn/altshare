using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AltShare.Models
{
    public class SharedAccountMapping
    {
        [BsonId]
        public ObjectId Id { get; set; }

        [BsonElement("Email")]
        public string Email { get; set; } = string.Empty;

        [BsonElement("EncryptedMasterKey")]
        public byte[]? EncryptedMasterKey { get; set; } = Array.Empty<byte>();
    }
}