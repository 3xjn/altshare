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

        [BsonElement("SharedAccountId")]
        public ObjectId SharedAccountId { get; set; }

        [BsonElement("UserKey")]
        public string UserKey { get; set; } = string.Empty;

        [BsonElement("Salt")]
        public byte[] Salt { get; set; } = Array.Empty<byte>();

        [BsonElement("IV")]
        public byte[] IV { get; set; } = Array.Empty<byte>();

        [BsonElement("Tag")]
        public byte[] Tag { get; set; } = Array.Empty<byte>();

        [BsonElement("EncryptedMasterKey")]
        public byte[] EncryptedMasterKey { get; set; } = Array.Empty<byte>();
    }
}