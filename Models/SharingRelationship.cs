using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AltShare.Models
{
    public class SharingRelationship
    {
        [BsonId]
        public ObjectId Id { get; set; }
        
        [BsonElement("ownerEmail")]
        public string OwnerEmail { get; set; } = null!;
        
        [BsonElement("sharedWithEmail")]
        public string SharedWithEmail { get; set; } = null!;
        
        [BsonElement("encryptedMasterKey")]
        public byte[] EncryptedMasterKey { get; set; } = null!;
        
        [BsonElement("iv")]
        public byte[] IV { get; set; } = null!;
        
        [BsonElement("salt")]
        public byte[] Salt { get; set; } = null!;
        
        [BsonElement("tag")]
        public byte[] Tag { get; set; } = null!;
        
        [BsonElement("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
} 