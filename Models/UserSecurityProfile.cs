using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class UserSecurityProfile {
    [BsonId]
    public ObjectId UserId { get; set; }
    public string EncryptedMasterKey { get; set; }
    public byte[] IV { get; set; }
    public byte[] Salt { get; set; }
} 