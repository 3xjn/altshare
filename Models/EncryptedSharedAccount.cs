using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

[BsonIgnoreExtraElements]
public class EncryptedSharedAccount
{
    [BsonId]
    public ObjectId Id { get; set; }
    public string OwnerEmail { get; set; }
    public string EncryptedJson { get; set; }
} 