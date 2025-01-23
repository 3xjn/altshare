using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AltShare.Models
{
    public class UserAccount
    {
        [BsonId]
        public ObjectId Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string HashedPassword { get; set; }
    }
}
