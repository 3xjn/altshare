using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace AltShare.Models
{
    public class SharedAccount
    {
        [BsonId]
        public ObjectId Id { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string notes { get; set; }
    }
}
