using MongoDB.Bson.Serialization.Attributes;

namespace AltShare.Models
{
    public class InviteCodeMapping
    {
        public string InviteCode { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;

        [BsonDateTimeOptions(Kind = DateTimeKind.Utc)]
        public DateTime ExpireAt { get; set; }
    }
}
