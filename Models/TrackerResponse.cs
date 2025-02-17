using System.Text.Json.Serialization;

namespace AltShare.Models
{
    public class TrackerResponse
    {
        [JsonPropertyName("data")]
        public TrackerData Data { get; set; }
    }

    public class TrackerData
    {
        [JsonPropertyName("segments")]
        public List<TrackerSegment> Segments { get; set; }
    }

    public class TrackerSegment
    {
        [JsonPropertyName("stats")]
        public TrackerStats Stats { get; set; }
    }

    public class TrackerStats
    {
        [JsonPropertyName("ranked")]
        public TrackerRanked Ranked { get; set; }
    }

    public class TrackerRanked
    {
        [JsonPropertyName("metadata")]
        public TrackerMetadata Metadata { get; set; }
    }

    public class TrackerMetadata
    {
        [JsonPropertyName("tierName")]
        public string TierName { get; set; }
    }
} 