namespace AltShare.Models
{
    public class Argon2Settings
    {
        public int TimeCost { get; set; } = 2;
        public int MemoryCost { get; set; } = 32768; // 32MB
        public int Parallelism { get; set; } = 1;
    }
} 