namespace AltShare.Models
{
    public class Argon2Options
    {
        public int MemorySize { get; set; }
        public int Iterations { get; set; }
        public int Parallelism { get; set; }
        public int HashLength { get; set; } = 32;
    }

}
