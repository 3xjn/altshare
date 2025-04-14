namespace AltShare.Utils
{
    public static class IsKubernetesEnvironment
    {
        public static bool IsRunningKubernetes { get; set; } = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST"));
    }
}