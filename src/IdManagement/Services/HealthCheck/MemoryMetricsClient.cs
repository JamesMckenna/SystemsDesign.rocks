using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace IdManagement.Services.HealthCheck
{
    //https: //dzone.com/articles/system-memory-health-check-for-aspnet-core
    public class MemoryMetricsClient
    {
        public MemoryMetrics GetMetrics()
        {
            MemoryMetrics metrics;

            Stopwatch watch = new Stopwatch();
            watch.Start();

            if (IsUnix())
            {
                metrics = GetUnixMetrics();
            }
            else
            {
                metrics = GetWindowsMetrics();
            }

            watch.Stop();
            metrics.CheckDurationInMilliseconds = watch.ElapsedMilliseconds;

            return metrics;
        }
        private bool IsUnix()
        {
            bool isUnix = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
              RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
            return isUnix;
        }
        private MemoryMetrics GetWindowsMetrics()
        {
            string output = "";

            ProcessStartInfo info = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = "OS get FreePhysicalMemory,TotalVisibleMemorySize /Value",
                RedirectStandardOutput = true
            };

            using (Process process = Process.Start(info))
            {
                output = process.StandardOutput.ReadToEnd();
            }

            string[] lines = output.Trim().Split("\n");

            string[] freeMemoryParts = lines[0].Split("=", StringSplitOptions.RemoveEmptyEntries);
            string[] totalMemoryParts = lines[1].Split("=", StringSplitOptions.RemoveEmptyEntries);

            MemoryMetrics metrics = new MemoryMetrics
            {
                Total = Math.Round(double.Parse(totalMemoryParts[1]) / 1024, 0),
                Free = Math.Round(double.Parse(freeMemoryParts[1]) / 1024, 0),

            };

            metrics.Used = metrics.Total - metrics.Free;

            return metrics;
        }
        private MemoryMetrics GetUnixMetrics()
        {
            string output = "";
            ProcessStartInfo info = new ProcessStartInfo("free -m")
            {
                FileName = "/bin/bash",
                Arguments = "-c \"free -m\"",
                RedirectStandardOutput = true
            };

            using (Process process = Process.Start(info))
            {
                output = process.StandardOutput.ReadToEnd();
                Console.WriteLine(output);
            }

            string[] lines = output.Split("\n");
            string[] memory = lines[1].Split(" ", StringSplitOptions.RemoveEmptyEntries);
            MemoryMetrics metrics = new MemoryMetrics
            {
                Total = double.Parse(memory[1]),
                Used = double.Parse(memory[2]),
                Free = double.Parse(memory[3]),
                CheckDurationInMilliseconds = long.Parse(memory[4])
            };

            return metrics;
        }
    }
}
