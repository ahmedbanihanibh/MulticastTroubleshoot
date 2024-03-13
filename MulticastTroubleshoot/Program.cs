using System;
using System.Collections.Generic;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Threading;

namespace MulticastDetect
{
    class Program
    {
        static void Main(string[] args)
        {
            // Keep track of source IPs for each multicast IP
            var sourceIpsByMulticastIp = new Dictionary<string, Dictionary<string, DateTime>>();

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found, print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No capture devices were found. Make sure WinPcap is installed.");
                return;
            }

            // Display available devices and let the user choose
            var selectedDevice = ChooseNetworkInterface(devices);
            if (selectedDevice == null)
            {
                Console.WriteLine("Invalid selection or no network interfaces available.");
                return;
            }

            // Open the selected device for capturing
            try
            {
                selectedDevice.Open(DeviceMode.Promiscuous);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error opening device: {ex.Message}");
                return;
            }

            // Get user input for multicast address and port
            Console.Write("Enter multicast address (e.g., 224.0.0.1): ");
            string multicastAddress = Console.ReadLine();

            Console.Write("Enter multicast port: ");
            int multicastPort;
            while (!int.TryParse(Console.ReadLine(), out multicastPort))
            {
                Console.WriteLine("Invalid port. Please enter a valid numeric port.");
                Console.Write("Enter multicast port: ");
            }

            // Get user input for the timeout in seconds
            Console.Write("Enter the timeout in seconds: ");
            int timeoutInSeconds;
            while (!int.TryParse(Console.ReadLine(), out timeoutInSeconds) || timeoutInSeconds <= 0)
            {
                Console.WriteLine("Invalid timeout. Please enter a valid positive integer.");
                Console.Write("Enter the timeout in seconds: ");
            }

            DateTime lastPacketTime = DateTime.Now;

            // Set a packet filter to capture only the specified multicast traffic
            try
            {
                selectedDevice.Filter = $"ip and udp and host {multicastAddress} and port {multicastPort}";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting packet filter: {ex.Message}");
                selectedDevice.Close(); // Close the device in case of an error
                return;
            }

            // Start the capture process
            selectedDevice.OnPacketArrival += (object sender, CaptureEventArgs e) =>
            {
                // Update the timestamp of the last packet
                lastPacketTime = DateTime.Now;

                // Parse the packet
                var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

                // Get the IP packet
                var ipPacket = packet.Extract<IPPacket>();

                // If the IP packet is null, ignore
                if (ipPacket == null)
                {
                    return;
                }

                var destinationAddress = ipPacket.DestinationAddress.ToString();
                var sourceAddress = ipPacket.SourceAddress.ToString();

                // Check if we've seen this multicast IP before
                if (!sourceIpsByMulticastIp.ContainsKey(destinationAddress))
                {
                    sourceIpsByMulticastIp[destinationAddress] = new Dictionary<string, DateTime>();
                }

                // Update or add the source IP with the current timestamp
                sourceIpsByMulticastIp[destinationAddress][sourceAddress] = DateTime.Now;

                // Print a message for each received packet
                Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: New source {sourceAddress} for multicast address {destinationAddress}");

                // If more than one source is transmitting on the same multicast IP, print a warning
                if (sourceIpsByMulticastIp[destinationAddress].Count > 1)
                {
                    Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: Warning: Multiple sources transmitting on multicast address {destinationAddress}");

                    // Remove inactive sources from the warning condition
                    var inactiveSources = new List<string>();
                    foreach (var sourceEntry in sourceIpsByMulticastIp[destinationAddress])
                    {
                        if ((DateTime.Now - sourceEntry.Value).TotalSeconds > timeoutInSeconds)
                        {
                            inactiveSources.Add(sourceEntry.Key);
                        }
                    }

                    // Remove inactive sources from the dictionary
                    foreach (var inactiveSource in inactiveSources)
                    {
                        sourceIpsByMulticastIp[destinationAddress].Remove(inactiveSource);
                        Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: Removed inactive source {inactiveSource} for multicast address {destinationAddress}");
                    }
                }

            };

            // Start the capture process
            selectedDevice.StartCapture();

            // Monitor for timeout and clean up sources
            while (true)
            {
                // Calculate elapsed time since the last packet
                TimeSpan elapsedPacketTime = DateTime.Now - lastPacketTime;

                // Check if timeout has occurred
                if (elapsedPacketTime.TotalSeconds > timeoutInSeconds)
                {
                    Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: Timeout reached. No packets received within the last {timeoutInSeconds} seconds.");

                    // Remove inactive sources
                    foreach (var multicastEntry in sourceIpsByMulticastIp)
                    {
                        var sourcesToRemove = new List<string>();

                        foreach (var sourceEntry in multicastEntry.Value)
                        {
                            if ((DateTime.Now - sourceEntry.Value).TotalSeconds > timeoutInSeconds)
                            {
                                sourcesToRemove.Add(sourceEntry.Key);
                            }
                        }

                        foreach (var sourceToRemove in sourcesToRemove)
                        {
                            multicastEntry.Value.Remove(sourceToRemove);
                            Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff}: Removed inactive source {sourceToRemove} for multicast address {multicastEntry.Key}");
                        }
                    }

                    // Update the timestamp of the last packet to avoid immediate reentry into the cleanup process
                    lastPacketTime = DateTime.Now;
                }

                Thread.Sleep(100); // Sleep for 100 milliseconds before checking again
            }
        }

        private static ICaptureDevice ChooseNetworkInterface(IList<ICaptureDevice> devices)
        {
            Console.WriteLine("Available Network Interfaces:");
            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i + 1}. {devices[i].Description}");
            }

            Console.Write("Select a network interface (enter the number): ");
            string userInput = Console.ReadLine();

            if (int.TryParse(userInput, out int selectedIndex) && selectedIndex > 0 && selectedIndex <= devices.Count)
            {
                return devices[selectedIndex - 1];
            }

            return null;
        }
    }
}
