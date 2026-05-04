using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace I2PCore.TransportLayer.NTCP2;

/// <summary>
///     Probing resistance for NTCP2 AEAD failures
///     NTCP2 spec lines 223-243, 530-544
///     On AEAD failure:
///     1. Set random timeout
///     2. Read random bytes from connection
///     3. Close connection (abnormal close with RST for handshake)
///     4. Update blacklist for repeated failures
/// </summary>
public static class NTCP2ProbingResistance
{
    private const int MIN_DELAY_MS = 500;
    private const int MAX_DELAY_MS = 5000;
    private const int MIN_BYTES_TO_READ = 0;
    private const int MAX_BYTES_TO_READ = 4096;
    private static readonly Random random = new();

    /// <summary>
    ///     Handle AEAD failure with probing resistance
    /// </summary>
    /// <param name="stream">Network stream to read from</param>
    /// <param name="ipAddress">Remote IP address for blacklisting</param>
    /// <param name="isHandshake">True if failure is during handshake</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public static async Task HandleAEADFailureAsync(
        Stream stream,
        string ipAddress,
        bool isHandshake,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Record failure for blacklisting
            if (!string.IsNullOrEmpty(ipAddress)) NTCP2SecurityValidator.RecordFailure(ipAddress);

            // Generate random delay
            var delayMs = random.Next(MIN_DELAY_MS, MAX_DELAY_MS);

            // Wait random time
            await Task.Delay(delayMs, cancellationToken);

            // Read random number of bytes and discard
            if (stream != null && stream.CanRead)
            {
                var bytesToRead = random.Next(MIN_BYTES_TO_READ, MAX_BYTES_TO_READ);
                var buffer = new byte[Math.Min(bytesToRead, 8192)];

                try
                {
                    var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                    var timeoutTask = Task.Delay(2000, cancellationToken);

                    // Wait for either read or timeout
                    await Task.WhenAny(readTask, timeoutTask);
                }
                catch
                {
                    // Ignore read errors
                }
            }

            // For data phase: could send termination block here
            // For now, just close
        }
        catch
        {
            // Ignore any errors during probing resistance
        }
    }

    /// <summary>
    ///     Handle AEAD failure synchronously
    /// </summary>
    public static void HandleAEADFailure(
        Stream stream,
        string ipAddress,
        bool isHandshake)
    {
        try
        {
            // Record failure
            if (!string.IsNullOrEmpty(ipAddress)) NTCP2SecurityValidator.RecordFailure(ipAddress);

            // Generate random delay
            var delayMs = random.Next(MIN_DELAY_MS, MAX_DELAY_MS);

            // Wait
            Thread.Sleep(delayMs);

            // Read and discard random bytes
            if (stream != null && stream.CanRead)
            {
                var bytesToRead = random.Next(MIN_BYTES_TO_READ, MAX_BYTES_TO_READ);
                var buffer = new byte[Math.Min(bytesToRead, 8192)];

                try
                {
                    stream.ReadExactly(buffer, 0, buffer.Length);
                }
                catch
                {
                    // Ignore read errors
                }
            }
        }
        catch
        {
            // Ignore any errors
        }
    }

    /// <summary>
    ///     Check MSB of obfuscated ephemeral key for fast rejection
    ///     NTCP2 spec lines 1184-1186: Bob should check bit 7 of the first byte
    ///     of Alice's obfuscated ephemeral key X.
    ///     If it is 1, Bob should terminate the session.
    /// </summary>
    /// <param name="obfuscatedKey">32-byte obfuscated ephemeral key</param>
    /// <returns>True if MSB is valid (bit 7 of byte 0 is 0)</returns>
    public static bool CheckMSB(byte[] obfuscatedKey)
    {
        if (obfuscatedKey == null || obfuscatedKey.Length < 32)
            return false;

        // NTCP2 spec: "Bob should check bit 7 of the first byte"
        return (obfuscatedKey[0] & 0x80) == 0;
    }

    /// <summary>
    ///     Generate random delay value for testing
    /// </summary>
    public static int GetRandomDelay()
    {
        return random.Next(MIN_DELAY_MS, MAX_DELAY_MS);
    }

    /// <summary>
    ///     Generate random byte count for testing
    /// </summary>
    public static int GetRandomByteCount()
    {
        return random.Next(MIN_BYTES_TO_READ, MAX_BYTES_TO_READ);
    }
}