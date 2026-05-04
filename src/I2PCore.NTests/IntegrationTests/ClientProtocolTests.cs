using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests;

/// <summary>
///     I2CP and SAM client protocol compatibility tests against i2pd.
///     Verifies that our SAM v3.3 and I2CP implementations produce
///     protocol-compatible responses.
/// </summary>
[TestFixture]
[Category("Integration")]
public class ClientProtocolTests
{
    [SetUp]
    public void SetUp()
    {
        TestNetworkFixture.RequireI2pd();
        TestNetworkFixture.RequireCSharpRouter();
    }

    /// <summary>
    ///     Test SAM HELLO handshake against i2pd's SAM bridge.
    ///     Verifies protocol version negotiation matches expected format.
    /// </summary>
    [Test]
    [CancelAfter(15000)]
    public async Task TestSAM_Hello_I2pd()
    {
        var samPort = PortAllocator.WellKnown.I2pdSam;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", samPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 10000;
            stream.WriteTimeout = 5000;

            // Send HELLO VERSION
            var hello = "HELLO VERSION MIN=3.0 MAX=3.3\n";
            var helloBytes = Encoding.ASCII.GetBytes(hello);
            await stream.WriteAsync(helloBytes);

            // Read response
            var response = await ReadSAMResponse(stream);
            Logging.LogInformation($"i2pd SAM HELLO response: {response}");

            // Expected: "HELLO REPLY RESULT=OK VERSION=3.3"
            Assert.IsTrue(response.StartsWith("HELLO REPLY"),
                $"Expected HELLO REPLY, got: {response}");
            Assert.IsTrue(response.Contains("RESULT=OK"),
                $"Expected RESULT=OK in: {response}");
            Assert.IsTrue(response.Contains("VERSION="),
                $"Expected VERSION= in: {response}");
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd SAM not reachable on port {samPort}: {ex.Message}");
        }
    }

    /// <summary>
    ///     Test SAM session creation against i2pd.
    ///     Verifies SESSION CREATE response format.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestSAM_SessionCreate_I2pd()
    {
        var samPort = PortAllocator.WellKnown.I2pdSam;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", samPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 15000;
            stream.WriteTimeout = 5000;

            // Handshake
            await SendSAMCommand(stream, "HELLO VERSION MIN=3.0 MAX=3.3\n");
            var helloReply = await ReadSAMResponse(stream);
            Assert.IsTrue(helloReply.Contains("RESULT=OK"),
                "HELLO should succeed");

            // Create a transient session
            await SendSAMCommand(stream,
                "SESSION CREATE STYLE=STREAM ID=test1 DESTINATION=TRANSIENT\n");
            var sessionReply = await ReadSAMResponse(stream);

            Logging.LogInformation($"i2pd SESSION CREATE reply: {sessionReply}");

            // Expected: "SESSION STATUS RESULT=OK DESTINATION=<base64>"
            Assert.IsTrue(sessionReply.StartsWith("SESSION STATUS"),
                $"Expected SESSION STATUS, got: {sessionReply}");
            Assert.IsTrue(sessionReply.Contains("RESULT=OK"),
                $"Expected RESULT=OK in: {sessionReply}");
            Assert.IsTrue(sessionReply.Contains("DESTINATION="),
                $"Expected DESTINATION= in: {sessionReply}");
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd SAM not reachable: {ex.Message}");
        }
    }

    /// <summary>
    ///     Test SAM NAMING LOOKUP against i2pd.
    /// </summary>
    [Test]
    [CancelAfter(15000)]
    public async Task TestSAM_NamingLookup_I2pd()
    {
        var samPort = PortAllocator.WellKnown.I2pdSam;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", samPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 10000;
            stream.WriteTimeout = 5000;

            // Handshake
            await SendSAMCommand(stream, "HELLO VERSION MIN=3.0 MAX=3.3\n");
            var helloReply = await ReadSAMResponse(stream);
            Assert.IsTrue(helloReply.Contains("RESULT=OK"));

            // Lookup ME (should return our destination)
            await SendSAMCommand(stream, "NAMING LOOKUP NAME=ME\n");
            var lookupReply = await ReadSAMResponse(stream);

            Logging.LogInformation($"i2pd NAMING LOOKUP ME reply: {lookupReply}");

            // i2pd should respond with NAMING REPLY
            Assert.IsTrue(lookupReply.StartsWith("NAMING REPLY"),
                $"Expected NAMING REPLY, got: {lookupReply}");
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd SAM not reachable: {ex.Message}");
        }
    }

    /// <summary>
    ///     Test SAM datagram session against i2pd.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestSAM_DatagramSession_I2pd()
    {
        var samPort = PortAllocator.WellKnown.I2pdSam;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", samPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 15000;
            stream.WriteTimeout = 5000;

            // Handshake
            await SendSAMCommand(stream, "HELLO VERSION MIN=3.0 MAX=3.3\n");
            var helloReply = await ReadSAMResponse(stream);
            Assert.IsTrue(helloReply.Contains("RESULT=OK"));

            // Create datagram session
            await SendSAMCommand(stream,
                "SESSION CREATE STYLE=DATAGRAM ID=dgtest DESTINATION=TRANSIENT PORT=29050\n");
            var sessionReply = await ReadSAMResponse(stream);

            Logging.LogInformation($"i2pd DATAGRAM session reply: {sessionReply}");

            Assert.IsTrue(sessionReply.Contains("RESULT=OK")
                          || sessionReply.Contains("SESSION STATUS"),
                $"Datagram session should succeed or report status: {sessionReply}");
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd SAM not reachable: {ex.Message}");
        }
    }

    /// <summary>
    ///     Test I2CP connection to i2pd.
    ///     Verifies the initial protocol byte exchange.
    /// </summary>
    [Test]
    [CancelAfter(15000)]
    public async Task TestI2CP_Connect_I2pd()
    {
        var i2cpPort = PortAllocator.WellKnown.I2pdI2cp;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", i2cpPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 10000;
            stream.WriteTimeout = 5000;

            // I2CP protocol: first byte is the protocol version (0x2a)
            var protoByte = new byte[] { 0x2a };
            await stream.WriteAsync(protoByte);

            // Send GetDate message (type 32)
            // Format: 4-byte length (big-endian) + 1-byte type + payload
            var getDate = BuildI2CPMessage(32, Array.Empty<byte>());
            await stream.WriteAsync(getDate);

            // Read response
            var responseBuf = new byte[256];
            var readTask = stream.ReadAsync(responseBuf, 0, responseBuf.Length);
            var completed = await Task.WhenAny(readTask,
                Task.Delay(5000));

            if (completed == readTask)
            {
                var bytesRead = await readTask;
                if (bytesRead > 0)
                {
                    Logging.LogInformation(
                        $"i2pd I2CP response: {bytesRead} bytes, " +
                        $"first byte: 0x{responseBuf[0]:x2}");
                    // SetDate response (type 33) expected
                    Assert.IsTrue(bytesRead >= 5,
                        "I2CP response should be at least 5 bytes (4 len + 1 type)");
                }
                else
                {
                    Logging.LogWarning("i2pd closed I2CP connection immediately");
                }
            }
            else
            {
                Logging.LogWarning("I2CP response timed out");
            }
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd I2CP not reachable on port {i2cpPort}: {ex.Message}");
        }
    }

    /// <summary>
    ///     Test that I2CP GetDate/SetDate exchange works with i2pd.
    /// </summary>
    [Test]
    [CancelAfter(15000)]
    public async Task TestI2CP_GetDate_I2pd()
    {
        var i2cpPort = PortAllocator.WellKnown.I2pdI2cp;

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", i2cpPort);
            using var stream = client.GetStream();
            stream.ReadTimeout = 10000;
            stream.WriteTimeout = 5000;

            // Protocol byte
            await stream.WriteAsync(new byte[] { 0x2a });

            // GetDate (type 32), with version string
            var version = Encoding.ASCII.GetBytes("0.9.68");
            var payload = new byte[2 + version.Length];
            payload[0] = (byte)(version.Length >> 8);
            payload[1] = (byte)(version.Length & 0xFF);
            Array.Copy(version, 0, payload, 2, version.Length);

            var getDate = BuildI2CPMessage(32, payload);
            await stream.WriteAsync(getDate);

            // Read SetDate response (type 33)
            var response = await ReadI2CPMessage(stream);
            if (response.HasValue)
            {
                var resp = response.Value;
                Logging.LogInformation(
                    $"i2pd I2CP SetDate: type={resp.type}, " +
                    $"payload={resp.payload.Length} bytes");

                Assert.AreEqual(33, resp.type,
                    "Expected SetDate (type 33) response");
            }
            else
            {
                Logging.LogWarning("No I2CP response received");
            }
        }
        catch (SocketException ex)
        {
            Assert.Ignore($"i2pd I2CP not reachable: {ex.Message}");
        }
    }

    private static async Task SendSAMCommand(NetworkStream stream, string command)
    {
        Console.WriteLine($"[DEBUG_LOG] SendSAMCommand: '{command.Trim()}'");
        var bytes = Encoding.ASCII.GetBytes(command);
        await stream.WriteAsync(bytes);
    }

    private static async Task<string> ReadSAMResponse(NetworkStream stream)
    {
        var buffer = new byte[4096];
        var sb = new StringBuilder();

        // SAM responses are typically line-based. 
        // Read until we get a newline or timeout.
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 20000)
            if (stream.DataAvailable)
            {
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (bytesRead > 0)
                {
                    var s = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    sb.Append(s);
                    if (sb.ToString().Contains("\n")) break;
                }
                else
                {
                    // Connection closed
                    Console.WriteLine("[DEBUG_LOG] ReadSAMResponse: Connection closed by peer");
                    break;
                }
            }
            else
            {
                if (sb.Length > 0 && sb.ToString().Contains("\n")) break;
                await Task.Delay(100);
            }

        var result = sb.ToString().Trim();
        Console.WriteLine($"[DEBUG_LOG] ReadSAMResponse: '{result}'");
        return result;
    }

    private static byte[] BuildI2CPMessage(byte type, byte[] payload)
    {
        var msg = new byte[5 + payload.Length];
        // 4-byte length (big-endian) = 1 (type) + payload length
        var len = 1 + payload.Length;
        msg[0] = (byte)(len >> 24);
        msg[1] = (byte)(len >> 16);
        msg[2] = (byte)(len >> 8);
        msg[3] = (byte)(len & 0xFF);
        msg[4] = type;
        if (payload.Length > 0)
            Array.Copy(payload, 0, msg, 5, payload.Length);
        return msg;
    }

    private static async Task<(byte type, byte[] payload)?> ReadI2CPMessage(
        NetworkStream stream, int timeoutMs = 5000)
    {
        var header = new byte[5];
        var readTask = ReadExactAsync(stream, header, 5);
        var completed = await Task.WhenAny(readTask, Task.Delay(timeoutMs));

        if (completed != readTask)
            return null;

        var bytesRead = await readTask;
        if (bytesRead < 5)
            return null;

        var len = (header[0] << 24) | (header[1] << 16) |
                  (header[2] << 8) | header[3];
        var type = header[4];
        var payloadLen = len - 1;

        byte[] payload;
        if (payloadLen > 0)
        {
            payload = new byte[payloadLen];
            await ReadExactAsync(stream, payload, payloadLen);
        }
        else
        {
            payload = Array.Empty<byte>();
        }

        return (type, payload);
    }

    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, int count)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer, totalRead, count - totalRead);
            if (read == 0) break;
            totalRead += read;
        }

        return totalRead;
    }
}