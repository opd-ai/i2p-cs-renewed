using System;
using System.Buffers;
using I2PCore.Data;
using I2PCore.TunnelLayer.ECIES;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Offline unit tests for tunnel build record serialization and deserialization.
///     All tests run without a live network or i2pd peer.
///     These exercise the message format code that would otherwise only be
///     tested by <see cref="I2PTests.IntegrationTests.TunnelBuildTests"/>.
/// </summary>
[TestFixture]
public class TunnelBuildRecordTest
{
    // ------------------------------------------------------------------ //
    // ShortBuildRequestRecord
    // ------------------------------------------------------------------ //

    [Test]
    public void TestShortBuildRequestRecord_Sizes()
    {
        Assert.AreEqual(154, ShortBuildRequestRecord.ClearTextSize,
            "ClearTextSize must be 154 bytes per i2pd SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE");
        Assert.AreEqual(218, ShortBuildRequestRecord.OnWireRecordSize,
            "OnWireRecordSize must be 218 bytes per i2pd SHORT_TUNNEL_BUILD_RECORD_SIZE");
        Assert.AreEqual(16, ShortBuildRequestRecord.EncryptedOffset,
            "EncryptedOffset must be 16 bytes per i2pd SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET");
    }

    [Test]
    public void TestShortBuildRequestRecord_RoundTrip()
    {
        // Build a minimal random ident hash for NextRouterHash
        var hashBytes = BufUtils.RandomBytes(32);
        var nextHash = new I2PIdentHash(new I2PBufferCursor(hashBytes, 0));

        var record = new ShortBuildRequestRecord(
            new I2PTunnelId((uint)0x1A2B3C4D),
            nextHash,
            new I2PTunnelId((uint)0x5E6F7080),
            (byte)ShortBuildRequestRecord.BuildRequestFlags.InboundGateway,
            requestTime: 1_000_000u,
            nextMessageId: 0xDEADBEEFu);

        // Serialize to bytes
        var bytes = record.ToByteArray();

        Assert.AreEqual(ShortBuildRequestRecord.ClearTextSize, bytes.Length,
            $"Serialized record must be exactly {ShortBuildRequestRecord.ClearTextSize} bytes");

        // Deserialize
        var cursor = new I2PBufferCursor(bytes, 0);
        var parsed = new ShortBuildRequestRecord(cursor);

        // Verify fields round-trip correctly
        Assert.AreEqual((uint)record.ReceiveTunnelId, (uint)parsed.ReceiveTunnelId,
            "ReceiveTunnelId mismatch after round-trip");
        Assert.AreEqual((uint)record.NextTunnelId, (uint)parsed.NextTunnelId,
            "NextTunnelId mismatch after round-trip");
        Assert.AreEqual(record.RequestTime, parsed.RequestTime,
            "RequestTime mismatch after round-trip");
        Assert.AreEqual(record.RequestExpiration, parsed.RequestExpiration,
            "RequestExpiration mismatch after round-trip");
        Assert.AreEqual(record.NextMessageId, parsed.NextMessageId,
            "NextMessageId mismatch after round-trip");
        Assert.AreEqual(record.Flags, parsed.Flags,
            "Flags mismatch after round-trip");
        Assert.IsTrue(BufUtils.Equal(
                record.NextRouterHash.Hash.ToByteArray(),
                parsed.NextRouterHash.Hash.ToByteArray()),
            "NextRouterHash mismatch after round-trip");
    }

    [Test]
    public void TestShortBuildRequestRecord_FlagsInboundGateway()
    {
        var record = new ShortBuildRequestRecord();
        record.Flags = (byte)ShortBuildRequestRecord.BuildRequestFlags.InboundGateway;

        Assert.IsTrue(record.IsInboundGateway(),
            "IsInboundGateway() should return true when IBGW flag is set");
        Assert.IsFalse(record.IsOutboundEndpoint(),
            "IsOutboundEndpoint() should return false when only IBGW flag is set");
    }

    [Test]
    public void TestShortBuildRequestRecord_FlagsOutboundEndpoint()
    {
        var record = new ShortBuildRequestRecord();
        record.Flags = (byte)ShortBuildRequestRecord.BuildRequestFlags.OutboundEndpoint;

        Assert.IsTrue(record.IsOutboundEndpoint(),
            "IsOutboundEndpoint() should return true when OBEP flag is set");
        Assert.IsFalse(record.IsInboundGateway(),
            "IsInboundGateway() should return false when only OBEP flag is set");
    }

    [Test]
    public void TestShortBuildRequestRecord_NoFlags()
    {
        var record = new ShortBuildRequestRecord();
        record.Flags = (byte)ShortBuildRequestRecord.BuildRequestFlags.None;

        Assert.IsFalse(record.IsInboundGateway(),
            "IsInboundGateway() should be false with no flags");
        Assert.IsFalse(record.IsOutboundEndpoint(),
            "IsOutboundEndpoint() should be false with no flags");
    }

    [Test]
    public void TestShortBuildRequestRecord_WriteProducesConsistentBytes()
    {
        // Two records with the same field values must produce identical bytes
        var hashBytes = BufUtils.RandomBytes(32);
        var nextHash = new I2PIdentHash(new I2PBufferCursor(hashBytes, 0));

        var r1 = new ShortBuildRequestRecord(
            new I2PTunnelId((uint)1234),
            nextHash,
            new I2PTunnelId((uint)5678),
            0x00,
            requestTime: 42u,
            nextMessageId: 99u);

        var r2 = new ShortBuildRequestRecord(
            new I2PTunnelId((uint)1234),
            nextHash,
            new I2PTunnelId((uint)5678),
            0x00,
            requestTime: 42u,
            nextMessageId: 99u);

        Assert.IsTrue(BufUtils.Equal(r1.ToByteArray(), r2.ToByteArray()),
            "Two records with identical fields must produce identical byte representations");
    }

    // ------------------------------------------------------------------ //
    // ShortBuildReplyRecord
    // ------------------------------------------------------------------ //

    [Test]
    public void TestShortBuildReplyRecord_ParseAccept()
    {
        // Status byte at offset 201 = 0x00 means Accept.
        var bytes = new byte[ShortBuildReplyRecord.ClearTextSize];
        bytes[ShortBuildReplyRecord.StatusByteOffset] = 0x00; // Accept

        var reply = new ShortBuildReplyRecord(bytes);

        Assert.IsNotNull(reply, "Parsed reply record should not be null");
        Assert.IsTrue(reply.IsAccepted(), "Status 0x00 should mean Accepted");
    }

    [Test]
    public void TestShortBuildReplyRecord_ParseBandwidthReject()
    {
        var bytes = new byte[ShortBuildReplyRecord.ClearTextSize];
        bytes[ShortBuildReplyRecord.StatusByteOffset] = 30; // RejectBandwidth

        var reply = new ShortBuildReplyRecord(bytes);

        Assert.IsNotNull(reply);
        Assert.IsFalse(reply.IsAccepted(), "Non-zero status should mean Rejected");
    }

    [Test]
    public void TestShortBuildReplyRecord_CorrectSize()
    {
        // Per spec ClearTextSize = 202 bytes, OnWireRecordSize = 218 (with 16-byte MAC)
        Assert.AreEqual(202, ShortBuildReplyRecord.ClearTextSize,
            "ShortBuildReplyRecord.ClearTextSize must be 202 per i2pd spec");
        Assert.AreEqual(218, ShortBuildReplyRecord.OnWireRecordSize,
            "ShortBuildReplyRecord.OnWireRecordSize must be 218 per i2pd spec");
        Assert.AreEqual(201, ShortBuildReplyRecord.StatusByteOffset,
            "Status byte must be at the last position (201) within the cleartext");
    }

    // ------------------------------------------------------------------ //
    // ShortTunnelBuildMessage
    // ------------------------------------------------------------------ //

    [Test]
    public void TestShortTunnelBuildMessage_RoundTrip()
    {
        // Create a ShortTunnelBuildMessage with 3 random records
        var recordCount = 3;
        var records = new System.Collections.Generic.List<byte[]>();
        for (var i = 0; i < recordCount; i++)
            records.Add(BufUtils.RandomBytes(ShortBuildRequestRecord.OnWireRecordSize));

        var msg = new ShortTunnelBuildMessage(records);

        Assert.AreEqual(recordCount, msg.RecordCount,
            "ShortTunnelBuildMessage should hold the correct number of records");
        Assert.AreEqual(recordCount, msg.Records.Count,
            "Records list should have the correct count");

        // Each record should be exactly OnWireRecordSize bytes
        for (var i = 0; i < recordCount; i++)
            Assert.AreEqual(
                ShortBuildRequestRecord.OnWireRecordSize,
                msg.Records[i].Length,
                $"Record {i} should be {ShortBuildRequestRecord.OnWireRecordSize} bytes");
    }

    [Test]
    public void TestShortTunnelBuildMessage_MaxRecords()
    {
        Assert.AreEqual(8, ShortTunnelBuildMessage.MaxRecords,
            "ShortTunnelBuildMessage.MaxRecords must be 8 per i2pd spec");
    }

    [Test]
    public void TestShortTunnelBuildMessage_SingleRecord()
    {
        var record = BufUtils.RandomBytes(ShortBuildRequestRecord.OnWireRecordSize);
        var msg = new ShortTunnelBuildMessage(new System.Collections.Generic.List<byte[]> { record });

        Assert.AreEqual(1, msg.RecordCount);
        Assert.IsTrue(BufUtils.Equal(record, msg.Records[0].ToByteArray()),
            "Single record content should be preserved");
    }

    // ------------------------------------------------------------------ //
    // LongBuildRequestRecord
    // ------------------------------------------------------------------ //

    [Test]
    public void TestLongBuildRequestRecord_Sizes()
    {
        // Per i2pd LONG_TUNNEL_BUILD_RECORD_SIZE the long record is 528 bytes on-wire
        Assert.AreEqual(528, LongBuildRequestRecord.EncryptedRecordSize,
            "LongBuildRequestRecord.EncryptedRecordSize must be exactly 528 bytes per i2pd spec");
    }
}
