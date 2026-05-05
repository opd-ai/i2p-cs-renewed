using System;
using I2PCore.Crypto;
using I2PCore.TransportLayer.SSU2;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     SSU2 protocol tests verifying packet format, crypto, and fragmentation
///     match the i2pd reference implementation.
/// </summary>
[TestFixture]
public class SSU2ProtocolTest
{
    /// <summary>
    ///     Verify SSU2 protocol constants match i2pd spec values exactly.
    /// </summary>
    [Test]
    public void TestSSU2ProtocolConstants()
    {
        // Protocol name per i2pd Crypto.cpp line 913
        Assert.AreEqual("Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256",
            SSU2Constants.PROTOCOL_NAME,
            "SSU2 protocol name must match i2pd");

        // Version and network ID
        Assert.AreEqual(2, SSU2Constants.VERSION, "SSU2 version must be 2");
        Assert.AreEqual(2, SSU2Constants.NETWORK_ID, "Network ID must be 2 for mainnet");

        // Header sizes per spec
        Assert.AreEqual(16, SSU2Constants.SHORT_HEADER_SIZE);
        Assert.AreEqual(32, SSU2Constants.LONG_HEADER_SIZE);

        // MTU values
        Assert.AreEqual(1280, SSU2Constants.MIN_MTU, "Min MTU per IPv6 spec");
        Assert.AreEqual(1500, SSU2Constants.DEFAULT_MTU);

        // Crypto
        Assert.AreEqual(32, SSU2Constants.EPHEMERAL_KEY_SIZE, "X25519 key is 32 bytes");
    }

    /// <summary>
    ///     Verify SSU2 message type constants match i2pd SSU2Session.h values.
    /// </summary>
    [Test]
    public void TestSSU2MessageTypes()
    {
        Assert.AreEqual(0, SSU2Constants.MSG_TYPE_SESSION_REQUEST);
        Assert.AreEqual(1, SSU2Constants.MSG_TYPE_SESSION_CREATED);
        Assert.AreEqual(2, SSU2Constants.MSG_TYPE_SESSION_CONFIRMED);
        Assert.AreEqual(6, SSU2Constants.MSG_TYPE_DATA);
        Assert.AreEqual(7, SSU2Constants.MSG_TYPE_PEER_TEST);
        Assert.AreEqual(9, SSU2Constants.MSG_TYPE_RETRY);
        Assert.AreEqual(10, SSU2Constants.MSG_TYPE_TOKEN_REQUEST);
        Assert.AreEqual(11, SSU2Constants.MSG_TYPE_HOLE_PUNCH);
    }

    /// <summary>
    ///     Verify SSU2 block type enum values match i2pd SSU2.h constants.
    /// </summary>
    [Test]
    public void TestSSU2BlockTypes()
    {
        Assert.AreEqual(0, (byte)SSU2BlockType.DateTime);
        Assert.AreEqual(1, (byte)SSU2BlockType.Options);
        Assert.AreEqual(2, (byte)SSU2BlockType.RouterInfo);
        Assert.AreEqual(3, (byte)SSU2BlockType.I2NP);
        Assert.AreEqual(4, (byte)SSU2BlockType.FirstFragment);
        Assert.AreEqual(5, (byte)SSU2BlockType.FollowOnFragment);
        Assert.AreEqual(6, (byte)SSU2BlockType.Termination);
        Assert.AreEqual(7, (byte)SSU2BlockType.RelayRequest);
        Assert.AreEqual(8, (byte)SSU2BlockType.RelayResponse);
        Assert.AreEqual(9, (byte)SSU2BlockType.RelayIntro);
        Assert.AreEqual(10, (byte)SSU2BlockType.PeerTest);
        Assert.AreEqual(11, (byte)SSU2BlockType.NextNonce);
        Assert.AreEqual(12, (byte)SSU2BlockType.ACK);
        Assert.AreEqual(13, (byte)SSU2BlockType.Address);
        // 14 is reserved in the spec (IntroKey not yet defined as block type)
        Assert.AreEqual(15, (byte)SSU2BlockType.RelayTagRequest);
        Assert.AreEqual(16, (byte)SSU2BlockType.RelayTag);
        Assert.AreEqual(17, (byte)SSU2BlockType.NewToken);
        Assert.AreEqual(18, (byte)SSU2BlockType.PathChallenge);
        Assert.AreEqual(19, (byte)SSU2BlockType.PathResponse);
        Assert.AreEqual(20, (byte)SSU2BlockType.FirstPacketNumber);
        Assert.AreEqual(254, (byte)SSU2BlockType.Padding);
    }

    /// <summary>
    ///     Test SSU2 short header (16 bytes) parse/serialize round-trip.
    ///     Per i2pd SSU2Session.cpp: Data packets use short headers.
    /// </summary>
    [Test]
    public void TestShortHeaderRoundTrip()
    {
        var original = new SSU2Header
        {
            DestinationConnectionId = 0x0102030405060708,
            PacketNumber = 42,
            Type = SSU2Constants.MSG_TYPE_DATA,
            IsLongHeader = false
        };

        var bytes = original.ToByteArray();
        Assert.AreEqual(SSU2Constants.SHORT_HEADER_SIZE, bytes.Length,
            "Short header should be 16 bytes");

        var parsed = SSU2Header.ParseShortHeader(new I2PBufferCursor(bytes));
        Assert.AreEqual(original.DestinationConnectionId, parsed.DestinationConnectionId);
        Assert.AreEqual(original.PacketNumber, parsed.PacketNumber);
        Assert.AreEqual(original.Type, parsed.Type);
    }

    /// <summary>
    ///     Test SSU2 long header (32 bytes) parse/serialize round-trip.
    ///     Per i2pd: SessionRequest/Created/Retry use long headers.
    /// </summary>
    [Test]
    public void TestLongHeaderRoundTrip()
    {
        var original = new SSU2Header
        {
            DestinationConnectionId = 0xAABBCCDDEEFF0011,
            PacketNumber = 0,
            Type = SSU2Constants.MSG_TYPE_SESSION_REQUEST,
            Version = SSU2Constants.VERSION,
            NetId = SSU2Constants.NETWORK_ID,
            Flag = 0,
            SourceConnectionId = 0x1122334455667788,
            Token = 0xDEADBEEFCAFEBABE,
            IsLongHeader = true
        };

        var bytes = original.ToByteArray();
        Assert.AreEqual(SSU2Constants.LONG_HEADER_SIZE, bytes.Length,
            "Long header should be 32 bytes");

        var parsed = SSU2Header.ParseLongHeader(new I2PBufferCursor(bytes));
        Assert.AreEqual(original.DestinationConnectionId, parsed.DestinationConnectionId);
        Assert.AreEqual(original.PacketNumber, parsed.PacketNumber);
        Assert.AreEqual(original.Type, parsed.Type);
        Assert.AreEqual(original.Version, parsed.Version);
        Assert.AreEqual(original.NetId, parsed.NetId);
        Assert.AreEqual(original.SourceConnectionId, parsed.SourceConnectionId);
        Assert.AreEqual(original.Token, parsed.Token);
    }

    /// <summary>
    ///     Verify short header byte layout matches i2pd wire format.
    ///     Bytes 0-7: DestConnId (BE), 8-11: PacketNum (BE), 12: Type
    /// </summary>
    [Test]
    public void TestShortHeaderByteLayout()
    {
        var header = new SSU2Header
        {
            DestinationConnectionId = 0x0102030405060708,
            PacketNumber = 0x0A0B0C0D,
            Type = 6, // DATA
            IsLongHeader = false
        };

        var bytes = header.ToByteArray();

        // DestConnId big-endian
        Assert.AreEqual(0x01, bytes[0]);
        Assert.AreEqual(0x02, bytes[1]);
        Assert.AreEqual(0x08, bytes[7]);

        // PacketNumber big-endian at offset 8
        Assert.AreEqual(0x0A, bytes[8]);
        Assert.AreEqual(0x0D, bytes[11]);

        // Type at offset 12
        Assert.AreEqual(6, bytes[12]);
    }

    /// <summary>
    ///     Test fragment handler constants match i2pd.
    /// </summary>
    [Test]
    public void TestFragmentConstants()
    {
        Assert.AreEqual(1500, SSU2FragmentHandler.SSU2_MAX_PACKET_SIZE);
        Assert.AreEqual(64, SSU2FragmentHandler.MAX_NUM_FRAGMENTS);
        Assert.AreEqual(30, SSU2FragmentHandler.INCOMPLETE_MESSAGE_TIMEOUT_SECONDS);
    }

    /// <summary>
    ///     Test that small messages don't need fragmentation.
    /// </summary>
    [Test]
    public void TestNoFragmentationNeeded()
    {
        var smallMsg = BufUtils.RandomBytes(100);
        Assert.IsFalse(
            SSU2FragmentHandler.NeedsFragmentation(smallMsg.Length, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV4),
            "Small message should not need fragmentation");
    }

    /// <summary>
    ///     Test that large messages trigger fragmentation.
    /// </summary>
    [Test]
    public void TestFragmentationNeeded()
    {
        var largeMsg = BufUtils.RandomBytes(5000);
        Assert.IsTrue(
            SSU2FragmentHandler.NeedsFragmentation(largeMsg.Length, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV4),
            "Large message should need fragmentation");
    }

    /// <summary>
    ///     Helper: strip 3-byte block header from a fragment block produced by FragmentMessage.
    ///     The fragment handler receives data AFTER block parsing removes the header.
    /// </summary>
    private static byte[] StripBlockHeader(byte[] block)
    {
        // Block format: type(1) + size(2) + data
        var size = (block[1] << 8) | block[2];
        var data = new byte[size];
        Array.Copy(block, 3, data, 0, size);
        return data;
    }

    /// <summary>
    ///     Test message fragmentation and reassembly round-trip.
    ///     Per i2pd: messages > MTU are split into FirstFragment + FollowOnFragments.
    ///     The fragment handler receives inner block data (block header already stripped).
    /// </summary>
    [Test]
    public void TestFragmentAndReassemble()
    {
        var handler = new SSU2FragmentHandler();
        var originalData = BufUtils.RandomBytes(5000);
        uint msgId = 12345;

        // The handler extracts msgId from I2NP header bytes [1..4] of the first fragment.
        // Embed the msgId into the data so the handler can find it.
        originalData[1] = (byte)(msgId >> 24);
        originalData[2] = (byte)(msgId >> 16);
        originalData[3] = (byte)(msgId >> 8);
        originalData[4] = (byte)msgId;

        var fragments = SSU2FragmentHandler.FragmentMessage(
            originalData, msgId, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV4);

        Assert.IsNotNull(fragments);
        Assert.IsTrue(fragments.Count > 1, "Should produce multiple fragments");
        Assert.IsTrue(fragments.Count <= SSU2FragmentHandler.MAX_NUM_FRAGMENTS);

        // Reassemble: strip block headers since handler gets raw inner data
        var result = handler.HandleFirstFragment(StripBlockHeader(fragments[0]));
        Assert.IsNull(result, "First fragment alone should not complete the message");

        for (var i = 1; i < fragments.Count - 1; i++)
        {
            result = handler.HandleFollowOnFragment(StripBlockHeader(fragments[i]));
            Assert.IsNull(result, $"Intermediate fragment {i} should not complete");
        }

        result = handler.HandleFollowOnFragment(StripBlockHeader(fragments[fragments.Count - 1]));
        Assert.IsNotNull(result, "Last fragment should complete the message");
        Assert.IsTrue(BufUtils.Equal(originalData, result),
            "Reassembled message should match original");
    }

    /// <summary>
    ///     Test out-of-order fragment reassembly.
    /// </summary>
    [Test]
    public void TestOutOfOrderFragmentReassembly()
    {
        var handler = new SSU2FragmentHandler();
        var originalData = BufUtils.RandomBytes(5000);
        uint msgId = 99999;

        // Embed msgId into I2NP header position (bytes 1-4)
        originalData[1] = (byte)(msgId >> 24);
        originalData[2] = (byte)(msgId >> 16);
        originalData[3] = (byte)(msgId >> 8);
        originalData[4] = (byte)msgId;

        var fragments = SSU2FragmentHandler.FragmentMessage(
            originalData, msgId, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV4);

        Assert.IsTrue(fragments.Count >= 3, "Need at least 3 fragments");

        // First fragment must come first to register the message ID
        handler.HandleFirstFragment(StripBlockHeader(fragments[0]));

        // Feed remaining in reverse order
        byte[] result = null;
        for (var i = fragments.Count - 1; i >= 1; i--)
            result = handler.HandleFollowOnFragment(StripBlockHeader(fragments[i]));

        Assert.IsNotNull(result, "All fragments received should complete the message");
        Assert.IsTrue(BufUtils.Equal(originalData, result),
            "Out-of-order reassembled data should match");
    }

    /// <summary>
    ///     Test ACK range generation from received packet numbers.
    /// </summary>
    [Test]
    public void TestAckRangeGeneration()
    {
        var ackMgr = new SSU2AckManager();

        // Record contiguous packets 1-5
        for (uint i = 1; i <= 5; i++)
            ackMgr.RecordReceived(i);

        var ackBlock = ackMgr.GenerateAck();
        Assert.IsNotNull(ackBlock);
        Assert.IsTrue(ackBlock.AckRanges.Count >= 1, "Should have at least one range");

        // The range should cover 1 through 5
        var firstRange = ackBlock.AckRanges[0];
        Assert.AreEqual(5u, firstRange.End, "End should be highest packet number");
    }

    /// <summary>
    ///     Test ACK with gaps (missing packets create multiple ranges).
    /// </summary>
    [Test]
    public void TestAckWithGaps()
    {
        var ackMgr = new SSU2AckManager();

        // Record packets with a gap: 1, 2, 3, 5, 6, 7 (missing 4)
        ackMgr.RecordReceived(1);
        ackMgr.RecordReceived(2);
        ackMgr.RecordReceived(3);
        ackMgr.RecordReceived(5);
        ackMgr.RecordReceived(6);
        ackMgr.RecordReceived(7);

        var ackBlock = ackMgr.GenerateAck();
        Assert.IsNotNull(ackBlock);

        // Should have 2 ranges: [5-7] and [1-3]
        Assert.IsTrue(ackBlock.AckRanges.Count >= 2,
            "Gap should produce at least 2 ACK ranges");
    }

    /// <summary>
    ///     Test retransmit tracking.
    /// </summary>
    [Test]
    public void TestRetransmitTracking()
    {
        var ackMgr = new SSU2AckManager();

        var packetData = BufUtils.RandomBytes(100);
        ackMgr.RecordSent(1, packetData);

        Assert.IsTrue(ackMgr.HasUnackedPackets, "Should have unacked packet");
        Assert.AreEqual(1, ackMgr.UnackedCount);

        // ACK the packet
        var ackBlock = new SSU2AckBlock();
        ackBlock.AckRanges.Add(new AckRange { Start = 1, End = 1 });
        ackMgr.ProcessAck(ackBlock);

        Assert.IsFalse(ackMgr.HasUnackedPackets, "Should have no unacked after ACK");
    }

    /// <summary>
    ///     Test ACK block serialization round-trip.
    /// </summary>
    [Test]
    public void TestAckBlockSerialization()
    {
        var original = new SSU2AckBlock();
        original.AckRanges.Add(new AckRange { Start = 10, End = 15 });
        original.AckRanges.Add(new AckRange { Start = 1, End = 5 });

        var bytes = original.Serialize();
        Assert.IsNotNull(bytes);
        Assert.IsTrue(bytes.Length > 0);

        var parsed = SSU2AckBlock.Parse(new I2PBufferCursor(bytes));
        Assert.IsNotNull(parsed);
        Assert.AreEqual(original.AckRanges.Count, parsed.AckRanges.Count,
            "Parsed ACK block should have same number of ranges");
    }

    /// <summary>
    ///     Test SSU2 header key derivation produces correct-length keys.
    /// </summary>
    [Test]
    public void TestHeaderKeyDerivation()
    {
        var chainingKey = BufUtils.RandomBytes(32);

        var sessionCreatedKey = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);
        Assert.IsNotNull(sessionCreatedKey);
        Assert.AreEqual(32, sessionCreatedKey.Length, "Header key should be 32 bytes");

        var sessionConfirmedKey = SSU2HeaderEncryption.DeriveSessionConfirmedHeaderKey(chainingKey);
        Assert.IsNotNull(sessionConfirmedKey);
        Assert.AreEqual(32, sessionConfirmedKey.Length);

        // Different info strings should produce different keys
        Assert.IsFalse(BufUtils.Equal(sessionCreatedKey, sessionConfirmedKey),
            "Different derivation contexts should produce different keys");
    }

    /// <summary>
    ///     Test SSU2 header key derivation is deterministic.
    /// </summary>
    [Test]
    public void TestHeaderKeyDerivationDeterministic()
    {
        var chainingKey = BufUtils.RandomBytes(32);

        var key1 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);
        var key2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

        Assert.IsTrue(BufUtils.Equal(key1, key2),
            "Same chaining key should produce same header key");
    }

    /// <summary>
    ///     Test headerX obfuscation/deobfuscation round-trip.
    ///     Per i2pd: the 48-byte headerX (srcConnID+token+ephKey) is XOR'd with a single
    ///     ChaCha20 keystream via ObfuscateHeaderX.  ChaCha20 is self-inverse, so calling
    ///     ObfuscateHeaderX twice on the same data restores the original.
    /// </summary>
    [Test]
    public void TestHeaderXObfuscationRoundTrip()
    {
        // Build a 64-byte packet: 16-byte first header + 48-byte headerX (srcConnID+token+ephKey)
        var packet = BufUtils.RandomBytes(80); // 32 header + 48 payload (need 24+ bytes after for IV)
        var original = (byte[])packet.Clone();
        var headerKey = BufUtils.RandomBytes(32);

        // Obfuscate headerX (bytes 16-63)
        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, headerKey);

        // Bytes 16-63 should have changed
        var anyChanged = false;
        for (var i = 16; i < 64; i++)
            if (packet[i] != original[i])
                anyChanged = true;
        Assert.IsTrue(anyChanged, "Obfuscation should change headerX bytes");

        // Bytes 0-15 should be unchanged (ObfuscateHeaderX only touches 16-63)
        for (var i = 0; i < 16; i++)
            Assert.AreEqual(original[i], packet[i], $"ObfuscateHeaderX must not change byte {i}");

        // Deobfuscate (ChaCha20 is self-inverse)
        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, headerKey);

        for (var i = 16; i < 64; i++)
            Assert.AreEqual(original[i], packet[i], $"HeaderX deobfuscation round-trip failed at byte {i}");
    }

    /// <summary>
    ///     Verifies that the ephemeral key within a headerX packet is obfuscated using
    ///     keystream bytes 16-47 (not 0-31).  Specifically confirms alignment with i2pd's
    ///     single 48-byte ChaCha20 call on headerX.
    /// </summary>
    [Test]
    public void TestEphemeralKeyUsesCorrectKeystreamOffset()
    {
        var introKey = BufUtils.RandomBytes(32);

        // Build a minimal long-header packet (32-byte header + 32-byte ephKey + 16-byte payload)
        var packet = new byte[80];
        var ephKey = BufUtils.RandomBytes(32);
        Array.Copy(ephKey, 0, packet, 32, 32); // Place plain ephKey at bytes 32-63

        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, introKey);

        // The obfuscated ephemeral key at bytes 32-63 should equal ephKey XOR ks[16:48]
        // where ks is the ChaCha20(introKey, zeroNonce, 48) keystream.
        // The GetEphKeyObfuscatedFirstByte helper uses ks[16] — verify it matches packet[32].
        var expectedObfFirstByte = SSU2HeaderEncryption.GetEphKeyObfuscatedFirstByte(ephKey[0], introKey);
        Assert.AreEqual(expectedObfFirstByte, packet[32],
            "First byte of obfuscated ephKey must use keystream byte 16 (not 0)");
    }

    /// <summary>
    ///     Test short header encrypt/decrypt round-trip.
    /// </summary>
    [Test]
    public void TestShortHeaderEncryptDecrypt()
    {
        // Build a packet: 16-byte header + 48-byte payload (need 24+ bytes after header for IV)
        var packet = BufUtils.RandomBytes(64);
        var original = (byte[])packet.Clone();

        var k1 = BufUtils.RandomBytes(32);
        var k2 = BufUtils.RandomBytes(32);

        SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet, 0, k1, k2);

        // Header bytes should have changed
        var anyChanged = false;
        for (var i = 0; i < 16; i++)
            if (packet[i] != original[i])
                anyChanged = true;
        Assert.IsTrue(anyChanged, "Encryption should change header bytes");

        // Decrypt
        SSU2HeaderEncryption.DecryptShortHeaderInPacket(packet, 0, k1, k2);

        // Should match original
        Assert.IsTrue(BufUtils.Equal(original, packet),
            "Decrypt(Encrypt(header)) should produce original");
    }

    /// <summary>
    ///     Verify payload size calculations match i2pd.
    ///     Per i2pd: max_payload = MTU - IP_header - UDP_header - crypto_overhead
    /// </summary>
    [Test]
    public void TestPayloadSizeCalculations()
    {
        // IPv4: 1500 - 20 - 8 - 32 = 1440
        Assert.AreEqual(1440, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV4,
            "IPv4 max payload should be 1440");

        // IPv6: 1500 - 40 - 8 - 32 = 1420
        Assert.AreEqual(1420, SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV6,
            "IPv6 max payload should be 1420");
    }
}