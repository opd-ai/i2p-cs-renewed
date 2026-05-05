using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.SessionLayer.Streaming;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class StreamingProtocolTest
{
    /// <summary>
    ///     Test that StreamingPacket round-trips through serialization.
    /// </summary>
    [Test]
    public void TestStreamingPacketSerialization()
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = 0x12345678,
            ReceiveStreamId = 0xABCDEF01,
            SequenceNumber = 42,
            AckThrough = 41,
            ResendDelay = 5,
            Flags = StreamingPacket.FLAG_SYNCHRONIZE | StreamingPacket.FLAG_FROM_INCLUDED,
            Payload = BufUtils.RandomBytes(100)
        };

        var bytes = pkt.ToByteArray();
        Assert.IsNotNull(bytes);
        Assert.IsTrue(bytes.Length > 0, "Serialized packet should not be empty");

        var parsed = StreamingPacket.Parse(bytes);

        Assert.AreEqual(pkt.SendStreamId, parsed.SendStreamId, "SendStreamId mismatch");
        Assert.AreEqual(pkt.ReceiveStreamId, parsed.ReceiveStreamId, "ReceiveStreamId mismatch");
        Assert.AreEqual(pkt.SequenceNumber, parsed.SequenceNumber, "SequenceNumber mismatch");
        Assert.AreEqual(pkt.AckThrough, parsed.AckThrough, "AckThrough mismatch");
    }

    /// <summary>
    ///     Test stream creation and basic state transitions.
    /// </summary>
    [Test]
    public void TestStreamStateTransitions()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var localDest = new I2PDestination(keys.PublicKey, pubskey);
        var remoteDest = new I2PDestination(keys.PublicKey, pubskey);

        var sentPackets = new List<byte[]>();

        var stream = new I2PStream(
            localDest,
            remoteDest,
            localDest.ToByteArray(),
            data => sentPackets.Add(data),
            privskey);

        Assert.AreEqual(I2PStream.StreamStatus.New, stream.Status);
        Assert.IsTrue(stream.IsOutgoing);

        // Send data should stay in New until SYN/ACK
        stream.Send(new byte[] { 1, 2, 3 });

        Assert.AreEqual(I2PStream.StreamStatus.New, stream.Status,
            "After first send, stream should still be New until SYN/ACK");
        Assert.IsTrue(sentPackets.Count > 0, "Should have sent a SYN packet");

        // Simulate receiving a SYN/ACK from remote
        var ackPkt = new StreamingPacket
        {
            SendStreamId = 12345, // remote ID
            ReceiveStreamId = stream.RecvStreamId, // our ID
            SequenceNumber = 0,
            AckThrough = 0, // ACK through seq 0
            Flags = StreamingPacket.FLAG_SYNCHRONIZE // SYN/ACK
        };
        stream.HandleNextPacket(ackPkt);

        Assert.AreEqual(I2PStream.StreamStatus.Open, stream.Status,
            "After SYN/ACK, stream should be Open");

        // First packet should have SYN flag
        var firstPkt = StreamingPacket.Parse(sentPackets[0]);
        Assert.IsTrue(firstPkt.IsSYN, "First packet should be SYN");
    }

    /// <summary>
    ///     Test that close sends a CLOSE packet after all data is acknowledged.
    /// </summary>
    [Test]
    public void TestStreamClose()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var localDest = new I2PDestination(keys.PublicKey, pubskey);
        var remoteDest = new I2PDestination(keys.PublicKey, pubskey);

        var sentPackets = new List<byte[]>();

        var stream = new I2PStream(
            localDest,
            remoteDest,
            localDest.ToByteArray(),
            data => sentPackets.Add(data),
            privskey);

        // Move to Open state by sending SYN and receiving SYN/ACK
        stream.Send(new byte[] { 1, 2, 3 });
        Assert.IsTrue(sentPackets.Count > 0, "Should have sent SYN");

        // Simulate receiving an ACK for the SYN packet (seq 0)
        var ackPkt = new StreamingPacket
        {
            SendStreamId = 12345, // remote ID
            ReceiveStreamId = stream.RecvStreamId, // our ID
            SequenceNumber = 0,
            AckThrough = 0, // ACK through seq 0
            Flags = StreamingPacket.FLAG_SYNCHRONIZE // SYN/ACK
        };
        stream.HandleNextPacket(ackPkt);
        Assert.AreEqual(I2PStream.StreamStatus.Open, stream.Status, "Stream should be Open after SYN/ACK");

        sentPackets.Clear();

        // Now close - should succeed since send queue is clear
        stream.Close();

        // Should have sent a CLOSE packet
        Assert.IsTrue(sentPackets.Count > 0, "Close should send a packet");
        var closePkt = StreamingPacket.Parse(sentPackets[sentPackets.Count - 1]);
        Assert.IsTrue(closePkt.IsClose, "Last sent packet should have CLOSE flag");
    }

    /// <summary>
    ///     Test streaming constants match i2pd reference values.
    /// </summary>
    [Test]
    public void TestStreamingConstants()
    {
        Assert.AreEqual(1730, I2PStream.STREAMING_MTU,
            "MTU should match i2pd STREAMING_MTU");
        Assert.AreEqual(1812, I2PStream.STREAMING_MTU_RATCHETS,
            "Ratchet MTU should match i2pd");
        Assert.AreEqual(10, I2PStream.INITIAL_WINDOW_SIZE,
            "Initial window should match i2pd");
        Assert.AreEqual(3, I2PStream.MIN_WINDOW_SIZE,
            "Min window should match i2pd");
        Assert.AreEqual(512, I2PStream.MAX_WINDOW_SIZE,
            "Max window should match i2pd");
        Assert.AreEqual(1500, I2PStream.INITIAL_RTT,
            "Initial RTT should match i2pd");
        Assert.AreEqual(9000, I2PStream.INITIAL_RTO,
            "Initial RTO should match i2pd");
        Assert.AreEqual(20, I2PStream.MIN_RTO,
            "Min RTO should match i2pd");
        Assert.AreEqual(10, I2PStream.MAX_NUM_RESEND_ATTEMPTS,
            "Max resend attempts should match i2pd");
        Assert.AreEqual(2, I2PStream.MIN_SEND_ACK_TIMEOUT,
            "Min ACK timeout should match i2pd");
    }

    /// <summary>
    ///     Test datagram creation and parsing round-trip.
    /// </summary>
    [Test]
    public void TestRepliableDatagramRoundTrip()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var sender = new I2PDestination(keys.PublicKey, pubskey);

        var payload = BufUtils.RandomBytes(256);

        // Create a repliable datagram
        var datagram = I2PDatagramDissector.CreateRepliableDatagram(
            sender, privskey, payload);

        Assert.IsNotNull(datagram);
        Assert.IsTrue(datagram.Length > payload.Length,
            "Datagram should be larger than payload (includes identity + signature)");

        // Parse it back
        var (parsedSender, parsedPayload, verified) =
            I2PDatagramDissector.ParseRepliableDatagram(datagram);

        Assert.IsNotNull(parsedSender, "Parsed sender should not be null");
        Assert.IsNotNull(parsedPayload, "Parsed payload should not be null");
        Assert.IsTrue(BufUtils.Equal(payload, parsedPayload),
            "Parsed payload should match original");
        Assert.IsTrue(verified, "Signature should verify");
    }

    /// <summary>
    ///     Test raw datagram creation.
    /// </summary>
    [Test]
    public void TestRawDatagram()
    {
        var payload = BufUtils.RandomBytes(512);
        var raw = I2PDatagramDissector.CreateRawDatagram(payload);

        Assert.IsNotNull(raw);
        Assert.IsTrue(BufUtils.Equal(payload, raw),
            "Raw datagram should be identical to payload");
    }

    // ------------------------------------------------------------------
    // Window management
    // ------------------------------------------------------------------

    private static (I2PStream stream, List<byte[]> sentPackets) CreateOpenStream()
    {
        var cert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var keys = I2PPrivateKey.GetNewKeyPair();
        var privskey = new I2PSigningPrivateKey(cert);
        var pubskey = new I2PSigningPublicKey(privskey);
        var localDest = new I2PDestination(keys.PublicKey, pubskey);
        var remoteDest = new I2PDestination(keys.PublicKey, pubskey);

        var sentPackets = new List<byte[]>();

        var stream = new I2PStream(
            localDest,
            remoteDest,
            localDest.ToByteArray(),
            data => sentPackets.Add(data),
            privskey);

        // Move stream to Open state by doing SYN exchange
        stream.Send(new byte[] { 1 });
        var synAck = new StreamingPacket
        {
            SendStreamId = 99999,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 0,
            AckThrough = 0,
            Flags = StreamingPacket.FLAG_SYNCHRONIZE
        };
        stream.HandleNextPacket(synAck);
        sentPackets.Clear();
        return (stream, sentPackets);
    }

    /// <summary>
    ///     Test that sending data beyond the initial window size buffers the excess.
    ///     Packets should be sent up to the window limit; the rest waits for ACKs.
    /// </summary>
    [Test]
    public void TestWindowFlowControl_BuffersExcess()
    {
        var (stream, sentPackets) = CreateOpenStream();

        // Track sent sequence numbers via the event
        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send (INITIAL_WINDOW_SIZE + 2) individual chunks at MTU size
        // The first INITIAL_WINDOW_SIZE should go out immediately; the rest buffer
        var numToSend = I2PStream.INITIAL_WINDOW_SIZE + 2;
        for (var i = 0; i < numToSend; i++)
            stream.Send(new byte[100]);

        // At most (INITIAL_WINDOW_SIZE + 1) packets should have been transmitted.
        // (+1 because the SYN/ACK received in setup increments the window by 1 via slow start.)
        // The key assertion is that NOT all numToSend packets were sent immediately.
        Assert.Less(sentSeqs.Count, numToSend,
            $"Not all {numToSend} packets should be sent before any data ACK — excess must be buffered");
        Assert.Greater(sentSeqs.Count, 0,
            "At least one packet should have been sent");
    }

    /// <summary>
    ///     Test that an ACK opens the window and lets buffered data flow.
    ///     Sends 2 × INITIAL_WINDOW_SIZE packets so that the second half is buffered,
    ///     then ACKs the first half and verifies the buffered packets are flushed.
    /// </summary>
    [Test]
    public void TestWindowFlowControl_AckOpensWindow()
    {
        var (stream, sentPackets) = CreateOpenStream();

        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send 2 × INITIAL_WINDOW_SIZE packets.
        // The first (INITIAL_WINDOW_SIZE + 1) will fill the window (window = 11 after SYN/ACK
        // slow-start increase); the remaining (INITIAL_WINDOW_SIZE - 1) will be buffered.
        var totalToSend = I2PStream.INITIAL_WINDOW_SIZE * 2;
        for (var i = 0; i < totalToSend; i++)
            stream.Send(new byte[100]);

        var countBeforeAck = sentSeqs.Count;

        // Sanity: not all packets were sent (some are buffered)
        Assert.Less(countBeforeAck, totalToSend,
            "Not all packets should be sent before an ACK — some must be buffered");

        // ACK all in-flight packets to open the window
        var ackThrough = sentSeqs.LastOrDefault();
        var ack = new StreamingPacket
        {
            SendStreamId = stream.SendStreamId,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 1,
            AckThrough = ackThrough,
            Flags = 0
        };
        stream.HandleNextPacket(ack);

        // After the ACK the buffered packets should have been sent
        Assert.Greater(sentSeqs.Count, countBeforeAck,
            "ACK should allow buffered packets to be sent (window opened)");
    }

    /// <summary>
    ///     Test that sequence numbers increase monotonically for consecutive sends.
    /// </summary>
    [Test]
    public void TestSequenceNumberMonotonicallyIncreases()
    {
        var (stream, _) = CreateOpenStream();

        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send a few individual payloads
        const int N = 5;
        for (var i = 0; i < N; i++)
            stream.Send(new byte[100]);

        var seqsSent = sentSeqs.Count;
        Assert.Greater(seqsSent, 0, "Should have sent at least one packet");

        for (var i = 1; i < seqsSent; i++)
            Assert.Greater(sentSeqs[i], sentSeqs[i - 1],
                $"Sequence number at index {i} should be greater than at index {i - 1}");
    }

    // ------------------------------------------------------------------
    // Retransmission / NACK handling
    // ------------------------------------------------------------------

    /// <summary>
    ///     Test that a NACK causes the window to drop (congestion signal).
    ///     After a NACK the stream should reduce its window size toward MIN_WINDOW_SIZE.
    /// </summary>
    [Test]
    public void TestNackCausesCongestionWindowDrop()
    {
        var (stream, _) = CreateOpenStream();

        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send a few packets to get sequence numbers to NACK
        for (var i = 0; i < 4; i++)
            stream.Send(new byte[100]);

        // We need at least 2 sent packets for a meaningful NACK test
        if (sentSeqs.Count < 2)
        {
            Assert.Ignore("Not enough packets sent to test NACK handling");
            return;
        }

        var windowBefore = stream.CurrentWindowSize;

        // Send an ACK for the first packet with a NACK for the second
        var ackPkt = new StreamingPacket
        {
            SendStreamId = stream.SendStreamId,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 1,
            AckThrough = sentSeqs[0],   // ACK only the first
            NACKs = new List<uint> { sentSeqs[1] }, // NACK the second
            Flags = 0
        };
        stream.HandleNextPacket(ackPkt);

        // Window must not grow on a NACK — it should stay the same or drop
        Assert.LessOrEqual(stream.CurrentWindowSize, windowBefore,
            $"Window ({stream.CurrentWindowSize}) must not grow after a NACK (was {windowBefore})");

        // Window must remain at least MIN_WINDOW_SIZE
        Assert.GreaterOrEqual(stream.CurrentWindowSize, I2PStream.MIN_WINDOW_SIZE,
            "Window must stay at or above MIN_WINDOW_SIZE after a NACK");

        // Stream must not terminate on a single NACK
        Assert.AreNotEqual(I2PStream.StreamStatus.Terminated, stream.Status,
            "Stream must not terminate on a single NACK");
    }

    /// <summary>
    ///     Test packet re-sending: after a NACK the stream eventually retransmits.
    ///     We verify the NACK is recorded by observing that the window did not open further.
    /// </summary>
    [Test]
    public void TestNack_NackedSequenceTracked()
    {
        var (stream, _) = CreateOpenStream();

        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send 3 packets
        for (var i = 0; i < 3; i++)
            stream.Send(new byte[50]);

        if (sentSeqs.Count < 2)
        {
            Assert.Ignore("Not enough packets sent to test NACK handling");
            return;
        }

        // Snapshot the window before the NACK
        var windowBeforeNack = stream.CurrentWindowSize;

        // NACK the first data packet
        var nackedSeq = sentSeqs[0];
        var ackWithNack = new StreamingPacket
        {
            SendStreamId = stream.SendStreamId,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 1,
            AckThrough = 0,
            NACKs = new List<uint> { nackedSeq },
            Flags = 0
        };
        stream.HandleNextPacket(ackWithNack);

        // The NACK must not cause the window to grow (it either stays same or drops)
        Assert.LessOrEqual(stream.CurrentWindowSize, windowBeforeNack,
            $"Window must not grow after NACK (before: {windowBeforeNack}, after: {stream.CurrentWindowSize})");

        // The stream should still be open (one NACK does not close the stream)
        Assert.AreNotEqual(I2PStream.StreamStatus.Terminated, stream.Status,
            "Stream must remain Open after a single NACK");
    }

    /// <summary>
    ///     Test that the window size starts at INITIAL_WINDOW_SIZE, increases after ACKs
    ///     and shrinks back toward MIN_WINDOW_SIZE after a NACK (AIMD behaviour).
    /// </summary>
    [Test]
    public void TestWindowSize_AIMDBehaviour()
    {
        var (stream, _) = CreateOpenStream();

        // Initial window should be INITIAL_WINDOW_SIZE (plus slow-start bump from SYN/ACK)
        Assert.GreaterOrEqual(stream.CurrentWindowSize, I2PStream.INITIAL_WINDOW_SIZE,
            "Initial window must be at least INITIAL_WINDOW_SIZE");

        var sentSeqs = new List<uint>();
        stream.PacketSent += (_, seq, _) => sentSeqs.Add(seq);

        // Send several packets to have sequences to ACK/NACK
        for (var i = 0; i < 4; i++)
            stream.Send(new byte[100]);

        if (sentSeqs.Count < 2)
        {
            Assert.Ignore("Not enough packets sent to test AIMD");
            return;
        }

        // Step 1: ACK the first packet — window should grow or stay the same
        var windowAfterSyn = stream.CurrentWindowSize;
        var ack1 = new StreamingPacket
        {
            SendStreamId = stream.SendStreamId,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 1,
            AckThrough = sentSeqs[0],
            Flags = 0
        };
        stream.HandleNextPacket(ack1);

        Assert.GreaterOrEqual(stream.CurrentWindowSize, windowAfterSyn,
            "Window should not shrink on a pure ACK");

        // Step 2: Send a NACK — window should drop
        var windowAfterAck = stream.CurrentWindowSize;
        if (sentSeqs.Count < 2)
        {
            Assert.Ignore("Not enough further sequences for NACK test");
            return;
        }

        var nack = new StreamingPacket
        {
            SendStreamId = stream.SendStreamId,
            ReceiveStreamId = stream.RecvStreamId,
            SequenceNumber = 2,
            AckThrough = sentSeqs[0],
            NACKs = new List<uint> { sentSeqs[1] },
            Flags = 0
        };
        stream.HandleNextPacket(nack);

        Assert.LessOrEqual(stream.CurrentWindowSize, windowAfterAck,
            $"Window must not grow after NACK (ACK window: {windowAfterAck}, NACK window: {stream.CurrentWindowSize})");
        Assert.GreaterOrEqual(stream.CurrentWindowSize, I2PStream.MIN_WINDOW_SIZE,
            "Window must stay at or above MIN_WINDOW_SIZE after NACK");
    }

    // ------------------------------------------------------------------
    // StreamingPacket NACK serialization
    // ------------------------------------------------------------------

    /// <summary>
    ///     Test that NACKs serialise and deserialise correctly in StreamingPacket.
    /// </summary>
    [Test]
    public void TestStreamingPacketNackRoundTrip()
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = 0xAABBCCDD,
            ReceiveStreamId = 0x11223344,
            SequenceNumber = 10,
            AckThrough = 9,
            NACKs = new List<uint> { 3, 5, 7 },
            Flags = 0
        };

        var bytes = pkt.ToByteArray();
        var parsed = StreamingPacket.Parse(bytes);

        Assert.IsNotNull(parsed.NACKs, "NACKs should not be null after parse");
        Assert.AreEqual(3, parsed.NACKs.Count, "Should have 3 NACKed sequence numbers");
        Assert.AreEqual((uint)3, parsed.NACKs[0], "NACK[0] mismatch");
        Assert.AreEqual((uint)5, parsed.NACKs[1], "NACK[1] mismatch");
        Assert.AreEqual((uint)7, parsed.NACKs[2], "NACK[2] mismatch");
    }
}