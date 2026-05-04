using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Data;
using I2PCore.Utils;

namespace I2PCore.SessionLayer.Streaming;

/// <summary>
///     I2P Streaming Protocol stream - provides TCP-like reliable delivery over I2P.
///     Implements the I2P Streaming spec with AIMD congestion control, EWMA RTT,
///     retransmission with fast retransmit/recovery, and proper close handshake.
/// </summary>
public class I2PStream : IDisposable
{
    public enum StreamStatus
    {
        New,
        Open,
        Reset,
        Closing,
        Closed,
        Terminated
    }

    // Constants per i2pd reference (Streaming.h)
    public const int STREAMING_MTU = 1730;
    public const int STREAMING_MTU_RATCHETS = 1812;
    public const int INITIAL_WINDOW_SIZE = 64; // Java I2P: MAX_SLOW_START_WINDOW = 64
    public const int MIN_WINDOW_SIZE = 3;
    public const int MAX_WINDOW_SIZE = 512;
    public const int INITIAL_RTT = 50; // ms — conservative estimate, EWMA will measure the real value
    public const int INITIAL_RTO = 1000; // ms
    public const int MIN_RTO = 20; // ms
    public const int SYN_TIMEOUT = 200; // ms
    public const int MAX_NUM_RESEND_ATTEMPTS = 10;
    public const int MAX_RECEIVE_TIMEOUT_MS = 20000;
    public const int MIN_SEND_ACK_TIMEOUT = 2; // ms
    public const int COMPRESSION_THRESHOLD_SIZE = 66;
    public const int MAX_PENDING_INCOMING_BACKLOG = 1024;
    public const int PENDING_INCOMING_TIMEOUT = 10000; // ms
    public const int REQUEST_IMMEDIATE_ACK_INTERVAL = 7500; // ms
    public const int REQUEST_IMMEDIATE_ACK_INTERVAL_VARIANCE = 3200; // ms
    public const int SEND_INTERVAL = 5; // ms (5000 us)

    // Loss-based congestion control (per i2pd Streaming.h)
    public const bool LOSS_BASED_CONTROL_ENABLED = true;
    private const double LOSS_RATE_THRESHOLD = 0.02; // 2% loss triggers window reduction

    // EWMA constants for RTT smoothing
    private const double RTT_EWMA_ALPHA = 0.1;
    private const double SLOWRTT_EWMA_ALPHA = 0.03;
    private const double PREV_SPEED_KEEP_TIME_COEFF = 0.2;

    // Choking detection delay thresholds (ms)
    private const ushort DELAY_CHOKING = 60000;
    private const ushort DELAY_CHOKING_JAVA = 61000;
    private const ushort DELAY_CHOKING_2 = 65535;
    private const ushort DELAY_CHOKING_3 = 65534;
    private const int LEASE_LOOKUP_INTERVAL_MS = 10000; // Don't look up more than once per 10s

    // Identity
    private readonly I2PDestination _localDestination;
    private readonly byte[] _localIdentityBytes;
    private readonly HashSet<uint> _nackedPackets = new();
    private readonly ConcurrentQueue<StreamingPacket> _receiveQueue = new();
    private readonly SortedDictionary<uint, StreamingPacket> _savedPackets = new();
    private readonly ConcurrentQueue<byte[]> _sendBuffer = new();

    // Send callback
    private readonly Action<byte[]> _sendCallback;

    // Packet tracking
    private readonly SortedDictionary<uint, StreamingPacket> _sentPackets = new();
    private readonly I2PSigningPrivateKey _signingPrivateKey;
    private bool _ackScheduled;
    private Timer _ackTimer;

    // Remote lease tracking for path optimization
    // Matches i2pd's m_CurrentRemoteLease / m_RemoteLeaseChangeTime
    private I2PLease _currentRemoteLease;

    // Choking detection
    private bool _isChoking;
    private bool _isChoking2;
    private bool _isChoking3;
    private bool _isFirstAck = true;
    private bool _synSent;
    private double _jitter = 50;
    private double _jitterAccum;
    private int _jitterDiv;
    private long _lastAckSendTime;
    private DateTime _lastLeaseSetLookupTime = DateTime.MinValue;
    private long _lastLossWindowDropTime;
    private uint _lastReceivedSequence;
    private int _lastWindowDropSize;
    private long _lastWindowDropTime;
    private int _lossCount;
    private double _minRtt = INITIAL_RTT;

    // MTU negotiation
    private int _negotiatedMtu = STREAMING_MTU;
    private int _numResendAttempts;
    private int _pacingTime;
    private uint _previousReceivedSequence;
    private I2PDestination _remoteDestination;
    public I2PDestination RemoteDestination => _remoteDestination;
    private DateTime _remoteLeaseExpiry = DateTime.MinValue;

    // Timers
    private Timer _resendTimer;
    private int _rto = INITIAL_RTO;
    private double _rtt = INITIAL_RTT;

    // Sequence tracking
    private uint _sequenceNumber;
    private double _slowRtt = INITIAL_RTT;
    private StreamStatus _status;
    private int _totalSentForLoss;
    private int _windowDropTargetSize;
    private int _windowIncCounter;

    // Flow control state - full AIMD implementation
    private int _windowSize = INITIAL_WINDOW_SIZE;

    /// <summary>
    ///     Create an outgoing stream
    /// </summary>
    public I2PStream(
        I2PDestination localDestination,
        I2PDestination remoteDestination,
        byte[] localIdentityBytes,
        Action<byte[]> sendCallback,
        I2PSigningPrivateKey signingPrivateKey)
    {
        _localDestination = localDestination;
        _remoteDestination = remoteDestination;
        _localIdentityBytes = localIdentityBytes;
        _sendCallback = sendCallback ?? throw new ArgumentNullException(nameof(sendCallback));
        _signingPrivateKey = signingPrivateKey;
        IsOutgoing = true;
        Status = StreamStatus.New;
        RecvStreamId = BufUtils.RandomUint();
        SendStreamId = 0;
        _lastReceivedSequence = uint.MaxValue;
    }

    /// <summary>
    ///     Create an incoming stream from a received SYN packet
    /// </summary>
    public I2PStream(
        I2PDestination localDestination,
        byte[] localIdentityBytes,
        StreamingPacket synPacket,
        Action<byte[]> sendCallback,
        I2PSigningPrivateKey signingPrivateKey)
    {
        _localDestination = localDestination;
        _localIdentityBytes = localIdentityBytes;
        _sendCallback = sendCallback ?? throw new ArgumentNullException(nameof(sendCallback));
        _signingPrivateKey = signingPrivateKey;
        IsOutgoing = false;
        Status = StreamStatus.New;
        RecvStreamId = BufUtils.RandomUint();
        SendStreamId = synPacket.SendStreamId;
        _lastReceivedSequence = uint.MaxValue;
        HandleNextPacket(synPacket);
    }

    public uint SendStreamId { get; private set; }
    public uint RecvStreamId { get; }

    public StreamStatus Status
    {
        get => _status;
        private set
        {
            if (_status != value)
            {
                _status = value;
                Logging.LogDebug($"I2PStream {RecvStreamId:X8}: Status changed to {_status}");
                StatusChanged?.Invoke(this, _status);
            }
        }
    }

    public bool IsOutgoing { get; }

    /// <summary>
    ///     Statistics: bytes sent and received
    /// </summary>
    public long NumSentBytes { get; private set; }

    public long NumReceivedBytes { get; private set; }

    public void Dispose()
    {
        Terminate();
        _resendTimer?.Dispose();
        _ackTimer?.Dispose();
    }

    // Events — DataReceived buffers payloads that arrive before any handler is
    // attached (common for incoming streams whose SYN carries initial data).
    private Action<I2PStream, byte[]> _dataReceived;
    private readonly ConcurrentQueue<byte[]> _earlyData = new();

    public event Action<I2PStream, byte[]> DataReceived
    {
        add
        {
            _dataReceived += value;
            // Deliver any data that arrived before the handler was attached
            while (_earlyData.TryDequeue(out var buffered))
                value(this, buffered);
        }
        remove => _dataReceived -= value;
    }

    public event Action<I2PStream> StreamClosed;
    public event Action<I2PStream, StreamStatus> StatusChanged;
    public event Action<I2PStream, uint, int> PacketSent;
    public event Action<I2PStream, uint, int> PacketReceived;
    public event Action<I2PStream, I2PDestination> LeaseSetLookupRequired;

    /// <summary>
    ///     Update the current remote lease used for sending.
    ///     Should be called periodically to ensure we're using a non-expired lease.
    /// </summary>
    internal void UpdateCurrentRemoteLease(I2PLease lease)
    {
        if (lease != null)
        {
            _currentRemoteLease = lease;
            _remoteLeaseExpiry = lease.Expire;
        }
    }

    /// <summary>
    ///     Check if the current remote lease needs refreshing.
    ///     Returns true if the lease is expired or about to expire.
    /// </summary>
    public bool NeedsLeaseRefresh()
    {
        if (_currentRemoteLease == null) return true;
        // Refresh if within 30 seconds of expiry or if we have too many resend attempts
        return DateTime.UtcNow.AddSeconds(30) >= _remoteLeaseExpiry || _numResendAttempts > 2;
    }

    /// <summary>
    ///     Request a lease set lookup for the remote destination.
    ///     Rate-limited to avoid excessive lookups.
    /// </summary>
    public bool ShouldLookupLeaseSet()
    {
        if (_remoteDestination == null) return false;
        var now = DateTime.UtcNow;
        if ((now - _lastLeaseSetLookupTime).TotalMilliseconds < LEASE_LOOKUP_INTERVAL_MS)
            return false;
        _lastLeaseSetLookupTime = now;
        return NeedsLeaseRefresh();
    }

    /// <summary>
    ///     Send data over the stream
    /// </summary>
    public void Send(byte[] data)
    {
        if (Status != StreamStatus.Open && Status != StreamStatus.New)
            throw new InvalidOperationException($"Cannot send in state {Status}");
        _sendBuffer.Enqueue(data);
        try
        {
            FlushSendBuffer();
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"I2PStream {RecvStreamId:X8}: FlushSendBuffer FAILED: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
            throw;
        }
    }

    /// <summary>
    ///     Send data asynchronously
    /// </summary>
    public Task SendAsync(byte[] data, CancellationToken ct = default)
    {
        Send(data);
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Handle a received packet for this stream
    /// </summary>
    private readonly object _receiveLock = new();

    public void HandleNextPacket(StreamingPacket packet)
    {
        // Lock the entire receive path — on loopback, multiple garlic messages
        // can arrive concurrently via Task.Run(), and without synchronisation
        // _lastReceivedSequence / _savedPackets / data delivery can race.
        lock (_receiveLock)
        {
            HandleNextPacketLocked(packet);
        }
    }

    private void HandleNextPacketLocked(StreamingPacket packet)
    {
        Logging.LogDebug(
            $"I2PStream {RecvStreamId:X8}: HandleNextPacket: Seq {packet.SequenceNumber} Ack {packet.AckThrough} Flags {packet.Flags}");
        PacketReceived?.Invoke(this, packet.SequenceNumber, packet.Payload.Length);

        if (Status == StreamStatus.Terminated)
            return;

        // Extract SendStreamId from incoming packet if not set yet
        if (SendStreamId == 0 && packet.ReceiveStreamId != 0)
        {
            SendStreamId = packet.SendStreamId;
            Logging.LogDebug($"I2PStream {RecvStreamId:X8}: Handshake: Received remote SendStreamId {SendStreamId:X8}");
        }

        // ReceiveStreamId=0 is allowed for initial SYN packets (the remote doesn't
        // know our RecvStreamId yet).  Java I2P (ConnectionPacketHandler) permits this
        // during connection establishment.  Once both sides have exchanged stream IDs,
        // non-zero mismatches are still rejected.
        if (packet.ReceiveStreamId != 0 && packet.ReceiveStreamId != RecvStreamId)
        {
            Logging.LogWarning(
                $"I2PStream {RecvStreamId:X8}: ReceiveStreamId mismatch! Got {packet.ReceiveStreamId:X8}, expected {RecvStreamId:X8}. Dropping packet.");
            return;
        }

        if (Status == StreamStatus.New && !packet.IsSYN && IsOutgoing)
        {
            Logging.LogWarning($"I2PStream {RecvStreamId:X8}: Dropping non-SYN packet while in New state");
            return;
        }

        // Handle ECHO (ping) packets
        if (packet.IsEcho)
        {
            HandlePing(packet);
            return;
        }

        // Process ACK if present
        if (!packet.IsNoAck)
            ProcessAck(packet);

        var seqn = packet.SequenceNumber;

        // ACK-only packet (seqn 0, no SYN)
        // Note: If _lastReceivedSequence is uint.MaxValue, seqn 0 IS the next expected packet.
        if (seqn == 0 && !packet.IsSYN && _lastReceivedSequence != uint.MaxValue)
            return;

        if (seqn == _lastReceivedSequence + 1)
        {
            // In-sequence packet
            ProcessPacket(packet);

            // Deliver saved out-of-order packets
            while (_savedPackets.Count > 0)
            {
                var nextExpected = _lastReceivedSequence + 1;
                if (_savedPackets.TryGetValue(nextExpected, out var saved))
                {
                    _savedPackets.Remove(nextExpected);
                    ProcessPacket(saved);
                }
                else
                {
                    break;
                }
            }

            // Send ACK immediately — delayed ACKs (ScheduleAck) add latency
            // that throttles throughput, especially on loopback where RTT ≈ 0.
            // The sender's window only opens when ACKs arrive, so every ms of
            // delay directly reduces throughput.
            SendQuickAck();
        }
        else if (seqn > _lastReceivedSequence + 1)
        {
            // Out-of-order - save for later
            _savedPackets[seqn] = packet;
            SendQuickAck(); // Immediate ACK with NACKs for gap
        }
        else if (seqn <= _lastReceivedSequence)
        {
            // Duplicate packet detected
            Logging.LogDebug($"I2PStream: Duplicate packet seq={seqn}, expected>{_lastReceivedSequence}");
            SendQuickAck();
        }
    }

    private void ProcessPacket(StreamingPacket packet)
    {
        if (packet.IsSYN)
            if (Status == StreamStatus.New)
            {
                Status = StreamStatus.Open;
                ParseSynOptions(packet);
            }

        _previousReceivedSequence = _lastReceivedSequence;
        _lastReceivedSequence = packet.SequenceNumber;

        // Deliver payload (decompress gzip if needed)
        if (packet.Payload.Length > 0)
        {
            var payloadData = packet.Payload;

            // Check gzip magic bytes (0x1f 0x8b) for compressed data
            if (payloadData.Length >= 2 && payloadData[0] == 0x1f && payloadData[1] == 0x8b)
                try
                {
                    var decompressed = LzUtils.BcgZipDecompressNew(new I2PByteBlock(payloadData));
                    if (!decompressed.IsEmpty) payloadData = decompressed.ToByteArray();
                }
                catch (Exception)
                {
                    // Decompression failed, use raw payload
                }

            _receiveQueue.Enqueue(packet);
            if (_dataReceived != null)
                _dataReceived.Invoke(this, payloadData);
            else
                _earlyData.Enqueue(payloadData);
        }

        // Handle close/reset flags
        if (packet.IsReset)
        {
            Status = StreamStatus.Reset;
            Terminate();
        }
        else if (packet.IsClose)
        {
            SendCloseAck();
            Status = StreamStatus.Closed;
            Terminate();
        }
    }

    /// <summary>
    ///     Parse options from a SYN packet (identity, max packet size, etc.)
    ///     Option order must match Java I2P's Packet.writePacket():
    ///       DELAY_REQUESTED → FROM_INCLUDED → MAX_PACKET_SIZE → OFFLINE_SIGNATURE → SIGNATURE
    /// </summary>
    private void ParseSynOptions(StreamingPacket packet)
    {
        if (packet.OptionData == null || packet.OptionData.Length == 0) return;

        var offset = 0;
        var opts = packet.OptionData;
        var flags = packet.Flags;

        // DELAY_REQUESTED: 2-byte delay value (comes BEFORE FROM in Java I2P)
        if ((flags & StreamingPacket.FLAG_DELAY_REQUESTED) != 0 && offset + 2 <= opts.Length)
            offset += 2; // skip the 2-byte delay value; we don't use it

        // FROM_INCLUDED: remote identity
        if ((flags & StreamingPacket.FLAG_FROM_INCLUDED) != 0 && offset < opts.Length)
            try
            {
                var startRef = new I2PBufferCursor(opts, offset);
                var reader = new I2PBufferCursor(opts, offset);
                _remoteDestination = new I2PDestination(reader);
                offset += reader.DistanceFrom(startRef);
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PStream: Failed to parse FROM: {ex.Message}");
            }

        // MAX_PACKET_SIZE_INCLUDED
        if ((flags & StreamingPacket.FLAG_MAX_PACKET_SIZE_INCLUDED) != 0 && offset + 2 <= opts.Length)
        {
            _negotiatedMtu = (opts[offset] << 8) | opts[offset + 1];
            offset += 2;
        }

        // OFFLINE_SIGNATURE: process offline/transient signing key
        I2PSigningPublicKey transientKey = null;
        if ((flags & StreamingPacket.FLAG_OFFLINE_SIGNATURE) != 0 && _remoteDestination != null)
            try
            {
                var startRef = new I2PBufferCursor(opts, offset);
                var reader = new I2PBufferCursor(opts, offset);
                var offlineSig = new I2POfflineSignature(reader, _remoteDestination.Certificate);

                // Verify the offline signature: it signs (expires + sigType + transientKey)
                // using the destination's long-term signing key
                var signedData = new ArrayBufferWriter<byte>();
                offlineSig.Expires.Write(signedData);
                signedData.Write(BufUtils.Flip16B((ushort)offlineSig.SignatureType));
                offlineSig.TransientPublicKey.Write(signedData);
                var signedBytes = signedData.WrittenSpan.ToArray();

                var offlineVerified = I2PSignature.DoVerify(
                    _remoteDestination.SigningPublicKey,
                    offlineSig.Signature,
                    new I2PByteBlock(signedBytes));

                if (offlineVerified)
                {
                    transientKey = offlineSig.TransientPublicKey;
                    offset = reader.DistanceFrom(startRef) + offset;
                    Logging.LogDebug("I2PStream: Offline signature verified, using transient key");
                }
                else
                {
                    Logging.LogWarning("I2PStream: Offline signature verification failed");
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PStream: Failed to parse offline signature: {ex.Message}");
            }

        // SIGNATURE_INCLUDED: verify the packet signature
        if ((flags & StreamingPacket.FLAG_SIGNATURE_INCLUDED) != 0 && _remoteDestination != null)
            try
            {
                var verifyKey = transientKey ?? _remoteDestination.SigningPublicKey;
                var sigLen = verifyKey.Certificate.SignatureLength;

                if (offset + sigLen <= opts.Length)
                {
                    // Extract the signature bytes from options
                    var sigBytes = new byte[sigLen];
                    Array.Copy(opts, offset, sigBytes, 0, sigLen);

                    // Zero out signature in options for verification
                    // (signature covers entire packet with signature field zeroed)
                    Array.Clear(opts, offset, sigLen);

                    // Rebuild packet bytes for verification
                    var packetBytes = packet.ToByteArray();

                    // Restore signature in options
                    Array.Copy(sigBytes, 0, opts, offset, sigLen);

                    var sig = new I2PSignature
                    {
                        Sig = new I2PByteBlock(sigBytes),
                        Certificate = verifyKey.Certificate
                    };

                    var verified = I2PSignature.DoVerify(
                        verifyKey,
                        sig,
                        new I2PByteBlock(packetBytes));

                    if (!verified)
                        Logging.LogWarning($"I2PStream: Signature verification failed for stream {SendStreamId:X8}");
                    else
                        Logging.LogDebug("I2PStream: Packet signature verified");

                    offset += sigLen;
                }
                else
                {
                    Logging.LogWarning("I2PStream: Signature data truncated in options");
                }
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"I2PStream: Signature verification error: {ex.Message}");
            }
    }

    /// <summary>
    ///     Handle a ping (ECHO) packet by sending a pong response.
    /// </summary>
    private void HandlePing(StreamingPacket packet)
    {
        var pong = new StreamingPacket
        {
            SendStreamId = RecvStreamId,
            ReceiveStreamId = SendStreamId,
            SequenceNumber = 0,
            AckThrough = _lastReceivedSequence,
            Flags = StreamingPacket.FLAG_ECHO | StreamingPacket.FLAG_NO_ACK
        };
        _sendCallback(pong.ToByteArray());
    }

    // --- Congestion Control (AIMD with slow start) ---

    private void ProcessAck(StreamingPacket packet)
    {
        var ackThrough = packet.AckThrough;
        Logging.LogDebug($"I2PStream {RecvStreamId:X8}: ProcessAck: {ackThrough}");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var anyAcked = false;
        var numAcked = 0;

        // Remove ACKed packets
        var toRemove = _sentPackets.Keys.Where(k => k <= ackThrough).ToList();
        foreach (var key in toRemove)
        {
            if (_sentPackets.TryGetValue(key, out var ackedPkt))
            {
                // RTT sample from non-resent packets only
                if (!ackedPkt.Resent && ackedPkt.SendTime > 0 && !_isFirstAck)
                {
                    var rttSample = (int)(now - ackedPkt.SendTime);
                    UpdateRTT(rttSample);
                }

                anyAcked = true;
                numAcked++;
            }

            _sentPackets.Remove(key);
            _nackedPackets.Remove(key);
        }

        if (_isFirstAck && anyAcked)
            _isFirstAck = false;

        // Process NACKs
        var hasNacks = false;
        foreach (var nack in packet.NACKs)
            if (_sentPackets.ContainsKey(nack))
            {
                _nackedPackets.Add(nack);
                hasNacks = true;
            }

        // Adjust window (AIMD with optional loss-based control)
        if (anyAcked)
        {
            _numResendAttempts = 0; // Reset on successful ACK

            // Loss-based congestion control: track loss rate over recent packets
            if (LOSS_BASED_CONTROL_ENABLED)
            {
                _totalSentForLoss += numAcked;
                if (hasNacks) _lossCount += packet.NACKs.Count;

                // Check loss rate periodically (every ~50 packets)
                if (_totalSentForLoss >= 50)
                {
                    var lossRate = (double)_lossCount / _totalSentForLoss;
                    if (lossRate > LOSS_RATE_THRESHOLD)
                    {
                        // Loss rate exceeded threshold - reduce window
                        var now2 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (now2 - _lastLossWindowDropTime > (long)_rtt)
                        {
                            _lastLossWindowDropTime = now2;
                            _windowSize = Math.Max(MIN_WINDOW_SIZE,
                                (int)(_windowSize * (1.0 - lossRate)));
                            _windowIncCounter = 0;
                            UpdatePacingTime();
                        }
                    }

                    _lossCount = 0;
                    _totalSentForLoss = 0;
                }
            }

            if (!hasNacks)
                // Increase window: slow start then congestion avoidance
                WindowIncrease(numAcked);
            else
                // Loss detected via NACKs: multiplicative decrease
                ProcessWindowDrop();

            FlushSendBuffer();
        }

        // Parse DELAY_REQUESTED option for choking detection
        if ((packet.Flags & StreamingPacket.FLAG_DELAY_REQUESTED) != 0 && packet.OptionData != null)
            if (packet.OptionData.Length >= 2)
            {
                var delay = (ushort)((packet.OptionData[0] << 8) | packet.OptionData[1]);
                DetectChoking(delay);
            }

        // Schedule fast retransmit for NACKed packets
        if (hasNacks)
            ScheduleResend();
    }

    /// <summary>
    ///     Window increase logic - slow start until half of last drop,
    ///     then congestion avoidance (linear increase).
    /// </summary>
    private void WindowIncrease(int numAcked)
    {
        if (_windowSize >= MAX_WINDOW_SIZE) return;

        var ssThresh = _windowDropTargetSize > 0 ? _windowDropTargetSize : MAX_WINDOW_SIZE;

        if (_windowSize < ssThresh)
        {
            // Slow start: increase by 1 for each ACK (exponential growth)
            _windowSize = Math.Min(_windowSize + numAcked, MAX_WINDOW_SIZE);
        }
        else
        {
            // Congestion avoidance: increase by 1/windowSize per ACK
            _windowIncCounter += numAcked;
            if (_windowIncCounter >= _windowSize)
            {
                _windowSize = Math.Min(_windowSize + 1, MAX_WINDOW_SIZE);
                _windowIncCounter -= _windowSize;
            }
        }
    }

    /// <summary>
    ///     Multiplicative decrease on packet loss.
    ///     Window = max(MIN_WINDOW_SIZE, window / 2)
    /// </summary>
    private void ProcessWindowDrop()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Avoid multiple drops within one RTT
        if (now - _lastWindowDropTime < (long)_rtt)
            return;

        _lastWindowDropSize = _windowSize;
        _lastWindowDropTime = now;

        // Target is between current and half
        _windowDropTargetSize = Math.Max(MIN_WINDOW_SIZE, _windowSize / 2);
        _windowSize = _windowDropTargetSize;
        _windowIncCounter = 0;

        UpdatePacingTime();
    }

    /// <summary>
    ///     Reset window to initial size (e.g., on timeout).
    /// </summary>
    private void ResetWindowSize()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        if (_lastWindowDropSize > 0)
        {
            // Gradually recover based on time since last drop
            double timeSinceDrop = now - _lastWindowDropTime;
            var recoveryTime = _rtt * _lastWindowDropSize * PREV_SPEED_KEEP_TIME_COEFF;
            if (timeSinceDrop < recoveryTime)
            {
                _windowDropTargetSize = (int)(_lastWindowDropSize * timeSinceDrop / recoveryTime);
                _windowDropTargetSize = Math.Max(MIN_WINDOW_SIZE, _windowDropTargetSize);
            }
            else
            {
                _windowDropTargetSize = _lastWindowDropSize;
            }
        }

        _windowSize = MIN_WINDOW_SIZE;
        _windowIncCounter = 0;
        _lastWindowDropSize = _windowSize;
        _lastWindowDropTime = now;

        UpdatePacingTime();
    }

    /// <summary>
    ///     Update pacing time based on current window and RTT.
    /// </summary>
    private void UpdatePacingTime()
    {
        if (_windowSize > 0)
            _pacingTime = Math.Max(SEND_INTERVAL, (int)(_rtt * 1000 / _windowSize));
    }

    /// <summary>
    ///     EWMA RTT update with jitter tracking.
    /// </summary>
    private void UpdateRTT(int rttSample)
    {
        if (rttSample <= 0) return;

        // EWMA: rtt = alpha * sample + (1-alpha) * rtt
        _rtt = RTT_EWMA_ALPHA * rttSample + (1.0 - RTT_EWMA_ALPHA) * _rtt;
        _slowRtt = SLOWRTT_EWMA_ALPHA * rttSample + (1.0 - SLOWRTT_EWMA_ALPHA) * _slowRtt;

        if (rttSample < _minRtt) _minRtt = rttSample;

        // Jitter with accumulator for smoother tracking
        var dev = Math.Abs(rttSample - _rtt);
        _jitterAccum += dev;
        _jitterDiv++;
        if (_jitterDiv >= 4)
        {
            _jitter = _jitterAccum / _jitterDiv;
            _jitterAccum = 0;
            _jitterDiv = 0;
        }

        // RTO = RTT + max(50, 4 * jitter)
        _rto = Math.Max(MIN_RTO, (int)(_rtt + Math.Max(50, _jitter * 4)));
    }

    /// <summary>
    ///     Detect choking from peer's DELAY_REQUESTED value.
    /// </summary>
    private void DetectChoking(ushort delay)
    {
        _isChoking = delay >= DELAY_CHOKING;
        _isChoking2 = delay >= DELAY_CHOKING_2;
        _isChoking3 = delay >= DELAY_CHOKING_3;
    }

    private void FlushSendBuffer()
    {
        var available = _windowSize - _sentPackets.Count;
        if (available <= 0)
        {
            Logging.LogDebug(
                $"I2PStream {RecvStreamId:X8}: Window full (size {_windowSize}, sent {_sentPackets.Count})");
            return;
        }

        while (available > 0 && _sendBuffer.TryDequeue(out var data))
        {
            Logging.LogDebug(
                $"I2PStream {RecvStreamId:X8}: Dequeued {data.Length} bytes for sending. available {available}");
            var offset = 0;
            var mtu = _negotiatedMtu;
            while (offset < data.Length && available > 0)
            {
                var chunkSize = Math.Min(data.Length - offset, mtu);
                var payload = new byte[chunkSize];
                Array.Copy(data, offset, payload, 0, chunkSize);

                // Gzip compress payloads above threshold (i2pd compatibility)
                if (payload.Length >= COMPRESSION_THRESHOLD_SIZE)
                    try
                    {
                        var compressed = LzUtils.BcgZipCompressNew(new I2PByteBlock(payload));
                        if (!compressed.IsEmpty && compressed.Length < payload.Length)
                            payload = compressed.ToByteArray();
                    }
                    catch (Exception)
                    {
                        // Compression failed, send uncompressed
                    }

                var pkt = BuildDataPacket(payload);
                Logging.LogDebug(
                    $"I2PStream {RecvStreamId:X8}: Built data packet seq {pkt.SequenceNumber} payload {pkt.Payload.Length} bytes");
                SendPacket(pkt);
                available--;
                offset += chunkSize;
            }
        }
    }

    private StreamingPacket BuildDataPacket(byte[] payload)
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = RecvStreamId,
            ReceiveStreamId = SendStreamId,
            SequenceNumber = _sequenceNumber++,
            AckThrough = _lastReceivedSequence,
            ResendDelay = (byte)Math.Min(255, _rto / 1000),
            Payload = payload
        };

        if (pkt.SequenceNumber == 0)
        {
            _synSent = true;
            SetSynOptions(pkt);
        }
        else if (_sentPackets.Count >= _windowSize / 2)
        {
            // Request immediate ACK when window is half consumed
            pkt.Flags |= StreamingPacket.FLAG_DELAY_REQUESTED;
            pkt.OptionData = new byte[2]; // delay=0 means immediate
        }

        return pkt;
    }

    private void SendPacket(StreamingPacket pkt)
    {
        pkt.SendTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        _sentPackets[pkt.SequenceNumber] = pkt;

        var bytes = pkt.ToByteArray();
        Logging.LogDebug(
            $"I2PStream {RecvStreamId:X8}: Calling sendCallback for pkt seq {pkt.SequenceNumber} ({bytes.Length} bytes). SendStreamId: {pkt.SendStreamId:X8}, ReceiveStreamId: {pkt.ReceiveStreamId:X8}, AckThrough: {pkt.AckThrough}, Flags: {pkt.Flags:X4}");
        _sendCallback(bytes);
        PacketSent?.Invoke(this, pkt.SequenceNumber, bytes.Length);

        if (_resendTimer == null)
            ScheduleResend();
    }

    private List<uint> GetCurrentNacks()
    {
        var nacks = new List<uint>();
        if (_savedPackets.Count > 0)
        {
            var expected = _lastReceivedSequence + 1;
            foreach (var saved in _savedPackets.Keys.OrderBy(k => k))
            {
                while (expected < saved && nacks.Count < 255)
                {
                    nacks.Add(expected);
                    expected++;
                }

                expected = saved + 1;
            }
        }

        return nacks;
    }

    private void SendQuickAck()
    {
        var isSyn = !_synSent;

        var ack = new StreamingPacket
        {
            SendStreamId = RecvStreamId,
            ReceiveStreamId = SendStreamId,
            // SYN packets consume a sequence number (the responder's seq 0).
            // Pure ACK-only packets always use seq 0 without consuming it.
            // Without this, BuildDataPacket would also produce seq 0 and the
            // receiver would drop the first data packet as a duplicate.
            SequenceNumber = isSyn ? _sequenceNumber++ : 0,
            AckThrough = _lastReceivedSequence,
            Flags = 0
        };

        if (isSyn)
        {
            _synSent = true;
            SetSynOptions(ack);
            Logging.LogDebug(
                $"I2PStream {RecvStreamId:X8}: Sending SYN+ACK: Send={ack.SendStreamId:X8}, " +
                $"Recv={ack.ReceiveStreamId:X8}, AckThrough={ack.AckThrough}, " +
                $"Flags={ack.Flags:X4}, OptionLen={ack.OptionData?.Length ?? 0}");
        }
        else
        {
            SignPacket(ack);
        }

        // Generate NACKs for gaps in received sequence
        if (_savedPackets.Count > 0)
        {
            var nacks = new List<uint>();
            var expected = _lastReceivedSequence + 1;
            foreach (var saved in _savedPackets.Keys.OrderBy(k => k))
            {
                while (expected < saved && nacks.Count < 255)
                {
                    nacks.Add(expected);
                    expected++;
                }

                expected = saved + 1;
            }

            ack.NACKs = nacks;
        }

        _sendCallback(ack.ToByteArray());
        _lastAckSendTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        _ackScheduled = false;
    }

    private void SendCloseAck()
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = RecvStreamId,
            ReceiveStreamId = SendStreamId,
            SequenceNumber = _sequenceNumber++,
            AckThrough = _lastReceivedSequence,
            Flags = StreamingPacket.FLAG_CLOSE
        };

        if (!_synSent)
        {
            _synSent = true;
            SetSynOptions(pkt);
        }
        else
        {
            SignPacket(pkt);
        }

        _sendCallback(pkt.ToByteArray());
    }

    private void SendReset()
    {
        var pkt = new StreamingPacket
        {
            SendStreamId = RecvStreamId,
            ReceiveStreamId = SendStreamId,
            SequenceNumber = _sequenceNumber++,
            AckThrough = _lastReceivedSequence,
            Flags = StreamingPacket.FLAG_RESET
        };

        if (!_synSent)
        {
            _synSent = true;
            SetSynOptions(pkt);
        }
        else
        {
            SignPacket(pkt);
        }

        _sendCallback(pkt.ToByteArray());
    }

    /// <summary>
    ///     Sign a packet by appending a signature to its options.
    ///     The signature covers the entire serialized packet with the signature
    ///     field zeroed out, matching the i2pd reference behavior.
    /// </summary>
    private void SetSynOptions(StreamingPacket pkt)
    {
        pkt.Flags |= StreamingPacket.FLAG_SYNCHRONIZE;
        pkt.Flags |= StreamingPacket.FLAG_FROM_INCLUDED;
        pkt.Flags |= StreamingPacket.FLAG_MAX_PACKET_SIZE_INCLUDED;

        var optStream = new ArrayBufferWriter<byte>();
        if (_localIdentityBytes != null)
            optStream.Write(_localIdentityBytes);
        optStream.Write(BufUtils.Flip16B(STREAMING_MTU));

        if (_signingPrivateKey != null)
        {
            pkt.Flags |= StreamingPacket.FLAG_SIGNATURE_INCLUDED;
            var sigLen = _signingPrivateKey.Certificate.SignatureLength;

            // Write zeroed signature placeholder into options
            var sigPlaceholder = new byte[sigLen];
            optStream.Write(sigPlaceholder);
            pkt.OptionData = optStream.WrittenSpan.ToArray();

            // Serialize the full packet (with zeroed signature) and sign it
            var packetBytes = pkt.ToByteArray();
            var signature = I2PSignature.DoSign(
                _signingPrivateKey,
                new I2PByteBlock(packetBytes));

            // Patch the signature into the option data
            var sigOffset = pkt.OptionData.Length - sigLen;
            Array.Copy(signature, 0, pkt.OptionData, sigOffset, sigLen);
        }
        else
        {
            pkt.OptionData = optStream.WrittenSpan.ToArray();
        }
    }

    private void SignPacket(StreamingPacket pkt)
    {
        if (_signingPrivateKey == null) return;

        var sigLen = _signingPrivateKey.Certificate.SignatureLength;

        // If signature already present, reuse space. Otherwise append.
        if ((pkt.Flags & StreamingPacket.FLAG_SIGNATURE_INCLUDED) == 0)
        {
            pkt.Flags |= StreamingPacket.FLAG_SIGNATURE_INCLUDED;
            var existingOpts = pkt.OptionData ?? Array.Empty<byte>();
            var newOpts = new byte[existingOpts.Length + sigLen];
            Array.Copy(existingOpts, 0, newOpts, 0, existingOpts.Length);
            pkt.OptionData = newOpts;
        }

        // Zero out signature placeholder for re-signing
        var sigOffset = pkt.OptionData.Length - sigLen;
        for (var i = 0; i < sigLen; i++) pkt.OptionData[sigOffset + i] = 0;

        // Serialize the full packet with zeroed signature, then sign
        var packetBytes = pkt.ToByteArray();
        var signature = I2PSignature.DoSign(
            _signingPrivateKey,
            new I2PByteBlock(packetBytes));

        // Patch signature into options
        Array.Copy(signature, 0, pkt.OptionData, sigOffset, sigLen);
    }

    private void ScheduleAck()
    {
        if (_ackScheduled) return;
        _ackScheduled = true;

        var delay = Math.Max(MIN_SEND_ACK_TIMEOUT, (int)(_rtt / 10));
        _ackTimer?.Dispose();
        _ackTimer = new Timer(_ =>
        {
            _ackScheduled = false;
            SendQuickAck();
        }, null, delay, Timeout.Infinite);
    }

    private void ScheduleResend()
    {
        _resendTimer?.Dispose();
        _resendTimer = new Timer(_ => HandleResendTimer(), null, _rto, Timeout.Infinite);
    }

    private void HandleResendTimer()
    {
        if (Status == StreamStatus.Terminated) return;

        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var toResend = new List<StreamingPacket>();

        // Fast retransmit: check NACKed packets first
        foreach (var seqn in _nackedPackets.ToList())
            if (_sentPackets.TryGetValue(seqn, out var pkt))
                if (now - pkt.SendTime >= _rto)
                {
                    Logging.LogDebug($"I2PStream {RecvStreamId:X8}: Fast retransmit seq {seqn} (NACKed)");

                    // Update ACK info before re-sending
                    pkt.ReceiveStreamId = SendStreamId;
                    pkt.AckThrough = _lastReceivedSequence;
                    pkt.NACKs = GetCurrentNacks();

                    if (pkt.HasSignature && _signingPrivateKey != null)
                    {
                        // Signature covers entire packet with signature field zeroed
                        var sigLen = _signingPrivateKey.Certificate.SignatureLength;
                        var sigOffset = pkt.OptionData.Length - sigLen;
                        var sigBytes = new byte[sigLen];
                        Array.Copy(pkt.OptionData, sigOffset, sigBytes, 0, sigLen);
                        Array.Clear(pkt.OptionData, sigOffset, sigLen);

                        var packetBytes = pkt.ToByteArray();
                        var signature = I2PSignature.DoSign(_signingPrivateKey, new I2PByteBlock(packetBytes));
                        Array.Copy(signature, 0, pkt.OptionData, sigOffset, sigLen);
                    }

                    pkt.Resent = true;
                    pkt.SendTime = now;
                    toResend.Add(pkt);
                }

        // Timeout-based retransmit: only one packet per RTO (RFC compliance)
        if (toResend.Count == 0 && _sentPackets.Count > 0)
        {
            var oldest = _sentPackets.Values.First();
            if (now - oldest.SendTime >= _rto)
            {
                Logging.LogDebug(
                    $"I2PStream {RecvStreamId:X8}: Timeout retransmit seq {oldest.SequenceNumber}. attempts {_numResendAttempts}");
                _numResendAttempts++;

                if (_numResendAttempts >= 3 && ShouldLookupLeaseSet())
                {
                    Logging.LogInformation($"I2PStream {RecvStreamId:X8}: Too many retransmissions, triggering LeaseSet lookup for {_remoteDestination?.IdentHash.Id32Short}");
                    LeaseSetLookupRequired?.Invoke(this, _remoteDestination);
                }

                // Update ACK info before re-sending
                oldest.ReceiveStreamId = SendStreamId;
                oldest.AckThrough = _lastReceivedSequence;
                oldest.NACKs = GetCurrentNacks();

                if (oldest.HasSignature && _signingPrivateKey != null)
                {
                    // Signature covers entire packet with signature field zeroed
                    var sigLen = _signingPrivateKey.Certificate.SignatureLength;
                    var sigOffset = oldest.OptionData.Length - sigLen;
                    var sigBytes = new byte[sigLen];
                    Array.Copy(oldest.OptionData, sigOffset, sigBytes, 0, sigLen);
                    Array.Clear(oldest.OptionData, sigOffset, sigLen);

                    var packetBytes = oldest.ToByteArray();
                    var signature = I2PSignature.DoSign(_signingPrivateKey, new I2PByteBlock(packetBytes));
                    Array.Copy(signature, 0, oldest.OptionData, sigOffset, sigLen);
                }

                if (_numResendAttempts > MAX_NUM_RESEND_ATTEMPTS)
                {
                    // Too many retries - send reset and terminate
                    SendReset();
                    Status = StreamStatus.Reset;
                    Terminate();
                    return;
                }

                oldest.Resent = true;
                oldest.SendTime = now;
                toResend.Add(oldest);

                // Timeout means congestion: reset window
                ResetWindowSize();

                // Double RTO (exponential backoff)
                _rto = Math.Min(_rto * 2, INITIAL_RTO * 4);
            }
        }

        // Send retransmissions
        foreach (var pkt in toResend)
        {
            // Update fields for retransmission to include latest ACK info
            pkt.ReceiveStreamId = SendStreamId;
            pkt.AckThrough = _lastReceivedSequence;
            pkt.NACKs = GetCurrentNacks();

            // Re-sign if necessary as we modified the header
            if (pkt.HasSignature)
                SignPacket(pkt);

            _sendCallback(pkt.ToByteArray());
        }

        // Reschedule if still have unacked packets
        if (_sentPackets.Count > 0)
            ScheduleResend();
    }

    /// <summary>
    ///     Gracefully close the stream
    /// </summary>
    public void Close()
    {
        switch (Status)
        {
            case StreamStatus.Open:
                Status = StreamStatus.Closing;
                if (_sentPackets.Count == 0 && _sendBuffer.IsEmpty)
                {
                    SendCloseAck();
                    Status = StreamStatus.Closed;
                    // Wait briefly for final ACK before terminating
                    _resendTimer?.Dispose();
                    _resendTimer = new Timer(_ => Terminate(), null, _rto * 2, Timeout.Infinite);
                }

                break;

            case StreamStatus.Closing:
                if (_sentPackets.Count == 0 && _sendBuffer.IsEmpty)
                {
                    SendCloseAck();
                    Status = StreamStatus.Closed;
                    _resendTimer?.Dispose();
                    _resendTimer = new Timer(_ => Terminate(), null, _rto * 2, Timeout.Infinite);
                }

                break;

            case StreamStatus.Reset:
            case StreamStatus.Closed:
            case StreamStatus.New:
                Terminate();
                break;
        }
    }

    /// <summary>
    ///     Force-terminate the stream and release resources
    /// </summary>
    public void Terminate()
    {
        if (Status == StreamStatus.Terminated) return;

        Status = StreamStatus.Terminated;
        _resendTimer?.Dispose();
        _ackTimer?.Dispose();
        _sentPackets.Clear();
        _savedPackets.Clear();
        _nackedPackets.Clear();

        StreamClosed?.Invoke(this);
    }
}

/// <summary>
///     Helper class for I2PBufferCursor that provides the base offset.
///     Used internally for tracking parse position in SYN options.
/// </summary>
internal class BufRefArray
{
    private readonly I2PBufferCursor _cursor;

    public BufRefArray(byte[] data, int offset)
    {
        _cursor = new I2PBufferCursor(data, offset);
        BaseOffset = offset;
    }

    public int BaseOffset { get; }
    public byte[] BaseArray => _cursor.BaseArray;
    public int BaseArrayOffset => _cursor.BaseArrayOffset;
    public int Position => _cursor.Position;
    public int Remaining => _cursor.Remaining;

    public byte ReadByte()
    {
        return _cursor.ReadByte();
    }

    public ushort ReadUInt16BigEndian()
    {
        return _cursor.ReadUInt16BigEndian();
    }

    public uint ReadUInt32BigEndian()
    {
        return _cursor.ReadUInt32BigEndian();
    }

    public byte[] ReadBytes(int count)
    {
        return _cursor.ReadBytes(count);
    }

    public I2PByteBlock ReadBlock(int length)
    {
        return _cursor.ReadBlock(length);
    }

    public int Seek(int offset)
    {
        return _cursor.Seek(offset);
    }
}