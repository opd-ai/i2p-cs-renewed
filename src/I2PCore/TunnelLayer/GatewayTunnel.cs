using System.Collections.Generic;
using System.Linq;
using I2PCore.Data;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace I2PCore.TunnelLayer;

public class GatewayTunnel : InboundTunnel
{
    protected readonly I2PIdentHash NextHop;
    public override I2PIdentHash Destination => NextHop;

    /// <summary>
    ///     Gateways accept from any peer, so this is typically null.
    /// </summary>
    public I2PIdentHash ReceiveFrom { get; internal set; }

    public override bool Established
    {
        get => true;
        set => base.Established = value;
    }

    internal I2PTunnelId SendTunnelId;
    private readonly I2PByteBlock IvKey;
    private readonly I2PByteBlock LayerKey;

    internal BandwidthLimiter Limiter;

    private readonly PeriodicAction PreTunnelDataBatching = new(TickSpan.Milliseconds(500));

    public GatewayTunnel(ITunnelOwner owner, TunnelConfig config, BuildRequestRecord brrec)
        : base(owner, config, 1)
    {
        Limiter = new BandwidthLimiter(Bandwidth.SendBandwidth, TunnelSettings.GatewayTunnelBitrateLimit);

        ReceiveTunnelId = new I2PTunnelId(brrec.ReceiveTunnel);
        SendTunnelId = new I2PTunnelId(brrec.NextTunnel);

        NextHop = new I2PIdentHash(new I2PBufferCursor(brrec.NextIdent.Hash.Clone()));
        IvKey = brrec.IvKey.Clone();
        LayerKey = brrec.LayerKey.Clone();
    }

    public override IEnumerable<I2PRouterIdentity> TunnelMembers => Enumerable.Empty<I2PRouterIdentity>();

    public override bool Exectue()
    {
        var ok = true;

        PreTunnelDataBatching.Do(() => { ok = HandleReceiveQueue(); });

        return ok;
    }

    private bool HandleSendQueue()
    {
        return false;
    }

#if LOG_ALL_TUNNEL_TRANSFER
        ItemFilterWindow<HashedItemGroup> FilterMessageTypes =
 new ItemFilterWindow<HashedItemGroup>( TickSpan.Seconds( 30 ), 2 );
#endif

    private new bool HandleReceiveQueue()
    {
        I2NpMessage[] messages = null;

        if (ReceiveQueue.IsEmpty) return true;

        var msgs = new List<I2NpMessage>();
        var dropped = 0;
        while (ReceiveQueue.TryDequeue(out var msg))
        {
            if (Limiter.DropMessage())
            {
                ++dropped;
                continue;
            }

            msgs.Add(msg);
        }

        messages = msgs.ToArray();

#if LOG_ALL_TUNNEL_TRANSFER
            if ( dropped > 0 )
            {
                if ( FilterMessageTypes.Update( new HashedItemGroup( Destination, 0x63e9 ) ) )
                {
                    Logging.LogDebug( $"{this} bandwidth limit. {dropped} dropped messages. {Bandwidth}" );
                }
            }
#endif

        if (messages == null || messages.Length == 0) return true;

        var tdata = TunnelDataMessage.MakeFragments(
            messages.Select(msg => new TunnelMessageLocal(msg))
            , SendTunnelId);

        EncryptTunnelMessages(tdata);

#if LOG_ALL_TUNNEL_TRANSFER
            if ( FilterMessageTypes.Update( new HashedItemGroup( Destination, 0x17f3 ) ) )
            {
                Logging.Log( $"GatewayTunnel {Destination.Id32Short}: TunnelData sent." );
            }
#endif
        foreach (var tdmsg in tdata)
        {
            TransportProvider.Send(Destination, tdmsg);
            Bandwidth.DataSent(tdmsg.Payload.Length);
            //Logging.LogDebug( $"{this} {Destination.Id32Short}: TDM len {tdmsg.Payload.Length}." );
        }

        return true;
    }

    private void EncryptTunnelMessages(IEnumerable<TunnelDataMessage> msgs)
    {
        var cipher = new CbcBlockCipher(new AesEngine());

        foreach (var msg in msgs)
        {
            msg.Iv.AesEcbEncrypt(IvKey);
            cipher.Encrypt(LayerKey, msg.Iv, msg.EncryptedWindow);
            msg.Iv.AesEcbEncrypt(IvKey);
        }
    }
}