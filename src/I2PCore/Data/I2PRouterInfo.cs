using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Utils;

namespace I2PCore.Data;

public class I2PRouterInfo : I2PType
{
    private readonly I2PByteBlock Data;
    public I2PRouterAddress[] Addresses;
    public I2PRouterIdentity Identity;
    public I2PMapping Options;
    public I2PDate PublishedDate;
    public I2PSignature Signature;

    public I2PRouterInfo(
        I2PRouterIdentity identity,
        I2PDate publisheddate,
        I2PRouterAddress[] addresses,
        I2PMapping options,
        I2PSigningPrivateKey privskey)
    {
        Identity = identity;
        PublishedDate = publisheddate;
        Addresses = addresses;
        Options = options;

        var dest = new ArrayBufferWriter<byte>();
        Identity.Write(dest);
        PublishedDate.Write(dest);
        dest.WriteByte((byte)Addresses.Length);
        foreach (var addr in Addresses) addr.Write(dest);
        dest.WriteByte(0); // Always zero
        Options.Write(dest);
        Data = new I2PByteBlock(dest.WrittenSpan.ToArray());

        Signature = new I2PSignature(new I2PBufferCursor(I2PSignature.DoSign(privskey, Data)), privskey.Certificate);
    }

    public I2PRouterInfo(I2PBufferCursor reader, bool verifysig)
    {
        var startPos = reader.Position;

        Identity = new I2PRouterIdentity(reader);
        PublishedDate = new I2PDate(reader);

        int addrcount = reader.ReadByte();
        var addresses = new List<I2PRouterAddress>();
        for (var i = 0; i < addrcount; ++i) addresses.Add(new I2PRouterAddress(reader));
        Addresses = addresses.ToArray();

        reader.Seek(reader.ReadByte() * 32); // peer_size. Unused.

        Options = new I2PMapping(reader);

        Data = reader.BlockSince(startPos);
        Signature = new I2PSignature(reader, Identity.Certificate);

        if (verifysig)
        {
            var versig = VerifySignature();
            if (!versig) throw new InvalidOperationException("I2PRouterInfo signature check failed");
        }
    }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteBlock(Data);
        Signature.Write(dest);
    }

    public bool VerifySignature()
    {
        var versig = I2PSignature.SupportedSignatureType(Identity.Certificate.SignatureType);

        if (!versig)
        {
            Logging.LogDebug("RouterInfo: VerifySignature false. Not supported: " + Identity.Certificate.SignatureType);
            return false;
        }

        versig = I2PSignature.DoVerify(Identity.SigningPublicKey, Signature, Data);
        if (!versig)
        {
            Logging.LogDebug("RouterInfo: I2PSignature.DoVerify failed: " + Identity.Certificate.SignatureType);
            return false;
        }

        return true;
    }

    /// <summary>
    ///     Get the X25519 public key for ECIES communication (garlic, tunnel builds, etc).
    ///     Per Proposal 152:
    ///     For ECIES routers, this is the identity key.
    ///     Handles hybrid PQ keys by extracting the X25519 component.
    /// </summary>
    public byte[] GetECIESPublicKey()
    {
        var pubkey = Identity.PublicKey.ToByteArray();
        var keyType = Identity.Certificate.PublicKeyType;

        if (pubkey.Length == 32 && keyType == I2PKeyType.KeyTypes.X25519)
            return pubkey;

        if (keyType == I2PKeyType.KeyTypes.MLKEM512_X25519 ||
            keyType == I2PKeyType.KeyTypes.MLKEM768_X25519 ||
            keyType == I2PKeyType.KeyTypes.MLKEM1024_X25519)
            return pubkey.Skip(pubkey.Length - 32).Take(32).ToArray();

        return null;
    }

    public override string ToString()
    {
        var result = new StringBuilder();

        result.AppendLine("I2PRouterInfo");

        result.AppendLine("Identity     : " + Identity.IdentHash.Id32);
        result.AppendLine("Identity     : " + Identity);
        result.AppendLine("Publish date : " + PublishedDate);

        foreach (var addr in Addresses) result.AppendLine("Address      : " + addr);

        result.AppendLine(Options.ToString());
        if (Signature == null)
            result.AppendLine("Signature    : member (null)");
        else
            result.AppendLine("Signature    : " +
                              (Signature.Sig.IsEmpty ? "(null)" : " [" + Signature.Sig.Length + "] " + Signature));

        return result.ToString();
    }
}