package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public final class ProtocolName {
    private final byte[] bytes;
    public static final ProtocolName HTTP_1_1 = asUtf8Encoding("http/1.1");
    public static final ProtocolName SPDY_1 = asUtf8Encoding("spdy/1");
    public static final ProtocolName SPDY_2 = asUtf8Encoding("spdy/2");
    public static final ProtocolName SPDY_3 = asUtf8Encoding("spdy/3");
    public static final ProtocolName STUN_TURN = asUtf8Encoding("stun.turn");
    public static final ProtocolName STUN_NAT_DISCOVERY = asUtf8Encoding("stun.nat-discovery");
    public static final ProtocolName HTTP_2_TLS = asUtf8Encoding("h2");
    public static final ProtocolName HTTP_2_TCP = asUtf8Encoding("h2c");
    public static final ProtocolName WEBRTC = asUtf8Encoding("webrtc");
    public static final ProtocolName WEBRTC_CONFIDENTIAL = asUtf8Encoding("c-webrtc");
    public static final ProtocolName FTP = asUtf8Encoding("ftp");
    public static final ProtocolName IMAP = asUtf8Encoding("imap");
    public static final ProtocolName POP3 = asUtf8Encoding("pop3");
    public static final ProtocolName MANAGESIEVE = asUtf8Encoding("managesieve");
    public static final ProtocolName COAP = asUtf8Encoding("coap");
    public static final ProtocolName XMPP_CLIENT = asUtf8Encoding("xmpp-client");
    public static final ProtocolName XMPP_SERVER = asUtf8Encoding("xmpp-server");
    public static final ProtocolName ACME_TLS_1 = asUtf8Encoding("acme-tls/1");
    public static final ProtocolName OASIS_MQTT = asUtf8Encoding("mqtt");
    public static final ProtocolName DNS_OVER_TLS = asUtf8Encoding("dot");
    public static final ProtocolName NTSKE_1 = asUtf8Encoding("ntske/1");
    public static final ProtocolName SNU_RPC = asUtf8Encoding("sunrpc");
    public static final ProtocolName HTTP_3 = asUtf8Encoding("h3");
    public static final ProtocolName SMB_2 = asUtf8Encoding("smb");
    public static final ProtocolName IRC = asUtf8Encoding("irc");
    public static final ProtocolName NNTP_READING = asUtf8Encoding("nntp");
    public static final ProtocolName NNTP_TRANSIT = asUtf8Encoding("nnsp");
    public static final ProtocolName DNS_OVER_QUIC = asUtf8Encoding("doq");

    private ProtocolName(byte[] bArr) {
        if (bArr == null) {
            throw new IllegalArgumentException("'bytes' cannot be null");
        }
        if (bArr.length < 1 || bArr.length > 255) {
            throw new IllegalArgumentException("'bytes' must have length from 1 to 255");
        }
        this.bytes = bArr;
    }

    public static ProtocolName asRawBytes(byte[] bArr) {
        return new ProtocolName(Arrays.clone(bArr));
    }

    public static ProtocolName asUtf8Encoding(String str) {
        return new ProtocolName(Strings.toUTF8ByteArray(str));
    }

    public static ProtocolName parse(InputStream inputStream) throws IOException {
        return new ProtocolName(TlsUtils.readOpaque8(inputStream, 1));
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeOpaque8(this.bytes, outputStream);
    }

    public boolean equals(Object obj) {
        return (obj instanceof ProtocolName) && Arrays.areEqual(this.bytes, ((ProtocolName) obj).bytes);
    }

    public byte[] getBytes() {
        return Arrays.clone(this.bytes);
    }

    public String getUtf8Decoding() {
        return Strings.fromUTF8ByteArray(this.bytes);
    }

    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }
}