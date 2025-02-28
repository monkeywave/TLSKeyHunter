package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import javassist.bytecode.Opcode;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineInputRecord.class */
public final class SSLEngineInputRecord extends InputRecord implements SSLRecord {
    private boolean formatVerified;
    private ByteBuffer handshakeBuffer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineInputRecord(HandshakeHash handshakeHash) {
        super(handshakeHash, SSLCipher.SSLReadCipher.nullTlsReadCipher());
        this.formatVerified = false;
        this.handshakeBuffer = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public int estimateFragmentSize(int packetSize) {
        if (packetSize > 0) {
            return this.readCipher.estimateFragmentSize(packetSize, 5);
        }
        return 16384;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public int bytesInCompletePacket(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException {
        return bytesInCompletePacket(srcs[srcsOffset]);
    }

    private int bytesInCompletePacket(ByteBuffer packet) throws SSLException {
        int len;
        if (packet.remaining() < 5) {
            return -1;
        }
        int pos = packet.position();
        int byteZero = packet.get(pos);
        if (this.formatVerified || byteZero == ContentType.HANDSHAKE.f965id || byteZero == ContentType.ALERT.f965id) {
            byte majorVersion = packet.get(pos + 1);
            byte minorVersion = packet.get(pos + 2);
            if (!ProtocolVersion.isNegotiable(majorVersion, minorVersion, false, false)) {
                throw new SSLException("Unrecognized record version " + ProtocolVersion.nameOf(majorVersion, minorVersion) + " , plaintext connection?");
            }
            this.formatVerified = true;
            len = ((packet.get(pos + 3) & 255) << 8) + (packet.get(pos + 4) & 255) + 5;
        } else {
            boolean isShort = (byteZero & 128) != 0;
            if (isShort && (packet.get(pos + 2) == 1 || packet.get(pos + 2) == 4)) {
                byte majorVersion2 = packet.get(pos + 3);
                byte minorVersion2 = packet.get(pos + 4);
                if (!ProtocolVersion.isNegotiable(majorVersion2, minorVersion2, false, false)) {
                    throw new SSLException("Unrecognized record version " + ProtocolVersion.nameOf(majorVersion2, minorVersion2) + " , plaintext connection?");
                }
                int mask = isShort ? Opcode.LAND : 63;
                len = ((byteZero & mask) << 8) + (packet.get(pos + 1) & 255) + (isShort ? 2 : 3);
            } else {
                throw new SSLException("Unrecognized SSL message, plaintext connection?");
            }
        }
        return len;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public Plaintext[] decode(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException, BadPaddingException {
        if (srcs == null || srcs.length == 0 || srcsLength == 0) {
            return new Plaintext[0];
        }
        if (srcsLength == 1) {
            return decode(srcs[srcsOffset]);
        }
        ByteBuffer packet = extract(srcs, srcsOffset, srcsLength, 5);
        return decode(packet);
    }

    private Plaintext[] decode(ByteBuffer packet) throws IOException, BadPaddingException {
        if (this.isClosed) {
            return null;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            SSLLogger.fine("Raw read", packet);
        }
        if (!this.formatVerified) {
            this.formatVerified = true;
            int pos = packet.position();
            byte byteZero = packet.get(pos);
            if (byteZero != ContentType.HANDSHAKE.f965id && byteZero != ContentType.ALERT.f965id) {
                return handleUnknownRecord(packet);
            }
        }
        return decodeInputRecord(packet);
    }

    /* JADX WARN: Code restructure failed: missing block: B:69:0x0313, code lost:
        return (org.openjsse.sun.security.ssl.Plaintext[]) r0.toArray(new org.openjsse.sun.security.ssl.Plaintext[0]);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private org.openjsse.sun.security.ssl.Plaintext[] decodeInputRecord(java.nio.ByteBuffer r14) throws java.io.IOException, javax.crypto.BadPaddingException {
        /*
            Method dump skipped, instructions count: 815
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.openjsse.sun.security.ssl.SSLEngineInputRecord.decodeInputRecord(java.nio.ByteBuffer):org.openjsse.sun.security.ssl.Plaintext[]");
    }

    private Plaintext[] handleUnknownRecord(ByteBuffer packet) throws IOException, BadPaddingException {
        int srcPos = packet.position();
        packet.limit();
        byte firstByte = packet.get(srcPos);
        byte thirdByte = packet.get(srcPos + 2);
        if ((firstByte & 128) != 0 && thirdByte == 1) {
            if (this.helloVersion != ProtocolVersion.SSL20Hello) {
                throw new SSLHandshakeException("SSLv2Hello is not enabled");
            }
            byte majorVersion = packet.get(srcPos + 3);
            byte minorVersion = packet.get(srcPos + 4);
            if (majorVersion == ProtocolVersion.SSL20Hello.major && minorVersion == ProtocolVersion.SSL20Hello.minor) {
                if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                    SSLLogger.fine("Requested to negotiate unsupported SSLv2!", new Object[0]);
                }
                throw new UnsupportedOperationException("Unsupported SSL v2.0 ClientHello");
            }
            packet.position(srcPos + 2);
            this.handshakeHash.receive(packet);
            packet.position(srcPos);
            ByteBuffer converted = convertToClientHello(packet);
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                SSLLogger.fine("[Converted] ClientHello", converted);
            }
            return new Plaintext[]{new Plaintext(ContentType.HANDSHAKE.f965id, majorVersion, minorVersion, -1, -1L, converted)};
        } else if ((firstByte & 128) != 0 && thirdByte == 4) {
            throw new SSLException("SSL V2.0 servers are not supported.");
        } else {
            throw new SSLException("Unsupported or unrecognized SSL message");
        }
    }
}