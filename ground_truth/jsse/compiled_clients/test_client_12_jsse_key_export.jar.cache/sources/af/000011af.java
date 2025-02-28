package org.openjsse.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketOutputRecord.class */
public final class SSLSocketOutputRecord extends OutputRecord implements SSLRecord {
    private OutputStream deliverStream;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketOutputRecord(HandshakeHash handshakeHash) {
        this(handshakeHash, null);
    }

    SSLSocketOutputRecord(HandshakeHash handshakeHash, TransportContext tc) {
        super(handshakeHash, SSLCipher.SSLWriteCipher.nullTlsWriteCipher());
        this.deliverStream = null;
        this.f977tc = tc;
        this.packetSize = SSLRecord.maxRecordSize;
        this.protocolVersion = ProtocolVersion.NONE;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public synchronized void encodeAlert(byte level, byte description) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound alert message: " + Alert.nameOf(description), new Object[0]);
                return;
            }
            return;
        }
        int position = 5 + this.writeCipher.getExplicitNonceSize();
        this.count = position;
        write(level);
        write(description);
        if (SSLLogger.isOn && SSLLogger.isOn("record")) {
            SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.ALERT.name + "(" + Alert.nameOf(description) + "), length = " + (this.count - 5), new Object[0]);
        }
        encrypt(this.writeCipher, ContentType.ALERT.f965id, 5);
        this.deliverStream.write(this.buf, 0, this.count);
        this.deliverStream.flush();
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            SSLLogger.fine("Raw write", new ByteArrayInputStream(this.buf, 0, this.count));
        }
        this.count = 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public synchronized void encodeHandshake(byte[] source, int offset, int length) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound handshake message", ByteBuffer.wrap(source, offset, length));
                return;
            }
            return;
        }
        if (this.firstMessage) {
            this.firstMessage = false;
            if (this.helloVersion == ProtocolVersion.SSL20Hello && source[offset] == SSLHandshake.CLIENT_HELLO.f987id && source[offset + 4 + 2 + 32] == 0) {
                ByteBuffer v2ClientHello = encodeV2ClientHello(source, offset + 4, length - 4);
                byte[] record = v2ClientHello.array();
                int limit = v2ClientHello.limit();
                this.handshakeHash.deliver(record, 2, limit - 2);
                if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                    SSLLogger.fine("WRITE: SSLv2 ClientHello message, length = " + limit, new Object[0]);
                }
                this.deliverStream.write(record, 0, limit);
                this.deliverStream.flush();
                if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                    SSLLogger.fine("Raw write", new ByteArrayInputStream(record, 0, limit));
                    return;
                }
                return;
            }
        }
        byte handshakeType = source[0];
        if (this.handshakeHash.isHashable(handshakeType)) {
            this.handshakeHash.deliver(source, offset, length);
        }
        int fragLimit = getFragLimit();
        int position = 5 + this.writeCipher.getExplicitNonceSize();
        if (this.count == 0) {
            this.count = position;
        }
        if (this.count - position < fragLimit - length) {
            write(source, offset, length);
            return;
        }
        int limit2 = offset + length;
        while (offset < limit2) {
            int remains = (limit2 - offset) + (this.count - position);
            int fragLen = Math.min(fragLimit, remains);
            write(source, offset, fragLen);
            if (remains < fragLimit) {
                return;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.HANDSHAKE.name + ", length = " + (this.count - 5), new Object[0]);
            }
            encrypt(this.writeCipher, ContentType.HANDSHAKE.f965id, 5);
            this.deliverStream.write(this.buf, 0, this.count);
            this.deliverStream.flush();
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                SSLLogger.fine("Raw write", new ByteArrayInputStream(this.buf, 0, this.count));
            }
            offset += fragLen;
            this.count = position;
        }
    }

    @Override // org.openjsse.sun.security.ssl.OutputRecord
    synchronized void encodeChangeCipherSpec() throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound change_cipher_spec message", new Object[0]);
                return;
            }
            return;
        }
        int position = 5 + this.writeCipher.getExplicitNonceSize();
        this.count = position;
        write(1);
        encrypt(this.writeCipher, ContentType.CHANGE_CIPHER_SPEC.f965id, 5);
        this.deliverStream.write(this.buf, 0, this.count);
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            SSLLogger.fine("Raw write", new ByteArrayInputStream(this.buf, 0, this.count));
        }
        this.count = 0;
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public synchronized void flush() throws IOException {
        int position = 5 + this.writeCipher.getExplicitNonceSize();
        if (this.count <= position) {
            return;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("record")) {
            SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.HANDSHAKE.name + ", length = " + (this.count - 5), new Object[0]);
        }
        encrypt(this.writeCipher, ContentType.HANDSHAKE.f965id, 5);
        this.deliverStream.write(this.buf, 0, this.count);
        this.deliverStream.flush();
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            SSLLogger.fine("Raw write", new ByteArrayInputStream(this.buf, 0, this.count));
        }
        this.count = 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public synchronized void deliver(byte[] source, int offset, int length) throws IOException {
        int fragLen;
        int fragLen2;
        if (isClosed()) {
            throw new SocketException("Connection or outbound has been closed");
        }
        if (this.writeCipher.authenticator.seqNumOverflow()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("sequence number extremely close to overflow (2^64-1 packets). Closing connection.", new Object[0]);
            }
            throw new SSLHandshakeException("sequence number overflow");
        }
        boolean isFirstRecordOfThePayload = true;
        int limit = offset + length;
        while (offset < limit) {
            if (this.packetSize > 0) {
                int fragLen3 = Math.min((int) SSLRecord.maxRecordSize, this.packetSize);
                fragLen = Math.min(this.writeCipher.calculateFragmentSize(fragLen3, 5), 16384);
            } else {
                fragLen = 16384;
            }
            int fragLen4 = calculateFragmentSize(fragLen);
            if (isFirstRecordOfThePayload && needToSplitPayload()) {
                fragLen2 = 1;
                isFirstRecordOfThePayload = false;
            } else {
                fragLen2 = Math.min(fragLen4, limit - offset);
            }
            int position = 5 + this.writeCipher.getExplicitNonceSize();
            this.count = position;
            write(source, offset, fragLen2);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.APPLICATION_DATA.name + ", length = " + (this.count - position), new Object[0]);
            }
            encrypt(this.writeCipher, ContentType.APPLICATION_DATA.f965id, 5);
            this.deliverStream.write(this.buf, 0, this.count);
            this.deliverStream.flush();
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                SSLLogger.fine("Raw write", new ByteArrayInputStream(this.buf, 0, this.count));
            }
            this.count = 0;
            if (this.isFirstAppOutputRecord) {
                this.isFirstAppOutputRecord = false;
            }
            offset += fragLen2;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public synchronized void setDeliverStream(OutputStream outputStream) {
        this.deliverStream = outputStream;
    }

    private boolean needToSplitPayload() {
        return !this.protocolVersion.useTLS11PlusSpec() && this.writeCipher.isCBCMode() && !this.isFirstAppOutputRecord && Record.enableCBCProtection;
    }

    private int getFragLimit() {
        int fragLimit;
        if (this.packetSize > 0) {
            int fragLimit2 = Math.min((int) SSLRecord.maxRecordSize, this.packetSize);
            fragLimit = Math.min(this.writeCipher.calculateFragmentSize(fragLimit2, 5), 16384);
        } else {
            fragLimit = 16384;
        }
        return calculateFragmentSize(fragLimit);
    }
}