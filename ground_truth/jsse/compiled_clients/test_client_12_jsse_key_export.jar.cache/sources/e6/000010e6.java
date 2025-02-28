package org.openjsse.sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/OutputRecord.class */
public abstract class OutputRecord extends ByteArrayOutputStream implements Record, Closeable {
    SSLCipher.SSLWriteCipher writeCipher;

    /* renamed from: tc */
    TransportContext f977tc;
    final HandshakeHash handshakeHash;
    ProtocolVersion protocolVersion;
    ProtocolVersion helloVersion;
    int packetSize;
    volatile boolean isClosed;
    private static final int[] V3toV2CipherMap1 = {-1, -1, -1, 2, 1, -1, 4, 5, -1, 6, 7};
    private static final int[] V3toV2CipherMap3 = {-1, -1, -1, 128, 128, -1, 128, 128, -1, 64, 192};
    private static final byte[] HANDSHAKE_MESSAGE_KEY_UPDATE = {SSLHandshake.KEY_UPDATE.f987id, 0, 0, 1, 0};
    boolean isFirstAppOutputRecord = true;
    boolean firstMessage = true;
    private int fragmentSize = 16384;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void encodeAlert(byte b, byte b2) throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void encodeHandshake(byte[] bArr, int i, int i2) throws IOException;

    abstract void encodeChangeCipherSpec() throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OutputRecord(HandshakeHash handshakeHash, SSLCipher.SSLWriteCipher writeCipher) {
        this.writeCipher = writeCipher;
        this.handshakeHash = handshakeHash;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void setVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void setHelloVersion(ProtocolVersion helloVersion) {
        this.helloVersion = helloVersion;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEmpty() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized boolean seqNumIsHuge() {
        return this.writeCipher.authenticator != null && this.writeCipher.authenticator.seqNumIsHuge();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Ciphertext encode(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void encodeV2NoCipher() throws IOException {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deliver(byte[] source, int offset, int length) throws IOException {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setDeliverStream(OutputStream outputStream) {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void changeWriteCiphers(SSLCipher.SSLWriteCipher writeCipher, boolean useChangeCipherSpec) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound change_cipher_spec message", new Object[0]);
                return;
            }
            return;
        }
        if (useChangeCipherSpec) {
            encodeChangeCipherSpec();
        }
        writeCipher.dispose();
        this.writeCipher = writeCipher;
        this.isFirstAppOutputRecord = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void changeWriteCiphers(SSLCipher.SSLWriteCipher writeCipher, byte keyUpdateRequest) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound key_update handshake message", new Object[0]);
                return;
            }
            return;
        }
        byte[] hm = (byte[]) HANDSHAKE_MESSAGE_KEY_UPDATE.clone();
        hm[hm.length - 1] = keyUpdateRequest;
        encodeHandshake(hm, 0, hm.length);
        flush();
        writeCipher.dispose();
        this.writeCipher = writeCipher;
        this.isFirstAppOutputRecord = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void changePacketSize(int packetSize) {
        this.packetSize = packetSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void changeFragmentSize(int fragmentSize) {
        this.fragmentSize = fragmentSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized int getMaxPacketSize() {
        return this.packetSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initHandshaker() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void finishHandshake() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void launchRetransmission() {
    }

    @Override // java.io.ByteArrayOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() throws IOException {
        if (this.isClosed) {
            return;
        }
        this.isClosed = true;
        this.writeCipher.dispose();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isClosed() {
        return this.isClosed;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/OutputRecord$T13PaddingHolder.class */
    public static final class T13PaddingHolder {
        private static final byte[] zeros = new byte[16];

        private T13PaddingHolder() {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int calculateFragmentSize(int fragmentLimit) {
        if (this.fragmentSize > 0) {
            fragmentLimit = Math.min(fragmentLimit, this.fragmentSize);
        }
        if (this.protocolVersion.useTLS13PlusSpec()) {
            return (fragmentLimit - T13PaddingHolder.zeros.length) - 1;
        }
        return fragmentLimit;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, ByteBuffer destination, int headerOffset, int dstLim, int headerSize, ProtocolVersion protocolVersion) {
        boolean isDTLS = protocolVersion.isDTLS;
        if (isDTLS) {
            if (protocolVersion.useTLS13PlusSpec()) {
                return d13Encrypt(encCipher, contentType, destination, headerOffset, dstLim, headerSize, protocolVersion);
            }
            return d10Encrypt(encCipher, contentType, destination, headerOffset, dstLim, headerSize, protocolVersion);
        } else if (protocolVersion.useTLS13PlusSpec()) {
            return t13Encrypt(encCipher, contentType, destination, headerOffset, dstLim, headerSize, protocolVersion);
        } else {
            return t10Encrypt(encCipher, contentType, destination, headerOffset, dstLim, headerSize, protocolVersion);
        }
    }

    private static long d13Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, ByteBuffer destination, int headerOffset, int dstLim, int headerSize, ProtocolVersion protocolVersion) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static long d10Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, ByteBuffer destination, int headerOffset, int dstLim, int headerSize, ProtocolVersion protocolVersion) {
        byte[] sequenceNumber = encCipher.authenticator.sequenceNumber();
        encCipher.encrypt(contentType, destination);
        int fragLen = (destination.limit() - headerOffset) - headerSize;
        destination.put(headerOffset, contentType);
        destination.put(headerOffset + 1, protocolVersion.major);
        destination.put(headerOffset + 2, protocolVersion.minor);
        destination.put(headerOffset + 3, sequenceNumber[0]);
        destination.put(headerOffset + 4, sequenceNumber[1]);
        destination.put(headerOffset + 5, sequenceNumber[2]);
        destination.put(headerOffset + 6, sequenceNumber[3]);
        destination.put(headerOffset + 7, sequenceNumber[4]);
        destination.put(headerOffset + 8, sequenceNumber[5]);
        destination.put(headerOffset + 9, sequenceNumber[6]);
        destination.put(headerOffset + 10, sequenceNumber[7]);
        destination.put(headerOffset + 11, (byte) (fragLen >> 8));
        destination.put(headerOffset + 12, (byte) fragLen);
        destination.position(destination.limit());
        return Authenticator.toLong(sequenceNumber);
    }

    private static long t13Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, ByteBuffer destination, int headerOffset, int dstLim, int headerSize, ProtocolVersion protocolVersion) {
        if (!encCipher.isNullCipher()) {
            int endOfPt = destination.limit();
            int startOfPt = destination.position();
            destination.position(endOfPt);
            destination.limit(endOfPt + 1 + T13PaddingHolder.zeros.length);
            destination.put(contentType);
            destination.put(T13PaddingHolder.zeros);
            destination.position(startOfPt);
        }
        ProtocolVersion pv = protocolVersion;
        if (!encCipher.isNullCipher()) {
            pv = ProtocolVersion.TLS12;
            contentType = ContentType.APPLICATION_DATA.f965id;
        } else if (protocolVersion.useTLS13PlusSpec()) {
            pv = ProtocolVersion.TLS12;
        }
        byte[] sequenceNumber = encCipher.authenticator.sequenceNumber();
        encCipher.encrypt(contentType, destination);
        int fragLen = (destination.limit() - headerOffset) - headerSize;
        destination.put(headerOffset, contentType);
        destination.put(headerOffset + 1, pv.major);
        destination.put(headerOffset + 2, pv.minor);
        destination.put(headerOffset + 3, (byte) (fragLen >> 8));
        destination.put(headerOffset + 4, (byte) fragLen);
        destination.position(destination.limit());
        return Authenticator.toLong(sequenceNumber);
    }

    private static long t10Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, ByteBuffer destination, int headerOffset, int dstLim, int headerSize, ProtocolVersion protocolVersion) {
        byte[] sequenceNumber = encCipher.authenticator.sequenceNumber();
        encCipher.encrypt(contentType, destination);
        int fragLen = (destination.limit() - headerOffset) - headerSize;
        destination.put(headerOffset, contentType);
        destination.put(headerOffset + 1, protocolVersion.major);
        destination.put(headerOffset + 2, protocolVersion.minor);
        destination.put(headerOffset + 3, (byte) (fragLen >> 8));
        destination.put(headerOffset + 4, (byte) fragLen);
        destination.position(destination.limit());
        return Authenticator.toLong(sequenceNumber);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, int headerSize) {
        if (this.protocolVersion.useTLS13PlusSpec()) {
            return t13Encrypt(encCipher, contentType, headerSize);
        }
        return t10Encrypt(encCipher, contentType, headerSize);
    }

    private long t13Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, int headerSize) {
        ProtocolVersion pv;
        if (!encCipher.isNullCipher()) {
            write(contentType);
            write(T13PaddingHolder.zeros, 0, T13PaddingHolder.zeros.length);
        }
        byte[] sequenceNumber = encCipher.authenticator.sequenceNumber();
        int contentLen = this.count - headerSize;
        int requiredPacketSize = encCipher.calculatePacketSize(contentLen, headerSize);
        if (requiredPacketSize > this.buf.length) {
            byte[] newBuf = new byte[requiredPacketSize];
            System.arraycopy(this.buf, 0, newBuf, 0, this.count);
            this.buf = newBuf;
        }
        ProtocolVersion protocolVersion = this.protocolVersion;
        if (!encCipher.isNullCipher()) {
            pv = ProtocolVersion.TLS12;
            contentType = ContentType.APPLICATION_DATA.f965id;
        } else {
            pv = ProtocolVersion.TLS12;
        }
        ByteBuffer destination = ByteBuffer.wrap(this.buf, headerSize, contentLen);
        this.count = headerSize + encCipher.encrypt(contentType, destination);
        int fragLen = this.count - headerSize;
        this.buf[0] = contentType;
        this.buf[1] = pv.major;
        this.buf[2] = pv.minor;
        this.buf[3] = (byte) ((fragLen >> 8) & GF2Field.MASK);
        this.buf[4] = (byte) (fragLen & GF2Field.MASK);
        return Authenticator.toLong(sequenceNumber);
    }

    private long t10Encrypt(SSLCipher.SSLWriteCipher encCipher, byte contentType, int headerSize) {
        byte[] sequenceNumber = encCipher.authenticator.sequenceNumber();
        int position = headerSize + this.writeCipher.getExplicitNonceSize();
        int contentLen = this.count - position;
        int requiredPacketSize = encCipher.calculatePacketSize(contentLen, headerSize);
        if (requiredPacketSize > this.buf.length) {
            byte[] newBuf = new byte[requiredPacketSize];
            System.arraycopy(this.buf, 0, newBuf, 0, this.count);
            this.buf = newBuf;
        }
        ByteBuffer destination = ByteBuffer.wrap(this.buf, position, contentLen);
        this.count = headerSize + encCipher.encrypt(contentType, destination);
        int fragLen = this.count - headerSize;
        this.buf[0] = contentType;
        this.buf[1] = this.protocolVersion.major;
        this.buf[2] = this.protocolVersion.minor;
        this.buf[3] = (byte) ((fragLen >> 8) & GF2Field.MASK);
        this.buf[4] = (byte) (fragLen & GF2Field.MASK);
        return Authenticator.toLong(sequenceNumber);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ByteBuffer encodeV2ClientHello(byte[] fragment, int offset, int length) throws IOException {
        int v3SessIdLenOffset = offset + 34;
        int v3CSLenOffset = v3SessIdLenOffset + 1 + fragment[v3SessIdLenOffset];
        int v3CSLen = ((fragment[v3CSLenOffset] & GF2Field.MASK) << 8) + (fragment[v3CSLenOffset + 1] & GF2Field.MASK);
        int cipherSpecs = v3CSLen / 2;
        int v2MaxMsgLen = 11 + (cipherSpecs * 6) + 3 + 32;
        byte[] dstBytes = new byte[v2MaxMsgLen];
        ByteBuffer dstBuf = ByteBuffer.wrap(dstBytes);
        int v3CSOffset = v3CSLenOffset + 2;
        int v2CSLen = 0;
        dstBuf.position(11);
        boolean containsRenegoInfoSCSV = false;
        for (int i = 0; i < cipherSpecs; i++) {
            int i2 = v3CSOffset;
            int v3CSOffset2 = v3CSOffset + 1;
            byte byte1 = fragment[i2];
            v3CSOffset = v3CSOffset2 + 1;
            byte byte2 = fragment[v3CSOffset2];
            v2CSLen += V3toV2CipherSuite(dstBuf, byte1, byte2);
            if (!containsRenegoInfoSCSV && byte1 == 0 && byte2 == -1) {
                containsRenegoInfoSCSV = true;
            }
        }
        if (!containsRenegoInfoSCSV) {
            v2CSLen += V3toV2CipherSuite(dstBuf, (byte) 0, (byte) -1);
        }
        dstBuf.put(fragment, offset + 2, 32);
        int msgLen = dstBuf.position() - 2;
        dstBuf.position(0);
        dstBuf.put((byte) (128 | ((msgLen >>> 8) & GF2Field.MASK)));
        dstBuf.put((byte) (msgLen & GF2Field.MASK));
        dstBuf.put(SSLHandshake.CLIENT_HELLO.f987id);
        dstBuf.put(fragment[offset]);
        dstBuf.put(fragment[offset + 1]);
        dstBuf.put((byte) (v2CSLen >>> 8));
        dstBuf.put((byte) (v2CSLen & GF2Field.MASK));
        dstBuf.put((byte) 0);
        dstBuf.put((byte) 0);
        dstBuf.put((byte) 0);
        dstBuf.put((byte) 32);
        dstBuf.position(0);
        dstBuf.limit(msgLen + 2);
        return dstBuf;
    }

    private static int V3toV2CipherSuite(ByteBuffer dstBuf, byte byte1, byte byte2) {
        dstBuf.put((byte) 0);
        dstBuf.put(byte1);
        dstBuf.put(byte2);
        if ((byte2 & 255) > 10 || V3toV2CipherMap1[byte2] == -1) {
            return 3;
        }
        dstBuf.put((byte) V3toV2CipherMap1[byte2]);
        dstBuf.put((byte) 0);
        dstBuf.put((byte) V3toV2CipherMap3[byte2]);
        return 6;
    }
}