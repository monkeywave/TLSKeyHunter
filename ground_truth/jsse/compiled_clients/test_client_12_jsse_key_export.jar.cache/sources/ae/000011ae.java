package org.openjsse.sun.security.ssl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLSocketInputRecord.class */
public final class SSLSocketInputRecord extends InputRecord implements SSLRecord {

    /* renamed from: is */
    private InputStream f1004is;

    /* renamed from: os */
    private OutputStream f1005os;
    private final byte[] header;
    private int headerOff;
    private ByteBuffer recordBody;
    private boolean formatVerified;
    private ByteBuffer handshakeBuffer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLSocketInputRecord(HandshakeHash handshakeHash) {
        super(handshakeHash, SSLCipher.SSLReadCipher.nullTlsReadCipher());
        this.f1004is = null;
        this.f1005os = null;
        this.header = new byte[5];
        this.headerOff = 0;
        this.recordBody = ByteBuffer.allocate(1024);
        this.formatVerified = false;
        this.handshakeBuffer = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public int bytesInCompletePacket() throws IOException {
        int len;
        try {
            readHeader();
            byte byteZero = this.header[0];
            if (this.formatVerified || byteZero == ContentType.HANDSHAKE.f965id || byteZero == ContentType.ALERT.f965id) {
                if (!ProtocolVersion.isNegotiable(this.header[1], this.header[2], false, false)) {
                    throw new SSLException("Unrecognized record version " + ProtocolVersion.nameOf(this.header[1], this.header[2]) + " , plaintext connection?");
                }
                this.formatVerified = true;
                len = ((this.header[3] & 255) << 8) + (this.header[4] & 255) + 5;
            } else {
                boolean isShort = (byteZero & 128) != 0;
                if (isShort && (this.header[2] == 1 || this.header[2] == 4)) {
                    if (!ProtocolVersion.isNegotiable(this.header[3], this.header[4], false, false)) {
                        throw new SSLException("Unrecognized record version " + ProtocolVersion.nameOf(this.header[3], this.header[4]) + " , plaintext connection?");
                    }
                    len = ((byteZero & Byte.MAX_VALUE) << 8) + (this.header[1] & 255) + 2;
                } else {
                    throw new SSLException("Unrecognized SSL message, plaintext connection?");
                }
            }
            return len;
        } catch (EOFException e) {
            return -1;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public Plaintext[] decode(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException, BadPaddingException {
        if (this.isClosed) {
            return null;
        }
        readHeader();
        Plaintext[] plaintext = null;
        boolean cleanInBuffer = true;
        try {
            try {
                if (!this.formatVerified) {
                    this.formatVerified = true;
                    if (this.header[0] != ContentType.HANDSHAKE.f965id && this.header[0] != ContentType.ALERT.f965id) {
                        plaintext = handleUnknownRecord();
                    }
                }
                if (plaintext == null) {
                    plaintext = decodeInputRecord();
                }
                if (1 != 0) {
                    this.headerOff = 0;
                    this.recordBody.clear();
                }
                return plaintext;
            } catch (InterruptedIOException e) {
                cleanInBuffer = false;
                throw e;
            }
        } catch (Throwable th) {
            if (cleanInBuffer) {
                this.headerOff = 0;
                this.recordBody.clear();
            }
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public void setReceiverStream(InputStream inputStream) {
        this.f1004is = inputStream;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public void setDeliverStream(OutputStream outputStream) {
        this.f1005os = outputStream;
    }

    /* JADX WARN: Code restructure failed: missing block: B:75:0x036a, code lost:
        return (org.openjsse.sun.security.ssl.Plaintext[]) r0.toArray(new org.openjsse.sun.security.ssl.Plaintext[0]);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private org.openjsse.sun.security.ssl.Plaintext[] decodeInputRecord() throws java.io.IOException, javax.crypto.BadPaddingException {
        /*
            Method dump skipped, instructions count: 899
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.openjsse.sun.security.ssl.SSLSocketInputRecord.decodeInputRecord():org.openjsse.sun.security.ssl.Plaintext[]");
    }

    private Plaintext[] handleUnknownRecord() throws IOException, BadPaddingException {
        byte firstByte = this.header[0];
        byte thirdByte = this.header[2];
        if ((firstByte & 128) != 0 && thirdByte == 1) {
            if (this.helloVersion != ProtocolVersion.SSL20Hello) {
                throw new SSLHandshakeException("SSLv2Hello is not enabled");
            }
            byte majorVersion = this.header[3];
            byte minorVersion = this.header[4];
            if (majorVersion == ProtocolVersion.SSL20Hello.major && minorVersion == ProtocolVersion.SSL20Hello.minor) {
                this.f1005os.write(SSLRecord.v2NoCipher);
                if (SSLLogger.isOn) {
                    if (SSLLogger.isOn("record")) {
                        SSLLogger.fine("Requested to negotiate unsupported SSLv2!", new Object[0]);
                    }
                    if (SSLLogger.isOn("packet")) {
                        SSLLogger.fine("Raw write", SSLRecord.v2NoCipher);
                    }
                }
                throw new SSLException("Unsupported SSL v2.0 ClientHello");
            }
            int msgLen = ((this.header[0] & Byte.MAX_VALUE) << 8) | (this.header[1] & 255);
            if (this.recordBody.position() == 0) {
                if (this.recordBody.capacity() < 5 + msgLen) {
                    this.recordBody = ByteBuffer.allocate(5 + msgLen);
                }
                this.recordBody.limit(5 + msgLen);
                this.recordBody.put(this.header, 0, 5);
            } else {
                msgLen = this.recordBody.remaining();
            }
            readFully(msgLen - 3);
            this.recordBody.flip();
            this.recordBody.position(2);
            this.handshakeHash.receive(this.recordBody);
            this.recordBody.position(0);
            ByteBuffer converted = convertToClientHello(this.recordBody);
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

    private int readFully(int len) throws IOException {
        int end = len + this.recordBody.position();
        int off = this.recordBody.position();
        while (off < end) {
            try {
                off += read(this.f1004is, this.recordBody.array(), off, end - off);
            } finally {
                this.recordBody.position(off);
            }
        }
        return len;
    }

    private int readHeader() throws IOException {
        while (this.headerOff < 5) {
            this.headerOff += read(this.f1004is, this.header, this.headerOff, 5 - this.headerOff);
        }
        return 5;
    }

    private static int read(InputStream is, byte[] buf, int off, int len) throws IOException {
        int readLen = is.read(buf, off, len);
        if (readLen < 0) {
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                SSLLogger.fine("Raw read: EOF", new Object[0]);
            }
            throw new EOFException("SSL peer shut down incorrectly");
        }
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            ByteBuffer bb = ByteBuffer.wrap(buf, off, readLen);
            SSLLogger.fine("Raw read", bb);
        }
        return readLen;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void deplete(boolean tryToRead) throws IOException {
        int remaining = this.f1004is.available();
        if (tryToRead && remaining == 0) {
            this.f1004is.read();
        }
        while (true) {
            int remaining2 = this.f1004is.available();
            if (remaining2 != 0) {
                this.f1004is.skip(remaining2);
            } else {
                return;
            }
        }
    }
}