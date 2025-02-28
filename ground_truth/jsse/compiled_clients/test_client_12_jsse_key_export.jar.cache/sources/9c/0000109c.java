package org.openjsse.sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HandshakeOutStream.class */
public class HandshakeOutStream extends ByteArrayOutputStream {
    OutputRecord outputRecord;

    /* JADX INFO: Access modifiers changed from: package-private */
    public HandshakeOutStream(OutputRecord outputRecord) {
        this.outputRecord = outputRecord;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void complete() throws IOException {
        if (size() < 4) {
            throw new RuntimeException("handshake message is not available");
        }
        if (this.outputRecord != null) {
            if (!this.outputRecord.isClosed()) {
                this.outputRecord.encodeHandshake(this.buf, 0, this.count);
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound handshake messages", ByteBuffer.wrap(this.buf, 0, this.count));
            }
            reset();
        }
    }

    @Override // java.io.ByteArrayOutputStream, java.io.OutputStream
    public void write(byte[] b, int off, int len) {
        checkOverflow(len, Record.OVERFLOW_OF_INT24);
        super.write(b, off, len);
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() throws IOException {
        if (this.outputRecord != null) {
            this.outputRecord.flush();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putInt8(int i) throws IOException {
        checkOverflow(i, 256);
        super.write(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putInt16(int i) throws IOException {
        checkOverflow(i, Record.OVERFLOW_OF_INT16);
        super.write(i >> 8);
        super.write(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putInt24(int i) throws IOException {
        checkOverflow(i, Record.OVERFLOW_OF_INT24);
        super.write(i >> 16);
        super.write(i >> 8);
        super.write(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putInt32(int i) throws IOException {
        super.write(i >> 24);
        super.write(i >> 16);
        super.write(i >> 8);
        super.write(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putBytes8(byte[] b) throws IOException {
        if (b == null) {
            putInt8(0);
            return;
        }
        putInt8(b.length);
        super.write(b, 0, b.length);
    }

    public void putBytes16(byte[] b) throws IOException {
        if (b == null) {
            putInt16(0);
            return;
        }
        putInt16(b.length);
        super.write(b, 0, b.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void putBytes24(byte[] b) throws IOException {
        if (b == null) {
            putInt24(0);
            return;
        }
        putInt24(b.length);
        super.write(b, 0, b.length);
    }

    private static void checkOverflow(int length, int limit) {
        if (length >= limit) {
            throw new RuntimeException("Field length overflow, the field length (" + length + ") should be less than " + limit);
        }
    }
}