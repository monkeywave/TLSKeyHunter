package org.openjsse.sun.security.ssl;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/InputRecord.class */
public abstract class InputRecord implements Record, Closeable {
    SSLCipher.SSLReadCipher readCipher;

    /* renamed from: tc */
    TransportContext f973tc;
    final HandshakeHash handshakeHash;
    ProtocolVersion helloVersion = ProtocolVersion.TLS10;
    boolean isClosed = false;
    int fragmentSize = 16384;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract Plaintext[] decode(ByteBuffer[] byteBufferArr, int i, int i2) throws IOException, BadPaddingException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public InputRecord(HandshakeHash handshakeHash, SSLCipher.SSLReadCipher readCipher) {
        this.readCipher = readCipher;
        this.handshakeHash = handshakeHash;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setHelloVersion(ProtocolVersion helloVersion) {
        this.helloVersion = helloVersion;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean seqNumIsHuge() {
        return this.readCipher.authenticator != null && this.readCipher.authenticator.seqNumIsHuge();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEmpty() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void expectingFinishFlight() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void finishHandshake() {
    }

    public synchronized void close() throws IOException {
        if (!this.isClosed) {
            this.isClosed = true;
            this.readCipher.dispose();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized boolean isClosed() {
        return this.isClosed;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void changeReadCiphers(SSLCipher.SSLReadCipher readCipher) {
        readCipher.dispose();
        this.readCipher = readCipher;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void changeFragmentSize(int fragmentSize) {
        this.fragmentSize = fragmentSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int bytesInCompletePacket(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int bytesInCompletePacket() throws IOException {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setReceiverStream(InputStream inputStream) {
        throw new UnsupportedOperationException();
    }

    Plaintext acquirePlaintext() throws IOException, BadPaddingException {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setDeliverStream(OutputStream outputStream) {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int estimateFragmentSize(int packetSize) {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ByteBuffer convertToClientHello(ByteBuffer packet) {
        int pointer;
        int srcPos = packet.position();
        byte firstByte = packet.get();
        byte secondByte = packet.get();
        int recordLen = (((firstByte & Byte.MAX_VALUE) << 8) | (secondByte & 255)) + 2;
        packet.position(srcPos + 3);
        byte majorVersion = packet.get();
        byte minorVersion = packet.get();
        int cipherSpecLen = ((packet.get() & 255) << 8) + (packet.get() & 255);
        int sessionIdLen = ((packet.get() & 255) << 8) + (packet.get() & 255);
        int nonceLen = ((packet.get() & 255) << 8) + (packet.get() & 255);
        int requiredSize = 48 + sessionIdLen + ((cipherSpecLen * 2) / 3);
        byte[] converted = new byte[requiredSize];
        converted[0] = ContentType.HANDSHAKE.f965id;
        converted[1] = majorVersion;
        converted[2] = minorVersion;
        converted[5] = 1;
        converted[9] = majorVersion;
        converted[10] = minorVersion;
        int pointer2 = 11;
        int offset = srcPos + 11 + cipherSpecLen + sessionIdLen;
        if (nonceLen < 32) {
            for (int i = 0; i < 32 - nonceLen; i++) {
                int i2 = pointer2;
                pointer2++;
                converted[i2] = 0;
            }
            packet.position(offset);
            packet.get(converted, pointer2, nonceLen);
            pointer = pointer2 + nonceLen;
        } else {
            packet.position((offset + nonceLen) - 32);
            packet.get(converted, 11, 32);
            pointer = 11 + 32;
        }
        int offset2 = offset - sessionIdLen;
        int i3 = pointer;
        int pointer3 = pointer + 1;
        converted[i3] = (byte) (sessionIdLen & GF2Field.MASK);
        packet.position(offset2);
        packet.get(converted, pointer3, sessionIdLen);
        packet.position(offset2 - cipherSpecLen);
        int j = pointer3 + 2;
        for (int i4 = 0; i4 < cipherSpecLen; i4 += 3) {
            if (packet.get() != 0) {
                packet.get();
                packet.get();
            } else {
                int i5 = j;
                int j2 = j + 1;
                converted[i5] = packet.get();
                j = j2 + 1;
                converted[j2] = packet.get();
            }
        }
        int j3 = j - (pointer3 + 2);
        int pointer4 = pointer3 + 1;
        converted[pointer3] = (byte) ((j3 >>> 8) & GF2Field.MASK);
        converted[pointer4] = (byte) (j3 & GF2Field.MASK);
        int pointer5 = pointer4 + 1 + j3;
        int pointer6 = pointer5 + 1;
        converted[pointer5] = 1;
        int pointer7 = pointer6 + 1;
        converted[pointer6] = 0;
        int fragLen = pointer7 - 5;
        converted[3] = (byte) ((fragLen >>> 8) & GF2Field.MASK);
        converted[4] = (byte) (fragLen & GF2Field.MASK);
        int fragLen2 = pointer7 - 9;
        converted[6] = (byte) ((fragLen2 >>> 16) & GF2Field.MASK);
        converted[7] = (byte) ((fragLen2 >>> 8) & GF2Field.MASK);
        converted[8] = (byte) (fragLen2 & GF2Field.MASK);
        packet.position(srcPos + recordLen);
        return ByteBuffer.wrap(converted, 5, pointer7 - 5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ByteBuffer extract(ByteBuffer[] buffers, int offset, int length, int headerSize) {
        boolean hasFullHeader = false;
        int contentLen = -1;
        int j = 0;
        for (int i = offset; i < offset + length && j < headerSize; i++) {
            int remains = buffers[i].remaining();
            int pos = buffers[i].position();
            int k = 0;
            while (true) {
                if (k < remains && j < headerSize) {
                    byte b = buffers[i].get(pos + k);
                    if (j == headerSize - 2) {
                        contentLen = (b & 255) << 8;
                    } else if (j == headerSize - 1) {
                        contentLen |= b & 255;
                        hasFullHeader = true;
                        break;
                    }
                    j++;
                    k++;
                }
            }
        }
        if (!hasFullHeader) {
            throw new BufferUnderflowException();
        }
        int packetLen = headerSize + contentLen;
        int remains2 = 0;
        for (int i2 = offset; i2 < offset + length; i2++) {
            remains2 += buffers[i2].remaining();
            if (remains2 >= packetLen) {
                break;
            }
        }
        if (remains2 < packetLen) {
            throw new BufferUnderflowException();
        }
        byte[] packet = new byte[packetLen];
        int packetOffset = 0;
        int packetSpaces = packetLen;
        for (int i3 = offset; i3 < offset + length; i3++) {
            if (buffers[i3].hasRemaining()) {
                int len = Math.min(packetSpaces, buffers[i3].remaining());
                buffers[i3].get(packet, packetOffset, len);
                packetOffset += len;
                packetSpaces -= len;
            }
            if (packetSpaces <= 0) {
                break;
            }
        }
        return ByteBuffer.wrap(packet);
    }
}