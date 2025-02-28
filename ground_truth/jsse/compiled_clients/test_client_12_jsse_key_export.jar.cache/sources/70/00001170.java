package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;
import javax.net.ssl.SSLHandshakeException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineOutputRecord.class */
public final class SSLEngineOutputRecord extends OutputRecord implements SSLRecord {
    private HandshakeFragment fragmenter;
    private boolean isTalkingToV2;
    private ByteBuffer v2ClientHello;
    private volatile boolean isCloseWaiting;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLEngineOutputRecord(HandshakeHash handshakeHash) {
        super(handshakeHash, SSLCipher.SSLWriteCipher.nullTlsWriteCipher());
        this.fragmenter = null;
        this.isTalkingToV2 = false;
        this.v2ClientHello = null;
        this.isCloseWaiting = false;
        this.packetSize = SSLRecord.maxRecordSize;
        this.protocolVersion = ProtocolVersion.NONE;
    }

    @Override // org.openjsse.sun.security.ssl.OutputRecord, java.io.ByteArrayOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() throws IOException {
        if (!this.isClosed) {
            if (this.fragmenter != null && this.fragmenter.hasAlert()) {
                this.isCloseWaiting = true;
            } else {
                super.close();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public boolean isClosed() {
        return this.isClosed || this.isCloseWaiting;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void encodeAlert(byte level, byte description) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound alert message: " + Alert.nameOf(description), new Object[0]);
                return;
            }
            return;
        }
        if (this.fragmenter == null) {
            this.fragmenter = new HandshakeFragment();
        }
        this.fragmenter.queueUpAlert(level, description);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void encodeHandshake(byte[] source, int offset, int length) throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound handshake message", ByteBuffer.wrap(source, offset, length));
                return;
            }
            return;
        }
        if (this.fragmenter == null) {
            this.fragmenter = new HandshakeFragment();
        }
        if (this.firstMessage) {
            this.firstMessage = false;
            if (this.helloVersion == ProtocolVersion.SSL20Hello && source[offset] == SSLHandshake.CLIENT_HELLO.f987id && source[offset + 4 + 2 + 32] == 0) {
                this.v2ClientHello = encodeV2ClientHello(source, offset + 4, length - 4);
                this.v2ClientHello.position(2);
                this.handshakeHash.deliver(this.v2ClientHello);
                this.v2ClientHello.position(0);
                return;
            }
        }
        byte handshakeType = source[offset];
        if (this.handshakeHash.isHashable(handshakeType)) {
            this.handshakeHash.deliver(source, offset, length);
        }
        this.fragmenter.queueUpFragment(source, offset, length);
    }

    @Override // org.openjsse.sun.security.ssl.OutputRecord
    void encodeChangeCipherSpec() throws IOException {
        if (isClosed()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound change_cipher_spec message", new Object[0]);
                return;
            }
            return;
        }
        if (this.fragmenter == null) {
            this.fragmenter = new HandshakeFragment();
        }
        this.fragmenter.queueUpChangeCipherSpec();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void encodeV2NoCipher() throws IOException {
        this.isTalkingToV2 = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public Ciphertext encode(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        if (this.isClosed) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound application data or cached messages", new Object[0]);
                return null;
            }
            return null;
        }
        if (this.isCloseWaiting) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.warning("outbound has closed, ignore outbound application data", new Object[0]);
            }
            srcs = null;
        }
        return encode(srcs, srcsOffset, srcsLength, dsts[0]);
    }

    private Ciphertext encode(ByteBuffer[] sources, int offset, int length, ByteBuffer destination) throws IOException {
        int fragLen;
        int fragLen2;
        if (this.writeCipher.authenticator.seqNumOverflow()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("sequence number extremely close to overflow (2^64-1 packets). Closing connection.", new Object[0]);
            }
            throw new SSLHandshakeException("sequence number overflow");
        }
        Ciphertext ct = acquireCiphertext(destination);
        if (ct != null) {
            return ct;
        }
        if (sources == null || sources.length == 0) {
            return null;
        }
        int srcsRemains = 0;
        for (int i = offset; i < offset + length; i++) {
            srcsRemains += sources[i].remaining();
        }
        if (srcsRemains == 0) {
            return null;
        }
        int dstLim = destination.limit();
        boolean isFirstRecordOfThePayload = true;
        int packetLeftSize = Math.min((int) SSLRecord.maxRecordSize, this.packetSize);
        boolean needMorePayload = true;
        long recordSN = 0;
        while (needMorePayload) {
            if (isFirstRecordOfThePayload && needToSplitPayload()) {
                needMorePayload = true;
                fragLen2 = 1;
                isFirstRecordOfThePayload = false;
            } else {
                needMorePayload = false;
                if (packetLeftSize > 0) {
                    int fragLen3 = this.writeCipher.calculateFragmentSize(packetLeftSize, 5);
                    fragLen = Math.min(fragLen3, 16384);
                } else {
                    fragLen = 16384;
                }
                fragLen2 = calculateFragmentSize(fragLen);
            }
            int dstPos = destination.position();
            int dstContent = dstPos + 5 + this.writeCipher.getExplicitNonceSize();
            destination.position(dstContent);
            int remains = Math.min(fragLen2, destination.remaining());
            int fragLen4 = 0;
            int srcsLen = offset + length;
            for (int i2 = offset; i2 < srcsLen && remains > 0; i2++) {
                int amount = Math.min(sources[i2].remaining(), remains);
                int srcLimit = sources[i2].limit();
                sources[i2].limit(sources[i2].position() + amount);
                destination.put(sources[i2]);
                sources[i2].limit(srcLimit);
                remains -= amount;
                fragLen4 += amount;
                if (remains > 0) {
                    offset++;
                    length--;
                }
            }
            destination.limit(destination.position());
            destination.position(dstContent);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.APPLICATION_DATA.name + ", length = " + destination.remaining(), new Object[0]);
            }
            recordSN = encrypt(this.writeCipher, ContentType.APPLICATION_DATA.f965id, destination, dstPos, dstLim, 5, this.protocolVersion);
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                ByteBuffer temporary = destination.duplicate();
                temporary.limit(temporary.position());
                temporary.position(dstPos);
                SSLLogger.fine("Raw write", temporary);
            }
            packetLeftSize -= destination.position() - dstPos;
            destination.limit(dstLim);
            if (this.isFirstAppOutputRecord) {
                this.isFirstAppOutputRecord = false;
            }
        }
        return new Ciphertext(ContentType.APPLICATION_DATA.f965id, SSLHandshake.NOT_APPLICABLE.f987id, recordSN);
    }

    private Ciphertext acquireCiphertext(ByteBuffer destination) throws IOException {
        if (this.isTalkingToV2) {
            destination.put(SSLRecord.v2NoCipher);
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                SSLLogger.fine("Raw write", SSLRecord.v2NoCipher);
            }
            this.isTalkingToV2 = false;
            return new Ciphertext(ContentType.ALERT.f965id, SSLHandshake.NOT_APPLICABLE.f987id, -1L);
        } else if (this.v2ClientHello != null) {
            if (SSLLogger.isOn) {
                if (SSLLogger.isOn("record")) {
                    SSLLogger.fine(Thread.currentThread().getName() + ", WRITE: SSLv2 ClientHello message, length = " + this.v2ClientHello.remaining(), new Object[0]);
                }
                if (SSLLogger.isOn("packet")) {
                    SSLLogger.fine("Raw write", this.v2ClientHello);
                }
            }
            destination.put(this.v2ClientHello);
            this.v2ClientHello = null;
            return new Ciphertext(ContentType.HANDSHAKE.f965id, SSLHandshake.CLIENT_HELLO.f987id, -1L);
        } else if (this.fragmenter != null) {
            return this.fragmenter.acquireCiphertext(destination);
        } else {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public boolean isEmpty() {
        return !this.isTalkingToV2 && this.v2ClientHello == null && (this.fragmenter == null || this.fragmenter.isEmpty());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineOutputRecord$RecordMemo.class */
    public static class RecordMemo {
        byte contentType;
        byte majorVersion;
        byte minorVersion;
        SSLCipher.SSLWriteCipher encodeCipher;
        byte[] fragment;

        private RecordMemo() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineOutputRecord$HandshakeMemo.class */
    public static class HandshakeMemo extends RecordMemo {
        byte handshakeType;
        int acquireOffset;

        private HandshakeMemo() {
            super();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLEngineOutputRecord$HandshakeFragment.class */
    public final class HandshakeFragment {
        private LinkedList<RecordMemo> handshakeMemos = new LinkedList<>();

        HandshakeFragment() {
        }

        void queueUpFragment(byte[] source, int offset, int length) throws IOException {
            HandshakeMemo memo = new HandshakeMemo();
            memo.contentType = ContentType.HANDSHAKE.f965id;
            memo.majorVersion = SSLEngineOutputRecord.this.protocolVersion.major;
            memo.minorVersion = SSLEngineOutputRecord.this.protocolVersion.minor;
            memo.encodeCipher = SSLEngineOutputRecord.this.writeCipher;
            memo.handshakeType = source[offset];
            memo.acquireOffset = 0;
            memo.fragment = new byte[length - 4];
            System.arraycopy(source, offset + 4, memo.fragment, 0, length - 4);
            this.handshakeMemos.add(memo);
        }

        void queueUpChangeCipherSpec() {
            RecordMemo memo = new RecordMemo();
            memo.contentType = ContentType.CHANGE_CIPHER_SPEC.f965id;
            memo.majorVersion = SSLEngineOutputRecord.this.protocolVersion.major;
            memo.minorVersion = SSLEngineOutputRecord.this.protocolVersion.minor;
            memo.encodeCipher = SSLEngineOutputRecord.this.writeCipher;
            memo.fragment = new byte[1];
            memo.fragment[0] = 1;
            this.handshakeMemos.add(memo);
        }

        void queueUpAlert(byte level, byte description) {
            RecordMemo memo = new RecordMemo();
            memo.contentType = ContentType.ALERT.f965id;
            memo.majorVersion = SSLEngineOutputRecord.this.protocolVersion.major;
            memo.minorVersion = SSLEngineOutputRecord.this.protocolVersion.minor;
            memo.encodeCipher = SSLEngineOutputRecord.this.writeCipher;
            memo.fragment = new byte[2];
            memo.fragment[0] = level;
            memo.fragment[1] = description;
            this.handshakeMemos.add(memo);
        }

        Ciphertext acquireCiphertext(ByteBuffer dstBuf) throws IOException {
            int fragLen;
            if (isEmpty()) {
                return null;
            }
            RecordMemo memo = this.handshakeMemos.getFirst();
            HandshakeMemo hsMemo = null;
            if (memo.contentType == ContentType.HANDSHAKE.f965id) {
                hsMemo = (HandshakeMemo) memo;
            }
            if (SSLEngineOutputRecord.this.packetSize > 0) {
                int fragLen2 = Math.min((int) SSLRecord.maxRecordSize, SSLEngineOutputRecord.this.packetSize);
                fragLen = memo.encodeCipher.calculateFragmentSize(fragLen2, 5);
            } else {
                fragLen = 16384;
            }
            int fragLen3 = SSLEngineOutputRecord.this.calculateFragmentSize(fragLen);
            int dstPos = dstBuf.position();
            int dstLim = dstBuf.limit();
            int dstContent = dstPos + 5 + memo.encodeCipher.getExplicitNonceSize();
            dstBuf.position(dstContent);
            if (hsMemo != null) {
                int i = fragLen3;
                while (true) {
                    int remainingFragLen = i;
                    if (remainingFragLen <= 0 || this.handshakeMemos.isEmpty()) {
                        break;
                    }
                    int memoFragLen = hsMemo.fragment.length;
                    if (hsMemo.acquireOffset == 0) {
                        if (remainingFragLen <= 4) {
                            break;
                        }
                        dstBuf.put(hsMemo.handshakeType);
                        dstBuf.put((byte) ((memoFragLen >> 16) & GF2Field.MASK));
                        dstBuf.put((byte) ((memoFragLen >> 8) & GF2Field.MASK));
                        dstBuf.put((byte) (memoFragLen & GF2Field.MASK));
                        remainingFragLen -= 4;
                    }
                    int chipLen = Math.min(remainingFragLen, memoFragLen - hsMemo.acquireOffset);
                    dstBuf.put(hsMemo.fragment, hsMemo.acquireOffset, chipLen);
                    hsMemo.acquireOffset += chipLen;
                    if (hsMemo.acquireOffset == memoFragLen) {
                        this.handshakeMemos.removeFirst();
                        if (remainingFragLen > chipLen && !this.handshakeMemos.isEmpty()) {
                            RecordMemo rm = this.handshakeMemos.getFirst();
                            if (rm.contentType != ContentType.HANDSHAKE.f965id || rm.encodeCipher != hsMemo.encodeCipher) {
                                break;
                            }
                            hsMemo = (HandshakeMemo) rm;
                        }
                    }
                    i = remainingFragLen - chipLen;
                }
            } else {
                dstBuf.put(memo.fragment, 0, Math.min(fragLen3, memo.fragment.length));
                this.handshakeMemos.removeFirst();
            }
            dstBuf.limit(dstBuf.position());
            dstBuf.position(dstContent);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + SSLEngineOutputRecord.this.protocolVersion + " " + ContentType.nameOf(memo.contentType) + ", length = " + dstBuf.remaining(), new Object[0]);
            }
            long recordSN = OutputRecord.encrypt(memo.encodeCipher, memo.contentType, dstBuf, dstPos, dstLim, 5, ProtocolVersion.valueOf(memo.majorVersion, memo.minorVersion));
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                ByteBuffer temporary = dstBuf.duplicate();
                temporary.limit(temporary.position());
                temporary.position(dstPos);
                SSLLogger.fine("Raw write", temporary);
            }
            dstBuf.limit(dstLim);
            if (hsMemo == null) {
                if (SSLEngineOutputRecord.this.isCloseWaiting && memo.contentType == ContentType.ALERT.f965id) {
                    SSLEngineOutputRecord.this.close();
                }
                return new Ciphertext(memo.contentType, SSLHandshake.NOT_APPLICABLE.f987id, recordSN);
            }
            return new Ciphertext(hsMemo.contentType, hsMemo.handshakeType, recordSN);
        }

        boolean isEmpty() {
            return this.handshakeMemos.isEmpty();
        }

        boolean hasAlert() {
            Iterator<RecordMemo> it = this.handshakeMemos.iterator();
            while (it.hasNext()) {
                RecordMemo memo = it.next();
                if (memo.contentType == ContentType.ALERT.f965id) {
                    return true;
                }
            }
            return false;
        }
    }

    boolean needToSplitPayload() {
        return !this.protocolVersion.useTLS11PlusSpec() && this.writeCipher.isCBCMode() && !this.isFirstAppOutputRecord && Record.enableCBCProtection;
    }
}