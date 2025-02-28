package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.LinkedList;
import javax.net.ssl.SSLHandshakeException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSOutputRecord.class */
public final class DTLSOutputRecord extends OutputRecord implements DTLSRecord {
    private DTLSFragmenter fragmenter;
    int writeEpoch;
    int prevWriteEpoch;
    Authenticator prevWriteAuthenticator;
    SSLCipher.SSLWriteCipher prevWriteCipher;
    private volatile boolean isCloseWaiting;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSOutputRecord(HandshakeHash handshakeHash) {
        super(handshakeHash, SSLCipher.SSLWriteCipher.nullDTlsWriteCipher());
        this.fragmenter = null;
        this.isCloseWaiting = false;
        this.writeEpoch = 0;
        this.prevWriteEpoch = 0;
        this.prevWriteCipher = SSLCipher.SSLWriteCipher.nullDTlsWriteCipher();
        this.packetSize = DTLSRecord.maxRecordSize;
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
    public void initHandshaker() {
        this.fragmenter = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void finishHandshake() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void changeWriteCiphers(SSLCipher.SSLWriteCipher writeCipher, boolean useChangeCipherSpec) throws IOException {
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
        this.prevWriteCipher.dispose();
        this.prevWriteCipher = this.writeCipher;
        this.prevWriteEpoch = this.writeEpoch;
        this.writeCipher = writeCipher;
        this.writeEpoch++;
        this.isFirstAppOutputRecord = true;
        this.writeCipher.authenticator.setEpochNumber(this.writeEpoch);
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
            this.fragmenter = new DTLSFragmenter();
        }
        this.fragmenter.queueUpAlert(level, description);
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
            this.fragmenter = new DTLSFragmenter();
        }
        this.fragmenter.queueUpChangeCipherSpec();
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
        if (this.firstMessage) {
            this.firstMessage = false;
        }
        if (this.fragmenter == null) {
            this.fragmenter = new DTLSFragmenter();
        }
        this.fragmenter.queueUpHandshake(source, offset, length);
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
        Ciphertext ct;
        int fragLen;
        if (this.writeCipher.authenticator.seqNumOverflow()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("sequence number extremely close to overflow (2^64-1 packets). Closing connection.", new Object[0]);
            }
            throw new SSLHandshakeException("sequence number overflow");
        } else if ((!isEmpty() || sources == null || sources.length == 0) && (ct = acquireCiphertext(destination)) != null) {
            return ct;
        } else {
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
            if (this.packetSize > 0) {
                int fragLen2 = Math.min((int) DTLSRecord.maxRecordSize, this.packetSize);
                fragLen = Math.min(this.writeCipher.calculateFragmentSize(fragLen2, 13), 16384);
            } else {
                fragLen = 16384;
            }
            int fragLen3 = calculateFragmentSize(fragLen);
            int dstPos = destination.position();
            int dstLim = destination.limit();
            int dstContent = dstPos + 13 + this.writeCipher.getExplicitNonceSize();
            destination.position(dstContent);
            int remains = Math.min(fragLen3, destination.remaining());
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
            }
            destination.limit(destination.position());
            destination.position(dstContent);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + this.protocolVersion + " " + ContentType.APPLICATION_DATA.name + ", length = " + destination.remaining(), new Object[0]);
            }
            long recordSN = encrypt(this.writeCipher, ContentType.APPLICATION_DATA.f965id, destination, dstPos, dstLim, 13, this.protocolVersion);
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                ByteBuffer temporary = destination.duplicate();
                temporary.limit(temporary.position());
                temporary.position(dstPos);
                SSLLogger.fine("Raw write", temporary);
            }
            destination.limit(dstLim);
            return new Ciphertext(ContentType.APPLICATION_DATA.f965id, SSLHandshake.NOT_APPLICABLE.f987id, recordSN);
        }
    }

    private Ciphertext acquireCiphertext(ByteBuffer destination) throws IOException {
        if (this.fragmenter != null) {
            return this.fragmenter.acquireCiphertext(destination);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public boolean isEmpty() {
        return this.fragmenter == null || this.fragmenter.isEmpty();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.OutputRecord
    public void launchRetransmission() {
        if (this.fragmenter == null || !this.fragmenter.isRetransmittable()) {
            return;
        }
        this.fragmenter.setRetransmission();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSOutputRecord$RecordMemo.class */
    public static class RecordMemo {
        byte contentType;
        byte majorVersion;
        byte minorVersion;
        int encodeEpoch;
        SSLCipher.SSLWriteCipher encodeCipher;
        byte[] fragment;

        private RecordMemo() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSOutputRecord$HandshakeMemo.class */
    public static class HandshakeMemo extends RecordMemo {
        byte handshakeType;
        int messageSequence;
        int acquireOffset;

        private HandshakeMemo() {
            super();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSOutputRecord$DTLSFragmenter.class */
    public final class DTLSFragmenter {
        private final LinkedList<RecordMemo> handshakeMemos;
        private int acquireIndex;
        private int messageSequence;
        private boolean flightIsReady;
        private int retransmits;

        private DTLSFragmenter() {
            this.handshakeMemos = new LinkedList<>();
            this.acquireIndex = 0;
            this.messageSequence = 0;
            this.flightIsReady = false;
            this.retransmits = 2;
        }

        void queueUpHandshake(byte[] buf, int offset, int length) throws IOException {
            if (this.flightIsReady) {
                this.handshakeMemos.clear();
                this.acquireIndex = 0;
                this.flightIsReady = false;
            }
            HandshakeMemo memo = new HandshakeMemo();
            memo.contentType = ContentType.HANDSHAKE.f965id;
            memo.majorVersion = DTLSOutputRecord.this.protocolVersion.major;
            memo.minorVersion = DTLSOutputRecord.this.protocolVersion.minor;
            memo.encodeEpoch = DTLSOutputRecord.this.writeEpoch;
            memo.encodeCipher = DTLSOutputRecord.this.writeCipher;
            memo.handshakeType = buf[offset];
            int i = this.messageSequence;
            this.messageSequence = i + 1;
            memo.messageSequence = i;
            memo.acquireOffset = 0;
            memo.fragment = new byte[length - 4];
            System.arraycopy(buf, offset + 4, memo.fragment, 0, length - 4);
            handshakeHashing(memo, memo.fragment);
            this.handshakeMemos.add(memo);
            if (memo.handshakeType == SSLHandshake.CLIENT_HELLO.f987id || memo.handshakeType == SSLHandshake.HELLO_REQUEST.f987id || memo.handshakeType == SSLHandshake.HELLO_VERIFY_REQUEST.f987id || memo.handshakeType == SSLHandshake.SERVER_HELLO_DONE.f987id || memo.handshakeType == SSLHandshake.FINISHED.f987id) {
                this.flightIsReady = true;
            }
        }

        void queueUpChangeCipherSpec() {
            if (this.flightIsReady) {
                this.handshakeMemos.clear();
                this.acquireIndex = 0;
                this.flightIsReady = false;
            }
            RecordMemo memo = new RecordMemo();
            memo.contentType = ContentType.CHANGE_CIPHER_SPEC.f965id;
            memo.majorVersion = DTLSOutputRecord.this.protocolVersion.major;
            memo.minorVersion = DTLSOutputRecord.this.protocolVersion.minor;
            memo.encodeEpoch = DTLSOutputRecord.this.writeEpoch;
            memo.encodeCipher = DTLSOutputRecord.this.writeCipher;
            memo.fragment = new byte[1];
            memo.fragment[0] = 1;
            this.handshakeMemos.add(memo);
        }

        void queueUpAlert(byte level, byte description) throws IOException {
            RecordMemo memo = new RecordMemo();
            memo.contentType = ContentType.ALERT.f965id;
            memo.majorVersion = DTLSOutputRecord.this.protocolVersion.major;
            memo.minorVersion = DTLSOutputRecord.this.protocolVersion.minor;
            memo.encodeEpoch = DTLSOutputRecord.this.writeEpoch;
            memo.encodeCipher = DTLSOutputRecord.this.writeCipher;
            memo.fragment = new byte[2];
            memo.fragment[0] = level;
            memo.fragment[1] = description;
            this.handshakeMemos.add(memo);
        }

        Ciphertext acquireCiphertext(ByteBuffer dstBuf) throws IOException {
            int fragLen;
            int fragLen2;
            if (isEmpty()) {
                if (isRetransmittable()) {
                    setRetransmission();
                } else {
                    return null;
                }
            }
            RecordMemo memo = this.handshakeMemos.get(this.acquireIndex);
            HandshakeMemo hsMemo = null;
            if (memo.contentType == ContentType.HANDSHAKE.f965id) {
                hsMemo = (HandshakeMemo) memo;
            }
            if (DTLSOutputRecord.this.packetSize > 0) {
                int fragLen3 = Math.min((int) DTLSRecord.maxRecordSize, DTLSOutputRecord.this.packetSize);
                fragLen = Math.min(memo.encodeCipher.calculateFragmentSize(fragLen3, 25), 16384);
            } else {
                fragLen = 16384;
            }
            int fragLen4 = DTLSOutputRecord.this.calculateFragmentSize(fragLen);
            int dstPos = dstBuf.position();
            int dstLim = dstBuf.limit();
            int dstContent = dstPos + 13 + memo.encodeCipher.getExplicitNonceSize();
            dstBuf.position(dstContent);
            if (hsMemo != null) {
                fragLen2 = Math.min(fragLen4, hsMemo.fragment.length - hsMemo.acquireOffset);
                dstBuf.put(hsMemo.handshakeType);
                dstBuf.put((byte) ((hsMemo.fragment.length >> 16) & GF2Field.MASK));
                dstBuf.put((byte) ((hsMemo.fragment.length >> 8) & GF2Field.MASK));
                dstBuf.put((byte) (hsMemo.fragment.length & GF2Field.MASK));
                dstBuf.put((byte) ((hsMemo.messageSequence >> 8) & GF2Field.MASK));
                dstBuf.put((byte) (hsMemo.messageSequence & GF2Field.MASK));
                dstBuf.put((byte) ((hsMemo.acquireOffset >> 16) & GF2Field.MASK));
                dstBuf.put((byte) ((hsMemo.acquireOffset >> 8) & GF2Field.MASK));
                dstBuf.put((byte) (hsMemo.acquireOffset & GF2Field.MASK));
                dstBuf.put((byte) ((fragLen2 >> 16) & GF2Field.MASK));
                dstBuf.put((byte) ((fragLen2 >> 8) & GF2Field.MASK));
                dstBuf.put((byte) (fragLen2 & GF2Field.MASK));
                dstBuf.put(hsMemo.fragment, hsMemo.acquireOffset, fragLen2);
            } else {
                fragLen2 = Math.min(fragLen4, memo.fragment.length);
                dstBuf.put(memo.fragment, 0, fragLen2);
            }
            dstBuf.limit(dstBuf.position());
            dstBuf.position(dstContent);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("WRITE: " + DTLSOutputRecord.this.protocolVersion + " " + ContentType.nameOf(memo.contentType) + ", length = " + dstBuf.remaining(), new Object[0]);
            }
            long recordSN = OutputRecord.encrypt(memo.encodeCipher, memo.contentType, dstBuf, dstPos, dstLim, 13, ProtocolVersion.valueOf(memo.majorVersion, memo.minorVersion));
            if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
                ByteBuffer temporary = dstBuf.duplicate();
                temporary.limit(temporary.position());
                temporary.position(dstPos);
                SSLLogger.fine("Raw write (" + temporary.remaining() + ")", temporary);
            }
            dstBuf.limit(dstLim);
            if (hsMemo == null) {
                if (DTLSOutputRecord.this.isCloseWaiting && memo.contentType == ContentType.ALERT.f965id) {
                    DTLSOutputRecord.this.close();
                }
                this.acquireIndex++;
                return new Ciphertext(memo.contentType, SSLHandshake.NOT_APPLICABLE.f987id, recordSN);
            }
            hsMemo.acquireOffset += fragLen2;
            if (hsMemo.acquireOffset == hsMemo.fragment.length) {
                this.acquireIndex++;
            }
            return new Ciphertext(hsMemo.contentType, hsMemo.handshakeType, recordSN);
        }

        private void handshakeHashing(HandshakeMemo hsFrag, byte[] hsBody) {
            byte hsType = hsFrag.handshakeType;
            if (!DTLSOutputRecord.this.handshakeHash.isHashable(hsType)) {
                return;
            }
            byte[] temporary = {hsFrag.handshakeType, (byte) ((hsBody.length >> 16) & GF2Field.MASK), (byte) ((hsBody.length >> 8) & GF2Field.MASK), (byte) (hsBody.length & GF2Field.MASK), (byte) ((hsFrag.messageSequence >> 8) & GF2Field.MASK), (byte) (hsFrag.messageSequence & GF2Field.MASK), 0, 0, 0, temporary[1], temporary[2], temporary[3]};
            DTLSOutputRecord.this.handshakeHash.deliver(temporary, 0, 12);
            DTLSOutputRecord.this.handshakeHash.deliver(hsBody, 0, hsBody.length);
        }

        boolean isEmpty() {
            if (!this.flightIsReady || this.handshakeMemos.isEmpty() || this.acquireIndex >= this.handshakeMemos.size()) {
                return true;
            }
            return false;
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

        boolean isRetransmittable() {
            return this.flightIsReady && !this.handshakeMemos.isEmpty() && this.acquireIndex >= this.handshakeMemos.size();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setRetransmission() {
            this.acquireIndex = 0;
            Iterator<RecordMemo> it = this.handshakeMemos.iterator();
            while (it.hasNext()) {
                RecordMemo memo = it.next();
                if (memo instanceof HandshakeMemo) {
                    HandshakeMemo hmemo = (HandshakeMemo) memo;
                    hmemo.acquireOffset = 0;
                }
            }
            if (DTLSOutputRecord.this.packetSize > 16717 || DTLSOutputRecord.this.packetSize <= 256) {
                return;
            }
            int i = this.retransmits;
            this.retransmits = i - 1;
            if (i <= 0) {
                shrinkPacketSize();
                this.retransmits = 2;
            }
        }

        private void shrinkPacketSize() {
            DTLSOutputRecord.this.packetSize = Math.max(256, DTLSOutputRecord.this.packetSize / 2);
        }
    }
}