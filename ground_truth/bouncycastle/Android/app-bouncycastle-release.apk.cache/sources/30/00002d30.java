package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;
import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class DTLSRecordLayer implements DatagramTransport {
    private static final int MAX_FRAGMENT_LENGTH = 16384;
    static final int RECORD_HEADER_LENGTH = 13;
    private static final long RETRANSMIT_TIMEOUT = 240000;
    private static final long TCP_MSL = 120000;
    private final TlsContext context;
    private DTLSEpoch currentEpoch;
    private volatile boolean inConnection;
    private final TlsPeer peer;
    private DTLSEpoch pendingEpoch;
    private volatile int plaintextLimit;
    private DTLSEpoch readEpoch;
    private final DatagramTransport transport;
    private DTLSEpoch writeEpoch;
    private final ByteQueue recordQueue = new ByteQueue();
    private final Object writeLock = new Object();
    private volatile boolean closed = false;
    private volatile boolean failed = false;
    private volatile ProtocolVersion readVersion = null;
    private volatile ProtocolVersion writeVersion = null;
    private DTLSHandshakeRetransmit retransmit = null;
    private DTLSEpoch retransmitEpoch = null;
    private Timeout retransmitTimeout = null;
    private TlsHeartbeat heartbeat = null;
    private boolean heartBeatResponder = false;
    private HeartbeatMessage heartbeatInFlight = null;
    private Timeout heartbeatTimeout = null;
    private int heartbeatResendMillis = -1;
    private Timeout heartbeatResendTimeout = null;
    private volatile boolean inHandshake = true;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSRecordLayer(TlsContext tlsContext, TlsPeer tlsPeer, DatagramTransport datagramTransport) {
        this.context = tlsContext;
        this.peer = tlsPeer;
        this.transport = datagramTransport;
        DTLSEpoch dTLSEpoch = new DTLSEpoch(0, TlsNullNullCipher.INSTANCE, 13, 13);
        this.currentEpoch = dTLSEpoch;
        this.pendingEpoch = null;
        this.readEpoch = dTLSEpoch;
        this.writeEpoch = dTLSEpoch;
        setPlaintextLimit(16384);
    }

    private void closeTransport() {
        if (this.closed) {
            return;
        }
        try {
            if (!this.failed) {
                warn((short) 0, null);
            }
            this.transport.close();
        } catch (Exception unused) {
        }
        this.closed = true;
    }

    private static long getMacSequenceNumber(int i, long j) {
        return ((i & BodyPartID.bodyIdMax) << 48) | j;
    }

    private int processRecord(int i, byte[] bArr, byte[] bArr2, int i2, int i3, DTLSRecordCallback dTLSRecordCallback) throws IOException {
        DTLSEpoch dTLSEpoch;
        DTLSEpoch dTLSEpoch2;
        if (i < 13) {
            return -1;
        }
        short readUint8 = TlsUtils.readUint8(bArr, 0);
        switch (readUint8) {
            case 20:
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
                ProtocolVersion readVersion = TlsUtils.readVersion(bArr, 1);
                if (readVersion.isDTLS()) {
                    int readUint16 = TlsUtils.readUint16(bArr, 3);
                    if (readUint16 == this.readEpoch.getEpoch()) {
                        dTLSEpoch = this.readEpoch;
                    } else {
                        DTLSEpoch dTLSEpoch3 = this.retransmitEpoch;
                        dTLSEpoch = (dTLSEpoch3 != null && readUint16 == dTLSEpoch3.getEpoch() && readUint8 == 22) ? this.retransmitEpoch : null;
                    }
                    if (dTLSEpoch == null) {
                        return -1;
                    }
                    long readUint48 = TlsUtils.readUint48(bArr, 5);
                    if (dTLSEpoch.getReplayWindow().shouldDiscard(readUint48)) {
                        return -1;
                    }
                    int recordHeaderLengthRead = dTLSEpoch.getRecordHeaderLengthRead();
                    if (recordHeaderLengthRead > 13) {
                        if (25 != readUint8 || i < recordHeaderLengthRead) {
                            return -1;
                        }
                        byte[] connectionIDPeer = this.context.getSecurityParameters().getConnectionIDPeer();
                        if (!Arrays.constantTimeAreEqual(connectionIDPeer.length, connectionIDPeer, 0, bArr, 11)) {
                            return -1;
                        }
                    } else if (25 == readUint8) {
                        return -1;
                    }
                    int readUint162 = TlsUtils.readUint16(bArr, recordHeaderLengthRead - 2);
                    if (i != readUint162 + recordHeaderLengthRead) {
                        return -1;
                    }
                    if (this.readVersion != null && !this.readVersion.equals(readVersion)) {
                        if (getReadEpoch() != 0 || readUint162 <= 0 || 22 != readUint8 || 1 != TlsUtils.readUint8(bArr, recordHeaderLengthRead)) {
                            return -1;
                        }
                    }
                    try {
                        DTLSEpoch dTLSEpoch4 = dTLSEpoch;
                        TlsDecodeResult decodeCiphertext = dTLSEpoch.getCipher().decodeCiphertext(getMacSequenceNumber(dTLSEpoch.getEpoch(), readUint48), readUint8, readVersion, bArr, recordHeaderLengthRead, readUint162);
                        if (decodeCiphertext.len > this.plaintextLimit) {
                            return -1;
                        }
                        if (decodeCiphertext.len >= 1 || decodeCiphertext.contentType == 23) {
                            if (this.readVersion == null) {
                                if (getReadEpoch() != 0 || readUint162 <= 0 || 22 != readUint8 || 3 != TlsUtils.readUint8(bArr, recordHeaderLengthRead)) {
                                    this.readVersion = readVersion;
                                } else if (!ProtocolVersion.DTLSv12.isEqualOrLaterVersionOf(readVersion)) {
                                    return -1;
                                }
                            }
                            boolean reportAuthenticated = dTLSEpoch4.getReplayWindow().reportAuthenticated(readUint48);
                            if (dTLSRecordCallback != null) {
                                int i4 = (dTLSEpoch4 == this.readEpoch && reportAuthenticated) ? 1 : 0;
                                if (25 == readUint8) {
                                    i4 |= 2;
                                }
                                dTLSRecordCallback.recordAccepted(i4);
                            }
                            switch (decodeCiphertext.contentType) {
                                case 20:
                                    for (int i5 = 0; i5 < decodeCiphertext.len; i5++) {
                                        if (TlsUtils.readUint8(decodeCiphertext.buf, decodeCiphertext.off + i5) == 1 && (dTLSEpoch2 = this.pendingEpoch) != null) {
                                            this.readEpoch = dTLSEpoch2;
                                        }
                                    }
                                    return -1;
                                case 21:
                                    if (decodeCiphertext.len == 2) {
                                        short readUint82 = TlsUtils.readUint8(decodeCiphertext.buf, decodeCiphertext.off);
                                        short readUint83 = TlsUtils.readUint8(decodeCiphertext.buf, decodeCiphertext.off + 1);
                                        this.peer.notifyAlertReceived(readUint82, readUint83);
                                        if (readUint82 == 2) {
                                            failed();
                                            throw new TlsFatalAlert(readUint83);
                                        } else if (readUint83 == 0) {
                                            closeTransport();
                                        }
                                    }
                                    return -1;
                                case 22:
                                    if (!this.inHandshake) {
                                        DTLSHandshakeRetransmit dTLSHandshakeRetransmit = this.retransmit;
                                        if (dTLSHandshakeRetransmit != null) {
                                            dTLSHandshakeRetransmit.receivedHandshakeRecord(readUint16, decodeCiphertext.buf, decodeCiphertext.off, decodeCiphertext.len);
                                        }
                                        return -1;
                                    }
                                    break;
                                case 23:
                                    if (this.inHandshake) {
                                        return -1;
                                    }
                                    break;
                                case 24:
                                    if (this.heartbeatInFlight != null || this.heartBeatResponder) {
                                        try {
                                            HeartbeatMessage parse = HeartbeatMessage.parse(new ByteArrayInputStream(decodeCiphertext.buf, decodeCiphertext.off, decodeCiphertext.len));
                                            if (parse != null) {
                                                short type = parse.getType();
                                                if (type != 1) {
                                                    if (type == 2 && this.heartbeatInFlight != null && Arrays.areEqual(parse.getPayload(), this.heartbeatInFlight.getPayload())) {
                                                        resetHeartbeat();
                                                    }
                                                } else if (this.heartBeatResponder) {
                                                    sendHeartbeatMessage(HeartbeatMessage.create(this.context, (short) 2, parse.getPayload()));
                                                }
                                            }
                                        } catch (Exception unused) {
                                        }
                                    }
                                    return -1;
                                default:
                                    return -1;
                            }
                            if (!this.inHandshake && this.retransmit != null) {
                                this.retransmit = null;
                                this.retransmitEpoch = null;
                                this.retransmitTimeout = null;
                            }
                            if (decodeCiphertext.len <= i3) {
                                System.arraycopy(decodeCiphertext.buf, decodeCiphertext.off, bArr2, i2, decodeCiphertext.len);
                                return decodeCiphertext.len;
                            }
                            throw new TlsFatalAlert((short) 80);
                        }
                        return -1;
                    } catch (TlsFatalAlert e) {
                        if (20 == e.getAlertDescription()) {
                            return -1;
                        }
                        throw e;
                    }
                }
                return -1;
            default:
                return -1;
        }
    }

    private void raiseAlert(short s, short s2, String str, Throwable th) throws IOException {
        this.peer.notifyAlertRaised(s, s2, str, th);
        sendRecord((short) 21, new byte[]{(byte) s, (byte) s2}, 0, 2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int receiveClientHelloRecord(byte[] bArr, int i, int i2) throws IOException {
        int readUint16;
        if (i2 >= 13 && 22 == TlsUtils.readUint8(bArr, i)) {
            if (ProtocolVersion.DTLSv10.isEqualOrEarlierVersionOf(TlsUtils.readVersion(bArr, i + 1)) && TlsUtils.readUint16(bArr, i + 3) == 0 && (readUint16 = TlsUtils.readUint16(bArr, i + 11)) >= 1 && readUint16 <= 16384 && i2 >= readUint16 + 13 && 1 == TlsUtils.readUint8(bArr, i + 13)) {
                return readUint16;
            }
            return -1;
        }
        return -1;
    }

    private int receiveDatagram(byte[] bArr, int i, int i2, int i3) throws IOException {
        try {
            int receive = this.transport.receive(bArr, i, i2, i3);
            if (receive <= i2) {
                return receive;
            }
            return -1;
        } catch (SocketTimeoutException unused) {
            return -1;
        } catch (InterruptedIOException e) {
            e.bytesTransferred = 0;
            throw e;
        }
    }

    private int receivePendingRecord(byte[] bArr, int i, int i2) throws IOException {
        DTLSEpoch dTLSEpoch;
        int i3 = 13;
        if (this.recordQueue.available() >= 13) {
            int readUint16 = this.recordQueue.readUint16(3);
            if (readUint16 == this.readEpoch.getEpoch()) {
                dTLSEpoch = this.readEpoch;
            } else {
                DTLSEpoch dTLSEpoch2 = this.retransmitEpoch;
                dTLSEpoch = (dTLSEpoch2 == null || readUint16 != dTLSEpoch2.getEpoch()) ? null : this.retransmitEpoch;
            }
            if (dTLSEpoch == null) {
                ByteQueue byteQueue = this.recordQueue;
                byteQueue.removeData(byteQueue.available());
                return -1;
            }
            i3 = dTLSEpoch.getRecordHeaderLengthRead();
            if (this.recordQueue.available() >= i3) {
                i3 += this.recordQueue.readUint16(i3 - 2);
            }
        }
        int min = Math.min(this.recordQueue.available(), i3);
        this.recordQueue.removeData(bArr, i, min, 0);
        return min;
    }

    private int receiveRecord(byte[] bArr, int i, int i2, int i3) throws IOException {
        DTLSEpoch dTLSEpoch;
        int readUint16;
        if (this.recordQueue.available() > 0) {
            return receivePendingRecord(bArr, i, i2);
        }
        int receiveDatagram = receiveDatagram(bArr, i, i2, i3);
        if (receiveDatagram >= 13) {
            this.inConnection = true;
            int readUint162 = TlsUtils.readUint16(bArr, i + 3);
            if (readUint162 == this.readEpoch.getEpoch()) {
                dTLSEpoch = this.readEpoch;
            } else {
                DTLSEpoch dTLSEpoch2 = this.retransmitEpoch;
                dTLSEpoch = (dTLSEpoch2 == null || readUint162 != dTLSEpoch2.getEpoch()) ? null : this.retransmitEpoch;
            }
            if (dTLSEpoch == null) {
                return -1;
            }
            int recordHeaderLengthRead = dTLSEpoch.getRecordHeaderLengthRead();
            if (receiveDatagram < recordHeaderLengthRead || receiveDatagram <= (readUint16 = recordHeaderLengthRead + TlsUtils.readUint16(bArr, (i + recordHeaderLengthRead) - 2))) {
                return receiveDatagram;
            }
            this.recordQueue.addData(bArr, i + readUint16, receiveDatagram - readUint16);
            return readUint16;
        }
        return receiveDatagram;
    }

    private void resetHeartbeat() {
        this.heartbeatInFlight = null;
        this.heartbeatResendMillis = -1;
        this.heartbeatResendTimeout = null;
        this.heartbeatTimeout = new Timeout(this.heartbeat.getIdleMillis());
    }

    private static void sendDatagram(DatagramSender datagramSender, byte[] bArr, int i, int i2) throws IOException {
        try {
            datagramSender.send(bArr, i, i2);
        } catch (InterruptedIOException e) {
            e.bytesTransferred = 0;
            throw e;
        }
    }

    private void sendHeartbeatMessage(HeartbeatMessage heartbeatMessage) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        heartbeatMessage.encode(byteArrayOutputStream);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        sendRecord((short) 24, byteArray, 0, byteArray.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void sendHelloVerifyRequestRecord(DatagramSender datagramSender, long j, byte[] bArr) throws IOException {
        TlsUtils.checkUint16(bArr.length);
        int length = bArr.length + 13;
        byte[] bArr2 = new byte[length];
        TlsUtils.writeUint8((short) 22, bArr2, 0);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, bArr2, 1);
        TlsUtils.writeUint16(0, bArr2, 3);
        TlsUtils.writeUint48(j, bArr2, 5);
        TlsUtils.writeUint16(bArr.length, bArr2, 11);
        System.arraycopy(bArr, 0, bArr2, 13, bArr.length);
        sendDatagram(datagramSender, bArr2, 0, length);
    }

    private void sendRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        if (this.writeVersion == null) {
            return;
        }
        if (i2 > this.plaintextLimit) {
            throw new TlsFatalAlert((short) 80);
        }
        if (i2 < 1 && s != 23) {
            throw new TlsFatalAlert((short) 80);
        }
        synchronized (this.writeLock) {
            int epoch = this.writeEpoch.getEpoch();
            long allocateSequenceNumber = this.writeEpoch.allocateSequenceNumber();
            long macSequenceNumber = getMacSequenceNumber(epoch, allocateSequenceNumber);
            ProtocolVersion protocolVersion = this.writeVersion;
            int recordHeaderLengthWrite = this.writeEpoch.getRecordHeaderLengthWrite();
            TlsEncodeResult encodePlaintext = this.writeEpoch.getCipher().encodePlaintext(macSequenceNumber, s, protocolVersion, recordHeaderLengthWrite, bArr, i, i2);
            int i3 = encodePlaintext.len - recordHeaderLengthWrite;
            TlsUtils.checkUint16(i3);
            TlsUtils.writeUint8(encodePlaintext.recordType, encodePlaintext.buf, encodePlaintext.off);
            TlsUtils.writeVersion(protocolVersion, encodePlaintext.buf, encodePlaintext.off + 1);
            TlsUtils.writeUint16(epoch, encodePlaintext.buf, encodePlaintext.off + 3);
            TlsUtils.writeUint48(allocateSequenceNumber, encodePlaintext.buf, encodePlaintext.off + 5);
            if (recordHeaderLengthWrite > 13) {
                byte[] connectionIDLocal = this.context.getSecurityParameters().getConnectionIDLocal();
                System.arraycopy(connectionIDLocal, 0, encodePlaintext.buf, encodePlaintext.off + 11, connectionIDLocal.length);
            }
            TlsUtils.writeUint16(i3, encodePlaintext.buf, encodePlaintext.off + (recordHeaderLengthWrite - 2));
            sendDatagram(this.transport, encodePlaintext.buf, encodePlaintext.off, encodePlaintext.len);
        }
    }

    @Override // org.bouncycastle.tls.TlsCloseable
    public void close() throws IOException {
        if (this.closed) {
            return;
        }
        if (this.inHandshake && this.inConnection) {
            warn((short) 90, "User canceled handshake");
        }
        closeTransport();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void fail(short s) {
        if (this.closed) {
            return;
        }
        if (this.inConnection) {
            try {
                raiseAlert((short) 2, s, null, null);
            } catch (Exception unused) {
            }
        }
        this.failed = true;
        closeTransport();
    }

    void failed() {
        if (this.closed) {
            return;
        }
        this.failed = true;
        closeTransport();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getReadEpoch() {
        return this.readEpoch.getEpoch();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProtocolVersion getReadVersion() {
        return this.readVersion;
    }

    @Override // org.bouncycastle.tls.DatagramReceiver
    public int getReceiveLimit() throws IOException {
        return Math.min(this.plaintextLimit, this.readEpoch.getCipher().getPlaintextDecodeLimit(this.transport.getReceiveLimit() - this.readEpoch.getRecordHeaderLengthRead()));
    }

    @Override // org.bouncycastle.tls.DatagramSender
    public int getSendLimit() throws IOException {
        return Math.min(this.plaintextLimit, this.writeEpoch.getCipher().getPlaintextEncodeLimit(this.transport.getSendLimit() - this.writeEpoch.getRecordHeaderLengthWrite()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void handshakeSuccessful(DTLSHandshakeRetransmit dTLSHandshakeRetransmit) {
        DTLSEpoch dTLSEpoch = this.readEpoch;
        DTLSEpoch dTLSEpoch2 = this.currentEpoch;
        if (dTLSEpoch == dTLSEpoch2 || this.writeEpoch == dTLSEpoch2) {
            throw new IllegalStateException();
        }
        if (dTLSHandshakeRetransmit != null) {
            this.retransmit = dTLSHandshakeRetransmit;
            this.retransmitEpoch = dTLSEpoch2;
            this.retransmitTimeout = new Timeout(RETRANSMIT_TIMEOUT);
        }
        this.inHandshake = false;
        this.currentEpoch = this.pendingEpoch;
        this.pendingEpoch = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initHeartbeat(TlsHeartbeat tlsHeartbeat, boolean z) {
        if (this.inHandshake) {
            throw new IllegalStateException();
        }
        this.heartbeat = tlsHeartbeat;
        this.heartBeatResponder = z;
        if (tlsHeartbeat != null) {
            resetHeartbeat();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void initPendingEpoch(TlsCipher tlsCipher) {
        if (this.pendingEpoch != null) {
            throw new IllegalStateException();
        }
        SecurityParameters securityParameters = this.context.getSecurityParameters();
        byte[] connectionIDLocal = securityParameters.getConnectionIDLocal();
        byte[] connectionIDPeer = securityParameters.getConnectionIDPeer();
        this.pendingEpoch = new DTLSEpoch(this.writeEpoch.getEpoch() + 1, tlsCipher, (connectionIDPeer != null ? connectionIDPeer.length : 0) + 13, (connectionIDLocal != null ? connectionIDLocal.length : 0) + 13);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isClosed() {
        return this.closed;
    }

    @Override // org.bouncycastle.tls.DatagramReceiver
    public int receive(byte[] bArr, int i, int i2, int i3) throws IOException {
        return receive(bArr, i, i2, i3, null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00b5 A[LOOP:0: B:3:0x000d->B:32:0x00b5, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b4 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public int receive(byte[] r13, int r14, int r15, int r16, org.bouncycastle.tls.DTLSRecordCallback r17) throws java.io.IOException {
        /*
            r12 = this;
            r7 = r12
            long r0 = java.lang.System.currentTimeMillis()
            r2 = r16
            org.bouncycastle.tls.Timeout r8 = org.bouncycastle.tls.Timeout.forWaitMillis(r2, r0)
            r9 = 0
            r3 = r9
        Ld:
            if (r2 < 0) goto Lc0
            org.bouncycastle.tls.Timeout r4 = r7.retransmitTimeout
            if (r4 == 0) goto L23
            long r4 = r4.remainingMillis(r0)
            r10 = 1
            int r4 = (r4 > r10 ? 1 : (r4 == r10 ? 0 : -1))
            if (r4 >= 0) goto L23
            r7.retransmit = r9
            r7.retransmitEpoch = r9
            r7.retransmitTimeout = r9
        L23:
            org.bouncycastle.tls.Timeout r4 = r7.heartbeatTimeout
            boolean r4 = org.bouncycastle.tls.Timeout.hasExpired(r4, r0)
            r5 = 1
            if (r4 == 0) goto L65
            org.bouncycastle.tls.HeartbeatMessage r4 = r7.heartbeatInFlight
            if (r4 != 0) goto L5d
            org.bouncycastle.tls.TlsContext r4 = r7.context
            org.bouncycastle.tls.TlsHeartbeat r6 = r7.heartbeat
            byte[] r6 = r6.generatePayload()
            org.bouncycastle.tls.HeartbeatMessage r4 = org.bouncycastle.tls.HeartbeatMessage.create(r4, r5, r6)
            r7.heartbeatInFlight = r4
            org.bouncycastle.tls.Timeout r4 = new org.bouncycastle.tls.Timeout
            org.bouncycastle.tls.TlsHeartbeat r6 = r7.heartbeat
            int r6 = r6.getTimeoutMillis()
            long r10 = (long) r6
            r4.<init>(r10, r0)
            r7.heartbeatTimeout = r4
            org.bouncycastle.tls.TlsPeer r4 = r7.peer
            int r4 = r4.getHandshakeResendTimeMillis()
            r7.heartbeatResendMillis = r4
            org.bouncycastle.tls.Timeout r4 = new org.bouncycastle.tls.Timeout
            int r6 = r7.heartbeatResendMillis
            long r10 = (long) r6
            r4.<init>(r10, r0)
            goto L7d
        L5d:
            org.bouncycastle.tls.TlsTimeoutException r0 = new org.bouncycastle.tls.TlsTimeoutException
            java.lang.String r1 = "Heartbeat timed out"
            r0.<init>(r1)
            throw r0
        L65:
            org.bouncycastle.tls.Timeout r4 = r7.heartbeatResendTimeout
            boolean r4 = org.bouncycastle.tls.Timeout.hasExpired(r4, r0)
            if (r4 == 0) goto L84
            int r4 = r7.heartbeatResendMillis
            int r4 = org.bouncycastle.tls.DTLSReliableHandshake.backOff(r4)
            r7.heartbeatResendMillis = r4
            org.bouncycastle.tls.Timeout r4 = new org.bouncycastle.tls.Timeout
            int r6 = r7.heartbeatResendMillis
            long r10 = (long) r6
            r4.<init>(r10, r0)
        L7d:
            r7.heartbeatResendTimeout = r4
            org.bouncycastle.tls.HeartbeatMessage r4 = r7.heartbeatInFlight
            r12.sendHeartbeatMessage(r4)
        L84:
            org.bouncycastle.tls.Timeout r4 = r7.heartbeatTimeout
            int r2 = org.bouncycastle.tls.Timeout.constrainWaitMillis(r2, r4, r0)
            org.bouncycastle.tls.Timeout r4 = r7.heartbeatResendTimeout
            int r0 = org.bouncycastle.tls.Timeout.constrainWaitMillis(r2, r4, r0)
            if (r0 >= 0) goto L93
            goto L94
        L93:
            r5 = r0
        L94:
            org.bouncycastle.tls.DatagramTransport r0 = r7.transport
            int r0 = r0.getReceiveLimit()
            if (r3 == 0) goto L9f
            int r1 = r3.length
            if (r1 >= r0) goto La1
        L9f:
            byte[] r3 = new byte[r0]
        La1:
            r10 = r3
            r1 = 0
            int r1 = r12.receiveRecord(r10, r1, r0, r5)
            r0 = r12
            r2 = r10
            r3 = r13
            r4 = r14
            r5 = r15
            r6 = r17
            int r0 = r0.processRecord(r1, r2, r3, r4, r5, r6)
            if (r0 < 0) goto Lb5
            return r0
        Lb5:
            long r0 = java.lang.System.currentTimeMillis()
            int r2 = org.bouncycastle.tls.Timeout.getWaitMillis(r8, r0)
            r3 = r10
            goto Ld
        Lc0:
            r0 = -1
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.DTLSRecordLayer.receive(byte[], int, int, int, org.bouncycastle.tls.DTLSRecordCallback):int");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int receivePending(byte[] bArr, int i, int i2, DTLSRecordCallback dTLSRecordCallback) throws IOException {
        if (this.recordQueue.available() > 0) {
            int available = this.recordQueue.available();
            byte[] bArr2 = new byte[available];
            do {
                int processRecord = processRecord(receivePendingRecord(bArr2, 0, available), bArr2, bArr, i, i2, dTLSRecordCallback);
                if (processRecord >= 0) {
                    return processRecord;
                }
            } while (this.recordQueue.available() > 0);
            return -1;
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resetAfterHelloVerifyRequestServer(long j) {
        this.inConnection = true;
        this.currentEpoch.setSequenceNumber(j);
        this.currentEpoch.getReplayWindow().reset(j);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resetWriteEpoch() {
        DTLSEpoch dTLSEpoch = this.retransmitEpoch;
        if (dTLSEpoch == null) {
            dTLSEpoch = this.currentEpoch;
        }
        this.writeEpoch = dTLSEpoch;
    }

    @Override // org.bouncycastle.tls.DatagramSender
    public void send(byte[] bArr, int i, int i2) throws IOException {
        short s;
        if (this.inHandshake || this.writeEpoch == this.retransmitEpoch) {
            if (TlsUtils.readUint8(bArr, i) == 20) {
                DTLSEpoch dTLSEpoch = this.inHandshake ? this.pendingEpoch : this.writeEpoch == this.retransmitEpoch ? this.currentEpoch : null;
                if (dTLSEpoch == null) {
                    throw new IllegalStateException();
                }
                sendRecord((short) 20, new byte[]{1}, 0, 1);
                this.writeEpoch = dTLSEpoch;
            }
            s = 22;
        } else {
            s = 23;
        }
        sendRecord(s, bArr, i, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPlaintextLimit(int i) {
        this.plaintextLimit = i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setReadVersion(ProtocolVersion protocolVersion) {
        this.readVersion = protocolVersion;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setWriteVersion(ProtocolVersion protocolVersion) {
        this.writeVersion = protocolVersion;
    }

    void warn(short s, String str) throws IOException {
        raiseAlert((short) 1, s, str, null);
    }
}