package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
class DTLSReliableHandshake {
    private static final int MAX_RECEIVE_AHEAD = 16;
    private static final int MAX_RESEND_MILLIS = 60000;
    static final int MESSAGE_HEADER_LENGTH = 12;
    private TlsHandshakeHash handshakeHash;
    private Timeout handshakeTimeout;
    private int initialResendMillis;
    private int next_receive_seq;
    private int next_send_seq;
    private DTLSRecordLayer recordLayer;
    private int resendMillis;
    private Timeout resendTimeout;
    private Hashtable currentInboundFlight = new Hashtable();
    private Hashtable previousInboundFlight = null;
    private Vector outboundFlight = new Vector();

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class Message {
        private final byte[] body;
        private final int message_seq;
        private final short msg_type;

        private Message(int i, short s, byte[] bArr) {
            this.message_seq = i;
            this.msg_type = s;
            this.body = bArr;
        }

        public byte[] getBody() {
            return this.body;
        }

        public int getSeq() {
            return this.message_seq;
        }

        public short getType() {
            return this.msg_type;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class RecordLayerBuffer extends ByteArrayOutputStream {
        RecordLayerBuffer(int i) {
            super(i);
        }

        void sendToRecordLayer(DTLSRecordLayer dTLSRecordLayer) throws IOException {
            dTLSRecordLayer.send(this.buf, 0, this.count);
            this.buf = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSReliableHandshake(TlsContext tlsContext, DTLSRecordLayer dTLSRecordLayer, int i, int i2, DTLSRequest dTLSRequest) {
        this.resendMillis = -1;
        this.resendTimeout = null;
        this.next_send_seq = 0;
        this.next_receive_seq = 0;
        this.recordLayer = dTLSRecordLayer;
        this.handshakeHash = new DeferredHash(tlsContext);
        this.handshakeTimeout = Timeout.forWaitMillis(i);
        this.initialResendMillis = i2;
        if (dTLSRequest != null) {
            this.resendMillis = i2;
            this.resendTimeout = new Timeout(this.resendMillis);
            long recordSeq = dTLSRequest.getRecordSeq();
            int messageSeq = dTLSRequest.getMessageSeq();
            byte[] message = dTLSRequest.getMessage();
            this.recordLayer.resetAfterHelloVerifyRequestServer(recordSeq);
            this.currentInboundFlight.put(Integers.valueOf(messageSeq), new DTLSReassembler((short) 1, message.length - 12));
            this.next_send_seq = 1;
            this.next_receive_seq = messageSeq + 1;
            this.handshakeHash.update(message, 0, message.length);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int backOff(int i) {
        return Math.min(i * 2, (int) MAX_RESEND_MILLIS);
    }

    private static boolean checkAll(Hashtable hashtable) {
        Enumeration elements = hashtable.elements();
        while (elements.hasMoreElements()) {
            if (((DTLSReassembler) elements.nextElement()).getBodyIfComplete() == null) {
                return false;
            }
        }
        return true;
    }

    private void checkInboundFlight() {
        Enumeration keys = this.currentInboundFlight.keys();
        while (keys.hasMoreElements()) {
            ((Integer) keys.nextElement()).intValue();
        }
    }

    private Message getPendingMessage() throws IOException {
        byte[] bodyIfComplete;
        DTLSReassembler dTLSReassembler = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(this.next_receive_seq));
        if (dTLSReassembler == null || (bodyIfComplete = dTLSReassembler.getBodyIfComplete()) == null) {
            return null;
        }
        this.previousInboundFlight = null;
        int i = this.next_receive_seq;
        this.next_receive_seq = i + 1;
        return new Message(i, dTLSReassembler.getMsgType(), bodyIfComplete);
    }

    private Message implReceiveMessage() throws IOException {
        long currentTimeMillis = System.currentTimeMillis();
        if (this.resendTimeout == null) {
            this.resendMillis = this.initialResendMillis;
            this.resendTimeout = new Timeout(this.resendMillis, currentTimeMillis);
            prepareInboundFlight(new Hashtable());
        }
        byte[] bArr = null;
        while (!this.recordLayer.isClosed()) {
            Message pendingMessage = getPendingMessage();
            if (pendingMessage != null) {
                return pendingMessage;
            }
            if (Timeout.hasExpired(this.handshakeTimeout, currentTimeMillis)) {
                throw new TlsTimeoutException("Handshake timed out");
            }
            int constrainWaitMillis = Timeout.constrainWaitMillis(Timeout.getWaitMillis(this.handshakeTimeout, currentTimeMillis), this.resendTimeout, currentTimeMillis);
            if (constrainWaitMillis < 1) {
                constrainWaitMillis = 1;
            }
            int receiveLimit = this.recordLayer.getReceiveLimit();
            if (bArr == null || bArr.length < receiveLimit) {
                bArr = new byte[receiveLimit];
            }
            int receive = this.recordLayer.receive(bArr, 0, receiveLimit, constrainWaitMillis);
            if (receive < 0) {
                resendOutboundFlight();
            } else {
                processRecord(16, this.recordLayer.getReadEpoch(), bArr, 0, receive);
            }
            currentTimeMillis = System.currentTimeMillis();
        }
        throw new TlsFatalAlert((short) 90);
    }

    private void prepareInboundFlight(Hashtable hashtable) {
        resetAll(this.currentInboundFlight);
        this.previousInboundFlight = this.currentInboundFlight;
        this.currentInboundFlight = hashtable;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processRecord(int i, int i2, byte[] bArr, int i3, int i4) throws IOException {
        int readUint24;
        int readUint242;
        DTLSReassembler dTLSReassembler;
        int i5 = i3;
        int i6 = i4;
        boolean z = false;
        while (i6 >= 12 && i6 >= (readUint242 = (readUint24 = TlsUtils.readUint24(bArr, i5 + 9)) + 12)) {
            int readUint243 = TlsUtils.readUint24(bArr, i5 + 1);
            int readUint244 = TlsUtils.readUint24(bArr, i5 + 6);
            if (readUint244 + readUint24 > readUint243) {
                break;
            }
            short readUint8 = TlsUtils.readUint8(bArr, i5);
            if (i2 != (readUint8 == 20 ? 1 : 0)) {
                break;
            }
            int readUint16 = TlsUtils.readUint16(bArr, i5 + 4);
            int i7 = this.next_receive_seq;
            if (readUint16 < i7 + i) {
                if (readUint16 >= i7) {
                    DTLSReassembler dTLSReassembler2 = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(readUint16));
                    if (dTLSReassembler2 == null) {
                        dTLSReassembler2 = new DTLSReassembler(readUint8, readUint243);
                        this.currentInboundFlight.put(Integers.valueOf(readUint16), dTLSReassembler2);
                    }
                    dTLSReassembler2.contributeFragment(readUint8, readUint243, bArr, i5 + 12, readUint244, readUint24);
                } else {
                    Hashtable hashtable = this.previousInboundFlight;
                    if (hashtable != null && (dTLSReassembler = (DTLSReassembler) hashtable.get(Integers.valueOf(readUint16))) != null) {
                        dTLSReassembler.contributeFragment(readUint8, readUint243, bArr, i5 + 12, readUint244, readUint24);
                        z = true;
                    }
                }
            }
            i5 += readUint242;
            i6 -= readUint242;
        }
        if (z && checkAll(this.previousInboundFlight)) {
            resendOutboundFlight();
            resetAll(this.previousInboundFlight);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ByteArrayInputStream receiveClientHelloMessage(byte[] bArr, int i, int i2) throws IOException {
        if (i2 >= 12 && 1 == TlsUtils.readUint8(bArr, i)) {
            int readUint24 = TlsUtils.readUint24(bArr, i + 1);
            if (i2 == readUint24 + 12 && TlsUtils.readUint24(bArr, i + 6) == 0 && readUint24 == TlsUtils.readUint24(bArr, i + 9)) {
                return new ByteArrayInputStream(bArr, i + 12, readUint24);
            }
            return null;
        }
        return null;
    }

    private void resendOutboundFlight() throws IOException {
        this.recordLayer.resetWriteEpoch();
        for (int i = 0; i < this.outboundFlight.size(); i++) {
            writeMessage((Message) this.outboundFlight.elementAt(i));
        }
        this.resendMillis = backOff(this.resendMillis);
        this.resendTimeout = new Timeout(this.resendMillis);
    }

    private static void resetAll(Hashtable hashtable) {
        Enumeration elements = hashtable.elements();
        while (elements.hasMoreElements()) {
            ((DTLSReassembler) elements.nextElement()).reset();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void sendHelloVerifyRequest(DatagramSender datagramSender, long j, byte[] bArr) throws IOException {
        TlsUtils.checkUint8(bArr.length);
        int length = bArr.length;
        int i = length + 3;
        byte[] bArr2 = new byte[length + 15];
        TlsUtils.writeUint8((short) 3, bArr2, 0);
        TlsUtils.writeUint24(i, bArr2, 1);
        TlsUtils.writeUint24(i, bArr2, 9);
        TlsUtils.writeVersion(ProtocolVersion.DTLSv10, bArr2, 12);
        TlsUtils.writeOpaque8(bArr, bArr2, 14);
        DTLSRecordLayer.sendHelloVerifyRequestRecord(datagramSender, j, bArr2);
    }

    private void writeHandshakeFragment(Message message, int i, int i2) throws IOException {
        RecordLayerBuffer recordLayerBuffer = new RecordLayerBuffer(i2 + 12);
        TlsUtils.writeUint8(message.getType(), (OutputStream) recordLayerBuffer);
        TlsUtils.writeUint24(message.getBody().length, recordLayerBuffer);
        TlsUtils.writeUint16(message.getSeq(), recordLayerBuffer);
        TlsUtils.writeUint24(i, recordLayerBuffer);
        TlsUtils.writeUint24(i2, recordLayerBuffer);
        recordLayerBuffer.write(message.getBody(), i, i2);
        recordLayerBuffer.sendToRecordLayer(this.recordLayer);
    }

    private void writeMessage(Message message) throws IOException {
        int sendLimit = this.recordLayer.getSendLimit() - 12;
        if (sendLimit < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        int length = message.getBody().length;
        int i = 0;
        do {
            int min = Math.min(length - i, sendLimit);
            writeHandshakeFragment(message, i, min);
            i += min;
        } while (i < length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void finish() {
        DTLSHandshakeRetransmit dTLSHandshakeRetransmit = null;
        if (this.resendTimeout != null) {
            checkInboundFlight();
        } else {
            prepareInboundFlight(null);
            if (this.previousInboundFlight != null) {
                dTLSHandshakeRetransmit = new DTLSHandshakeRetransmit() { // from class: org.bouncycastle.tls.DTLSReliableHandshake.1
                    @Override // org.bouncycastle.tls.DTLSHandshakeRetransmit
                    public void receivedHandshakeRecord(int i, byte[] bArr, int i2, int i3) throws IOException {
                        DTLSReliableHandshake.this.processRecord(0, i, bArr, i2, i3);
                    }
                };
            }
        }
        this.recordLayer.handshakeSuccessful(dTLSHandshakeRetransmit);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsHandshakeHash getHandshakeHash() {
        return this.handshakeHash;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void prepareToFinish() {
        this.handshakeHash.stopTracking();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Message receiveMessage() throws IOException {
        Message implReceiveMessage = implReceiveMessage();
        updateHandshakeMessagesDigest(implReceiveMessage);
        return implReceiveMessage;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] receiveMessageBody(short s) throws IOException {
        Message implReceiveMessage = implReceiveMessage();
        if (implReceiveMessage.getType() == s) {
            updateHandshakeMessagesDigest(implReceiveMessage);
            return implReceiveMessage.getBody();
        }
        throw new TlsFatalAlert((short) 10);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Message receiveMessageDelayedDigest(short s) throws IOException {
        Message implReceiveMessage = implReceiveMessage();
        if (implReceiveMessage.getType() == s) {
            return implReceiveMessage;
        }
        throw new TlsFatalAlert((short) 10);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void resetAfterHelloVerifyRequestClient() {
        this.currentInboundFlight = new Hashtable();
        this.previousInboundFlight = null;
        this.outboundFlight = new Vector();
        this.resendMillis = -1;
        this.resendTimeout = null;
        this.next_receive_seq = 1;
        this.handshakeHash.reset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void sendMessage(short s, byte[] bArr) throws IOException {
        TlsUtils.checkUint24(bArr.length);
        if (this.resendTimeout != null) {
            checkInboundFlight();
            this.resendMillis = -1;
            this.resendTimeout = null;
            this.outboundFlight.removeAllElements();
        }
        int i = this.next_send_seq;
        this.next_send_seq = i + 1;
        Message message = new Message(i, s, bArr);
        this.outboundFlight.addElement(message);
        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateHandshakeMessagesDigest(Message message) throws IOException {
        short type = message.getType();
        if (type == 0 || type == 3 || type == 24) {
            return;
        }
        byte[] body = message.getBody();
        byte[] bArr = new byte[12];
        TlsUtils.writeUint8(type, bArr, 0);
        TlsUtils.writeUint24(body.length, bArr, 1);
        TlsUtils.writeUint16(message.getSeq(), bArr, 4);
        TlsUtils.writeUint24(0, bArr, 6);
        TlsUtils.writeUint24(body.length, bArr, 9);
        this.handshakeHash.update(bArr, 0, 12);
        this.handshakeHash.update(body, 0, body.length);
    }
}