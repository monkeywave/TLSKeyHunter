package org.bouncycastle.tls;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDecodeResult;
import org.bouncycastle.tls.crypto.TlsEncodeResult;
import org.bouncycastle.tls.crypto.TlsNullNullCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class RecordStream {
    private static int DEFAULT_PLAINTEXT_LIMIT = 16384;
    private int ciphertextLimit;
    private TlsProtocol handler;
    private boolean ignoreChangeCipherSpec;
    private InputStream input;
    private OutputStream output;
    private int plaintextLimit;
    private final Record inputRecord = new Record();
    private final SequenceNumber readSeqNo = new SequenceNumber();
    private final SequenceNumber writeSeqNo = new SequenceNumber();
    private TlsCipher pendingCipher = null;
    private TlsCipher readCipher = TlsNullNullCipher.INSTANCE;
    private TlsCipher readCipherDeferred = null;
    private TlsCipher writeCipher = TlsNullNullCipher.INSTANCE;
    private ProtocolVersion writeVersion = null;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static class Record {
        volatile byte[] buf;
        private final byte[] header;
        volatile int pos;

        private Record() {
            byte[] bArr = new byte[5];
            this.header = bArr;
            this.buf = bArr;
            this.pos = 0;
        }

        private void resize(int i) {
            if (this.buf.length < i) {
                byte[] bArr = new byte[i];
                System.arraycopy(this.buf, 0, bArr, 0, this.pos);
                this.buf = bArr;
            }
        }

        void fillTo(InputStream inputStream, int i) throws IOException {
            while (this.pos < i) {
                try {
                    int read = inputStream.read(this.buf, this.pos, i - this.pos);
                    if (read < 0) {
                        return;
                    }
                    this.pos += read;
                } catch (InterruptedIOException e) {
                    this.pos += e.bytesTransferred;
                    e.bytesTransferred = 0;
                    throw e;
                }
            }
        }

        void readFragment(InputStream inputStream, int i) throws IOException {
            int i2 = i + 5;
            resize(i2);
            fillTo(inputStream, i2);
            if (this.pos < i2) {
                throw new EOFException();
            }
        }

        boolean readHeader(InputStream inputStream) throws IOException {
            fillTo(inputStream, 5);
            if (this.pos == 0) {
                return false;
            }
            if (this.pos >= 5) {
                return true;
            }
            throw new EOFException();
        }

        void reset() {
            this.buf = this.header;
            this.pos = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public static class SequenceNumber {
        private boolean exhausted;
        private long value;

        private SequenceNumber() {
            this.value = 0L;
            this.exhausted = false;
        }

        synchronized long currentValue() {
            return this.value;
        }

        synchronized long nextValue(short s) throws TlsFatalAlert {
            long j;
            if (this.exhausted) {
                throw new TlsFatalAlert(s, "Sequence numbers exhausted");
            }
            j = this.value;
            long j2 = 1 + j;
            this.value = j2;
            if (j2 == 0) {
                this.exhausted = true;
            }
            return j;
        }

        synchronized void reset() {
            this.value = 0L;
            this.exhausted = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RecordStream(TlsProtocol tlsProtocol, InputStream inputStream, OutputStream outputStream) {
        int i = DEFAULT_PLAINTEXT_LIMIT;
        this.plaintextLimit = i;
        this.ciphertextLimit = i;
        this.ignoreChangeCipherSpec = false;
        this.handler = tlsProtocol;
        this.input = inputStream;
        this.output = outputStream;
    }

    private void checkChangeCipherSpec(byte[] bArr, int i, int i2) throws IOException {
        if (1 != i2 || 1 != bArr[i]) {
            throw new TlsFatalAlert((short) 10, "Malformed " + ContentType.getText((short) 20));
        }
    }

    private static void checkLength(int i, int i2, short s) throws IOException {
        if (i > i2) {
            throw new TlsFatalAlert(s);
        }
    }

    private short checkRecordType(byte[] bArr, int i) throws IOException {
        short readUint8 = TlsUtils.readUint8(bArr, i);
        TlsCipher tlsCipher = this.readCipherDeferred;
        if (tlsCipher != null && readUint8 == 23) {
            this.readCipher = tlsCipher;
            this.readCipherDeferred = null;
            this.ciphertextLimit = tlsCipher.getCiphertextDecodeLimit(this.plaintextLimit);
            this.readSeqNo.reset();
        } else if (!this.readCipher.usesOpaqueRecordTypeDecode()) {
            switch (readUint8) {
                case 20:
                case 21:
                case 22:
                    break;
                default:
                    throw new TlsFatalAlert((short) 10, "Unsupported " + ContentType.getText(readUint8));
                case 23:
                    if (!this.handler.isApplicationDataReady()) {
                        throw new TlsFatalAlert((short) 10, "Not ready for " + ContentType.getText((short) 23));
                    }
                    break;
            }
        } else if (23 != readUint8 && (!this.ignoreChangeCipherSpec || 20 != readUint8)) {
            throw new TlsFatalAlert((short) 10, "Opaque " + ContentType.getText(readUint8));
        }
        return readUint8;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void close() throws IOException {
        this.inputRecord.reset();
        try {
            this.input.close();
            e = null;
        } catch (IOException e) {
            e = e;
        }
        try {
            this.output.close();
        } catch (IOException e2) {
            if (e == null) {
                e = e2;
            }
        }
        if (e != null) {
            throw e;
        }
    }

    TlsDecodeResult decodeAndVerify(short s, ProtocolVersion protocolVersion, byte[] bArr, int i, int i2) throws IOException {
        TlsDecodeResult decodeCiphertext = this.readCipher.decodeCiphertext(this.readSeqNo.nextValue((short) 10), s, protocolVersion, bArr, i, i2);
        checkLength(decodeCiphertext.len, this.plaintextLimit, (short) 22);
        if (decodeCiphertext.len >= 1 || decodeCiphertext.contentType == 23) {
            return decodeCiphertext;
        }
        throw new TlsFatalAlert((short) 47);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void enablePendingCipherRead(boolean z) throws IOException {
        TlsCipher tlsCipher = this.pendingCipher;
        if (tlsCipher == null) {
            throw new TlsFatalAlert((short) 80);
        }
        if (this.readCipherDeferred != null) {
            throw new TlsFatalAlert((short) 80);
        }
        if (z) {
            this.readCipherDeferred = tlsCipher;
            return;
        }
        this.readCipher = tlsCipher;
        this.ciphertextLimit = tlsCipher.getCiphertextDecodeLimit(this.plaintextLimit);
        this.readSeqNo.reset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void enablePendingCipherWrite() throws IOException {
        TlsCipher tlsCipher = this.pendingCipher;
        if (tlsCipher == null) {
            throw new TlsFatalAlert((short) 80);
        }
        this.writeCipher = tlsCipher;
        this.writeSeqNo.reset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void finaliseHandshake() throws IOException {
        TlsCipher tlsCipher = this.readCipher;
        TlsCipher tlsCipher2 = this.pendingCipher;
        if (tlsCipher != tlsCipher2 || this.writeCipher != tlsCipher2) {
            throw new TlsFatalAlert((short) 40);
        }
        this.pendingCipher = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getPlaintextLimit() {
        return this.plaintextLimit;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean needsKeyUpdate() {
        return this.writeSeqNo.currentValue() >= 1048576;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void notifyChangeCipherSpecReceived() throws IOException {
        if (this.pendingCipher == null) {
            throw new TlsFatalAlert((short) 10, "No pending cipher");
        }
        enablePendingCipherRead(false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void notifyKeyUpdateReceived() throws IOException {
        this.readCipher.rekeyDecoder();
        this.readSeqNo.reset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void notifyKeyUpdateSent() throws IOException {
        this.writeCipher.rekeyEncoder();
        this.writeSeqNo.reset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RecordPreview previewOutputRecord(int i) {
        int max = Math.max(0, Math.min(this.plaintextLimit, i));
        return new RecordPreview(previewOutputRecordSize(max), max);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int previewOutputRecordSize(int i) {
        return this.writeCipher.getCiphertextEncodeLimit(i) + 5;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RecordPreview previewRecordHeader(byte[] bArr) throws IOException {
        int i = 0;
        short checkRecordType = checkRecordType(bArr, 0);
        int readUint16 = TlsUtils.readUint16(bArr, 3);
        checkLength(readUint16, this.ciphertextLimit, (short) 22);
        int i2 = readUint16 + 5;
        if (23 == checkRecordType && this.handler.isApplicationDataReady()) {
            i = Math.max(0, Math.min(this.plaintextLimit, this.readCipher.getPlaintextDecodeLimit(readUint16)));
        }
        return new RecordPreview(i2, i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean readFullRecord(byte[] bArr, int i, int i2) throws IOException {
        if (i2 < 5) {
            return false;
        }
        int readUint16 = TlsUtils.readUint16(bArr, i + 3);
        if (i2 != readUint16 + 5) {
            return false;
        }
        short checkRecordType = checkRecordType(bArr, i);
        ProtocolVersion readVersion = TlsUtils.readVersion(bArr, i + 1);
        checkLength(readUint16, this.ciphertextLimit, (short) 22);
        if (this.ignoreChangeCipherSpec && 20 == checkRecordType) {
            checkChangeCipherSpec(bArr, i + 5, readUint16);
            return true;
        }
        TlsDecodeResult decodeAndVerify = decodeAndVerify(checkRecordType, readVersion, bArr, i + 5, readUint16);
        this.handler.processRecord(decodeAndVerify.contentType, decodeAndVerify.buf, decodeAndVerify.off, decodeAndVerify.len);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean readRecord() throws IOException {
        if (this.inputRecord.readHeader(this.input)) {
            short checkRecordType = checkRecordType(this.inputRecord.buf, 0);
            ProtocolVersion readVersion = TlsUtils.readVersion(this.inputRecord.buf, 1);
            int readUint16 = TlsUtils.readUint16(this.inputRecord.buf, 3);
            checkLength(readUint16, this.ciphertextLimit, (short) 22);
            this.inputRecord.readFragment(this.input, readUint16);
            try {
                if (this.ignoreChangeCipherSpec && 20 == checkRecordType) {
                    checkChangeCipherSpec(this.inputRecord.buf, 5, readUint16);
                    return true;
                }
                TlsDecodeResult decodeAndVerify = decodeAndVerify(checkRecordType, readVersion, this.inputRecord.buf, 5, readUint16);
                this.inputRecord.reset();
                this.handler.processRecord(decodeAndVerify.contentType, decodeAndVerify.buf, decodeAndVerify.off, decodeAndVerify.len);
                return true;
            } finally {
                this.inputRecord.reset();
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setIgnoreChangeCipherSpec(boolean z) {
        this.ignoreChangeCipherSpec = z;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPendingCipher(TlsCipher tlsCipher) {
        this.pendingCipher = tlsCipher;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPlaintextLimit(int i) {
        this.plaintextLimit = i;
        this.ciphertextLimit = this.readCipher.getCiphertextDecodeLimit(i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setWriteVersion(ProtocolVersion protocolVersion) {
        this.writeVersion = protocolVersion;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void writeRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        if (this.writeVersion == null) {
            return;
        }
        checkLength(i2, this.plaintextLimit, (short) 80);
        if (i2 < 1 && s != 23) {
            throw new TlsFatalAlert((short) 80);
        }
        long nextValue = this.writeSeqNo.nextValue((short) 80);
        ProtocolVersion protocolVersion = this.writeVersion;
        TlsEncodeResult encodePlaintext = this.writeCipher.encodePlaintext(nextValue, s, protocolVersion, 5, bArr, i, i2);
        int i3 = encodePlaintext.len - 5;
        TlsUtils.checkUint16(i3);
        TlsUtils.writeUint8(encodePlaintext.recordType, encodePlaintext.buf, encodePlaintext.off);
        TlsUtils.writeVersion(protocolVersion, encodePlaintext.buf, encodePlaintext.off + 1);
        TlsUtils.writeUint16(i3, encodePlaintext.buf, encodePlaintext.off + 3);
        try {
            this.output.write(encodePlaintext.buf, encodePlaintext.off, encodePlaintext.len);
            this.output.flush();
        } catch (InterruptedIOException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}