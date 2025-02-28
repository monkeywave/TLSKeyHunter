package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCipher;

/* loaded from: classes2.dex */
class DTLSEpoch {
    private final TlsCipher cipher;
    private final int epoch;
    private final int recordHeaderLengthRead;
    private final int recordHeaderLengthWrite;
    private final DTLSReplayWindow replayWindow = new DTLSReplayWindow();
    private long sequenceNumber = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSEpoch(int i, TlsCipher tlsCipher, int i2, int i3) {
        if (i < 0) {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        }
        if (tlsCipher == null) {
            throw new IllegalArgumentException("'cipher' cannot be null");
        }
        this.epoch = i;
        this.cipher = tlsCipher;
        this.recordHeaderLengthRead = i2;
        this.recordHeaderLengthWrite = i3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized long allocateSequenceNumber() throws IOException {
        long j;
        j = this.sequenceNumber;
        if (j >= 281474976710656L) {
            throw new TlsFatalAlert((short) 80);
        }
        this.sequenceNumber = 1 + j;
        return j;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsCipher getCipher() {
        return this.cipher;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getEpoch() {
        return this.epoch;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getRecordHeaderLengthRead() {
        return this.recordHeaderLengthRead;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getRecordHeaderLengthWrite() {
        return this.recordHeaderLengthWrite;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSReplayWindow getReplayWindow() {
        return this.replayWindow;
    }

    synchronized long getSequenceNumber() {
        return this.sequenceNumber;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized void setSequenceNumber(long j) {
        this.sequenceNumber = j;
    }
}