package org.bouncycastle.tls;

/* loaded from: classes2.dex */
class DTLSReplayWindow {
    private static final long VALID_SEQ_MASK = 281474976710655L;
    private static final long WINDOW_SIZE = 64;
    private long latestConfirmedSeq = -1;
    private long bitmap = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean reportAuthenticated(long j) {
        if ((VALID_SEQ_MASK & j) == j) {
            long j2 = this.latestConfirmedSeq;
            if (j <= j2) {
                long j3 = j2 - j;
                if (j3 < WINDOW_SIZE) {
                    this.bitmap |= 1 << ((int) j3);
                    return false;
                }
                return false;
            }
            long j4 = j - j2;
            if (j4 >= WINDOW_SIZE) {
                this.bitmap = 1L;
            } else {
                this.bitmap = (this.bitmap << ((int) j4)) | 1;
            }
            this.latestConfirmedSeq = j;
            return true;
        }
        throw new IllegalArgumentException("'seq' out of range");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reset(long j) {
        if ((VALID_SEQ_MASK & j) != j) {
            throw new IllegalArgumentException("'seq' out of range");
        }
        this.latestConfirmedSeq = j;
        this.bitmap = (-1) >>> ((int) Math.max(0L, 63 - j));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean shouldDiscard(long j) {
        if ((VALID_SEQ_MASK & j) != j) {
            return true;
        }
        long j2 = this.latestConfirmedSeq;
        if (j <= j2) {
            long j3 = j2 - j;
            return j3 >= WINDOW_SIZE || (this.bitmap & (1 << ((int) j3))) != 0;
        }
        return false;
    }
}