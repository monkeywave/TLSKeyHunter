package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface Committer {
    Commitment commit(byte[] bArr);

    boolean isRevealed(Commitment commitment, byte[] bArr);
}