package org.bouncycastle.crypto.commitments;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.Committer;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/commitments/HashCommitter.class */
public class HashCommitter implements Committer {
    private final Digest digest;
    private final int byteLength;
    private final SecureRandom random;

    public HashCommitter(ExtendedDigest extendedDigest, SecureRandom secureRandom) {
        this.digest = extendedDigest;
        this.byteLength = extendedDigest.getByteLength();
        this.random = secureRandom;
    }

    @Override // org.bouncycastle.crypto.Committer
    public Commitment commit(byte[] bArr) {
        if (bArr.length > this.byteLength / 2) {
            throw new DataLengthException("Message to be committed to too large for digest.");
        }
        byte[] bArr2 = new byte[this.byteLength - bArr.length];
        this.random.nextBytes(bArr2);
        return new Commitment(bArr2, calculateCommitment(bArr2, bArr));
    }

    @Override // org.bouncycastle.crypto.Committer
    public boolean isRevealed(Commitment commitment, byte[] bArr) {
        if (bArr.length + commitment.getSecret().length != this.byteLength) {
            throw new DataLengthException("Message and witness secret lengths do not match.");
        }
        return Arrays.constantTimeAreEqual(commitment.getCommitment(), calculateCommitment(commitment.getSecret(), bArr));
    }

    private byte[] calculateCommitment(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[this.digest.getDigestSize()];
        this.digest.update(bArr, 0, bArr.length);
        this.digest.update(bArr2, 0, bArr2.length);
        this.digest.doFinal(bArr3, 0);
        return bArr3;
    }
}