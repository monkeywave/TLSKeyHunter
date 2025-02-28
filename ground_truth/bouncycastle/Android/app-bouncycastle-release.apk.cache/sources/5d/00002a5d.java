package org.bouncycastle.pqc.crypto.picnic;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Signature {
    final byte[] challengeBits;
    final Proof[] proofs;
    final byte[] salt = new byte[32];

    /* loaded from: classes2.dex */
    public static class Proof {
        final byte[] communicatedBits;
        final int[] inputShare;
        final byte[] seed1;
        final byte[] seed2;
        final byte[] view3Commitment;
        final byte[] view3UnruhG;

        Proof(PicnicEngine picnicEngine) {
            this.seed1 = new byte[picnicEngine.seedSizeBytes];
            this.seed2 = new byte[picnicEngine.seedSizeBytes];
            this.inputShare = new int[picnicEngine.stateSizeWords];
            this.communicatedBits = new byte[picnicEngine.andSizeBytes];
            this.view3Commitment = new byte[picnicEngine.digestSizeBytes];
            if (picnicEngine.UnruhGWithInputBytes > 0) {
                this.view3UnruhG = new byte[picnicEngine.UnruhGWithInputBytes];
            } else {
                this.view3UnruhG = null;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Signature(PicnicEngine picnicEngine) {
        this.challengeBits = new byte[Utils.numBytes(picnicEngine.numMPCRounds * 2)];
        this.proofs = new Proof[picnicEngine.numMPCRounds];
        int i = 0;
        while (true) {
            Proof[] proofArr = this.proofs;
            if (i >= proofArr.length) {
                return;
            }
            proofArr[i] = new Proof(picnicEngine);
            i++;
        }
    }
}