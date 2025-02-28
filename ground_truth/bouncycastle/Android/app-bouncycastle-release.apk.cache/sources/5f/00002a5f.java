package org.bouncycastle.pqc.crypto.picnic;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Signature2 {
    int[] challengeC;
    byte[] challengeHash;
    int[] challengeP;
    byte[] cvInfo;
    int cvInfoLen;
    byte[] iSeedInfo;
    int iSeedInfoLen;
    Proof2[] proofs;
    byte[] salt = new byte[32];

    /* loaded from: classes2.dex */
    public static class Proof2 {

        /* renamed from: C */
        byte[] f1369C;
        byte[] aux;
        byte[] input;
        byte[] msgs;
        byte[] seedInfo = null;
        int seedInfoLen = 0;

        public Proof2(PicnicEngine picnicEngine) {
            this.f1369C = new byte[picnicEngine.digestSizeBytes];
            this.input = new byte[picnicEngine.stateSizeBytes];
            this.aux = new byte[picnicEngine.andSizeBytes];
            this.msgs = new byte[picnicEngine.andSizeBytes];
        }
    }

    public Signature2(PicnicEngine picnicEngine) {
        this.challengeHash = new byte[picnicEngine.digestSizeBytes];
        this.challengeC = new int[picnicEngine.numOpenedRounds];
        this.challengeP = new int[picnicEngine.numOpenedRounds];
        this.proofs = new Proof2[picnicEngine.numMPCRounds];
    }
}