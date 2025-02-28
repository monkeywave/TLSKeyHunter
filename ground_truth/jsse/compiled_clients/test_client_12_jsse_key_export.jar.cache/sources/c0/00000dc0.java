package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/Fors.class */
class Fors {
    private final WotsPlus wots;
    SPHINCSPlusEngine engine;

    public Fors(SPHINCSPlusEngine sPHINCSPlusEngine) {
        this.engine = sPHINCSPlusEngine;
        this.wots = new WotsPlus(sPHINCSPlusEngine);
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [byte[], byte[][]] */
    byte[] pkGen(byte[] bArr, byte[] bArr2, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        ?? r0 = new byte[this.engine.f915K];
        for (int i = 0; i < this.engine.f915K; i++) {
            r0[i] = treehash(bArr, i * this.engine.f917T, this.engine.f914A, bArr2, adrs);
        }
        adrs2.setType(4);
        adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(bArr2, adrs2, Arrays.concatenate(r0));
    }

    byte[] treehash(byte[] bArr, int i, int i2, byte[] bArr2, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        LinkedList linkedList = new LinkedList();
        if (i % (1 << i2) != 0) {
            return null;
        }
        for (int i3 = 0; i3 < (1 << i2); i3++) {
            adrs2.setTreeHeight(0);
            adrs2.setTreeIndex(i + i3);
            byte[] mo4F = this.engine.mo4F(bArr2, adrs2, this.engine.PRF(bArr, adrs2));
            adrs2.setTreeHeight(1);
            adrs2.setTreeIndex(i + i3);
            while (!linkedList.isEmpty() && ((NodeEntry) linkedList.get(0)).nodeHeight == adrs2.getTreeHeight()) {
                adrs2.setTreeIndex((adrs2.getTreeIndex() - 1) / 2);
                mo4F = this.engine.mo3H(bArr2, adrs2, ((NodeEntry) linkedList.remove(0)).nodeValue, mo4F);
                adrs2.setTreeHeight(adrs2.getTreeHeight() + 1);
            }
            linkedList.add(0, new NodeEntry(mo4F, adrs2.getTreeHeight()));
        }
        return ((NodeEntry) linkedList.get(0)).nodeValue;
    }

    /* JADX WARN: Type inference failed for: r0v22, types: [byte[], byte[][]] */
    public SIG_FORS[] sign(byte[] bArr, byte[] bArr2, byte[] bArr3, ADRS adrs) {
        int[] message_to_idxs = message_to_idxs(bArr, this.engine.f915K, this.engine.f914A);
        SIG_FORS[] sig_forsArr = new SIG_FORS[this.engine.f915K];
        int i = this.engine.f917T;
        for (int i2 = 0; i2 < this.engine.f915K; i2++) {
            int i3 = message_to_idxs[i2];
            adrs.setTreeHeight(0);
            adrs.setTreeIndex((i2 * i) + i3);
            byte[] PRF = this.engine.PRF(bArr2, adrs);
            ?? r0 = new byte[this.engine.f914A];
            for (int i4 = 0; i4 < this.engine.f914A; i4++) {
                r0[i4] = treehash(bArr2, (i2 * i) + (((i3 / (1 << i4)) ^ 1) * (1 << i4)), i4, bArr3, adrs);
            }
            sig_forsArr[i2] = new SIG_FORS(PRF, r0);
        }
        return sig_forsArr;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v5, types: [byte[], byte[][]] */
    public byte[] pkFromSig(SIG_FORS[] sig_forsArr, byte[] bArr, byte[] bArr2, ADRS adrs) {
        byte[] bArr3 = new byte[2];
        ?? r0 = new byte[this.engine.f915K];
        int i = this.engine.f917T;
        int[] message_to_idxs = message_to_idxs(bArr, this.engine.f915K, this.engine.f914A);
        for (int i2 = 0; i2 < this.engine.f915K; i2++) {
            int i3 = message_to_idxs[i2];
            byte[] sk = sig_forsArr[i2].getSK();
            adrs.setTreeHeight(0);
            adrs.setTreeIndex((i2 * i) + i3);
            bArr3[0] = this.engine.mo4F(bArr2, adrs, sk);
            byte[][] authPath = sig_forsArr[i2].getAuthPath();
            adrs.setTreeIndex((i2 * i) + i3);
            for (int i4 = 0; i4 < this.engine.f914A; i4++) {
                adrs.setTreeHeight(i4 + 1);
                if ((i3 / (1 << i4)) % 2 == 0) {
                    adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                    bArr3[1] = this.engine.mo3H(bArr2, adrs, bArr3[0], authPath[i4]);
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    bArr3[1] = this.engine.mo3H(bArr2, adrs, authPath[i4], bArr3[0]);
                }
                bArr3[0] = bArr3[1];
            }
            r0[i2] = bArr3[0];
        }
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setType(4);
        adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(bArr2, adrs2, Arrays.concatenate(r0));
    }

    static int[] message_to_idxs(byte[] bArr, int i, int i2) {
        int i3 = 0;
        int[] iArr = new int[i];
        for (int i4 = 0; i4 < i; i4++) {
            iArr[i4] = 0;
            for (int i5 = 0; i5 < i2; i5++) {
                int i6 = i4;
                iArr[i6] = iArr[i6] ^ (((bArr[i3 >> 3] >> (i3 & 7)) & 1) << i5);
                i3++;
            }
        }
        return iArr;
    }
}