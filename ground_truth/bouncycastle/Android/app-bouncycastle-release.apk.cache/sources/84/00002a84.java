package org.bouncycastle.pqc.crypto.slhdsa;

import java.math.BigInteger;
import java.util.LinkedList;
import kotlin.UByte;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class Fors {
    SLHDSAEngine engine;

    public Fors(SLHDSAEngine sLHDSAEngine) {
        this.engine = sLHDSAEngine;
    }

    static int[] base2B(byte[] bArr, int i, int i2) {
        int[] iArr = new int[i2];
        BigInteger bigInteger = BigInteger.ZERO;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            while (i4 < i) {
                bigInteger = bigInteger.shiftLeft(8).add(BigInteger.valueOf(bArr[i3] & UByte.MAX_VALUE));
                i3++;
                i4 += 8;
            }
            i4 -= i;
            iArr[i5] = bigInteger.shiftRight(i4).mod(BigInteger.valueOf(2L).pow(i)).intValue();
        }
        return iArr;
    }

    public byte[] pkFromSig(SIG_FORS[] sig_forsArr, byte[] bArr, byte[] bArr2, ADRS adrs) {
        int i = 2;
        byte[][] bArr3 = new byte[2];
        byte[][] bArr4 = new byte[this.engine.f1403K];
        int i2 = this.engine.f1405T;
        int[] base2B = base2B(bArr, this.engine.f1400A, this.engine.f1403K);
        int i3 = 0;
        while (i3 < this.engine.f1403K) {
            int i4 = base2B[i3];
            byte[] sk = sig_forsArr[i3].getSK();
            adrs.setTreeHeight(0);
            int i5 = (i3 * i2) + i4;
            adrs.setTreeIndex(i5);
            bArr3[0] = this.engine.mo15F(bArr2, adrs, sk);
            byte[][] authPath = sig_forsArr[i3].getAuthPath();
            adrs.setTreeIndex(i5);
            int i6 = 0;
            while (i6 < this.engine.f1400A) {
                int i7 = i6 + 1;
                adrs.setTreeHeight(i7);
                if ((i4 / (1 << i6)) % i == 0) {
                    adrs.setTreeIndex(adrs.getTreeIndex() / i);
                    bArr3[1] = this.engine.mo14H(bArr2, adrs, bArr3[0], authPath[i6]);
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    bArr3[1] = this.engine.mo14H(bArr2, adrs, authPath[i6], bArr3[0]);
                }
                bArr3[0] = bArr3[1];
                i6 = i7;
                i = 2;
            }
            bArr4[i3] = bArr3[0];
            i3++;
            i = 2;
        }
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setTypeAndClear(4);
        adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(bArr2, adrs2, Arrays.concatenate(bArr4));
    }

    public SIG_FORS[] sign(byte[] bArr, byte[] bArr2, byte[] bArr3, ADRS adrs) {
        Fors fors = this;
        ADRS adrs2 = new ADRS(adrs);
        int[] base2B = base2B(bArr, fors.engine.f1400A, fors.engine.f1403K);
        SIG_FORS[] sig_forsArr = new SIG_FORS[fors.engine.f1403K];
        int i = fors.engine.f1405T;
        int i2 = 0;
        int i3 = 0;
        while (i3 < fors.engine.f1403K) {
            int i4 = base2B[i3];
            adrs2.setTypeAndClear(6);
            adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
            adrs2.setTreeHeight(i2);
            int i5 = i3 * i;
            adrs2.setTreeIndex(i5 + i4);
            byte[] PRF = fors.engine.PRF(bArr3, bArr2, adrs2);
            adrs2.changeType(3);
            byte[][] bArr4 = new byte[fors.engine.f1400A];
            int i6 = i2;
            while (i6 < fors.engine.f1400A) {
                int i7 = 1 << i6;
                int i8 = i6;
                byte[][] bArr5 = bArr4;
                bArr5[i8] = treehash(bArr2, i5 + (((i4 / i7) ^ 1) * i7), i8, bArr3, adrs2);
                i6 = i8 + 1;
                PRF = PRF;
                bArr4 = bArr5;
                fors = this;
            }
            sig_forsArr[i3] = new SIG_FORS(PRF, bArr4);
            i3++;
            i2 = 0;
            fors = this;
        }
        return sig_forsArr;
    }

    byte[] treehash(byte[] bArr, int i, int i2, byte[] bArr2, ADRS adrs) {
        if (((i >>> i2) << i2) != i) {
            return null;
        }
        LinkedList linkedList = new LinkedList();
        ADRS adrs2 = new ADRS(adrs);
        for (int i3 = 0; i3 < (1 << i2); i3++) {
            adrs2.setTypeAndClear(6);
            adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
            adrs2.setTreeHeight(0);
            int i4 = i + i3;
            adrs2.setTreeIndex(i4);
            byte[] PRF = this.engine.PRF(bArr2, bArr, adrs2);
            adrs2.changeType(3);
            byte[] mo15F = this.engine.mo15F(bArr2, adrs2, PRF);
            adrs2.setTreeHeight(1);
            int i5 = 1;
            while (!linkedList.isEmpty() && ((NodeEntry) linkedList.get(0)).nodeHeight == i5) {
                i4 = (i4 - 1) / 2;
                adrs2.setTreeIndex(i4);
                mo15F = this.engine.mo14H(bArr2, adrs2, ((NodeEntry) linkedList.remove(0)).nodeValue, mo15F);
                i5++;
                adrs2.setTreeHeight(i5);
            }
            linkedList.add(0, new NodeEntry(mo15F, i5));
        }
        return ((NodeEntry) linkedList.get(0)).nodeValue;
    }
}