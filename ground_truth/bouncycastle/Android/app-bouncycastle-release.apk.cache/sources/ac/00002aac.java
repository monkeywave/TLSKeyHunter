package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.pqc.crypto.sphincsplus.HT */
/* loaded from: classes2.dex */
class C1402HT {
    SPHINCSPlusEngine engine;
    final byte[] htPubKey;
    private final byte[] pkSeed;
    private final byte[] skSeed;
    WotsPlus wots;

    public C1402HT(SPHINCSPlusEngine sPHINCSPlusEngine, byte[] bArr, byte[] bArr2) {
        this.skSeed = bArr;
        this.pkSeed = bArr2;
        this.engine = sPHINCSPlusEngine;
        this.wots = new WotsPlus(sPHINCSPlusEngine);
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(sPHINCSPlusEngine.f1426D - 1);
        adrs.setTreeAddress(0L);
        if (bArr != null) {
            this.htPubKey = xmss_PKgen(bArr, bArr2, adrs);
        } else {
            this.htPubKey = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] sign(byte[] bArr, long j, int i) {
        long j2 = j;
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j2);
        SIG_XMSS xmss_sign = xmss_sign(bArr, this.skSeed, i, this.pkSeed, adrs);
        int i2 = this.engine.f1426D;
        SIG_XMSS[] sig_xmssArr = new SIG_XMSS[i2];
        sig_xmssArr[0] = xmss_sign;
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j2);
        byte[] xmss_pkFromSig = xmss_pkFromSig(i, xmss_sign, bArr, this.pkSeed, adrs);
        for (int i3 = 1; i3 < this.engine.f1426D; i3++) {
            int i4 = (int) (((1 << this.engine.H_PRIME) - 1) & j2);
            j2 >>>= this.engine.H_PRIME;
            adrs.setLayerAddress(i3);
            adrs.setTreeAddress(j2);
            SIG_XMSS xmss_sign2 = xmss_sign(xmss_pkFromSig, this.skSeed, i4, this.pkSeed, adrs);
            sig_xmssArr[i3] = xmss_sign2;
            if (i3 < this.engine.f1426D - 1) {
                xmss_pkFromSig = xmss_pkFromSig(i4, xmss_sign2, xmss_pkFromSig, this.pkSeed, adrs);
            }
        }
        byte[][] bArr2 = new byte[i2];
        for (int i5 = 0; i5 != i2; i5++) {
            bArr2[i5] = Arrays.concatenate(sig_xmssArr[i5].sig, Arrays.concatenate(sig_xmssArr[i5].auth));
        }
        return Arrays.concatenate(bArr2);
    }

    byte[] treehash(byte[] bArr, int i, int i2, byte[] bArr2, ADRS adrs) {
        if (((i >>> i2) << i2) != i) {
            return null;
        }
        LinkedList linkedList = new LinkedList();
        ADRS adrs2 = new ADRS(adrs);
        for (int i3 = 0; i3 < (1 << i2); i3++) {
            adrs2.setTypeAndClear(0);
            int i4 = i + i3;
            adrs2.setKeyPairAddress(i4);
            byte[] pkGen = this.wots.pkGen(bArr, bArr2, adrs2);
            adrs2.setTypeAndClear(2);
            adrs2.setTreeHeight(1);
            adrs2.setTreeIndex(i4);
            int i5 = 1;
            while (!linkedList.isEmpty() && ((NodeEntry) linkedList.get(0)).nodeHeight == i5) {
                i4 = (i4 - 1) / 2;
                adrs2.setTreeIndex(i4);
                pkGen = this.engine.mo12H(bArr2, adrs2, ((NodeEntry) linkedList.remove(0)).nodeValue, pkGen);
                i5++;
                adrs2.setTreeHeight(i5);
            }
            linkedList.add(0, new NodeEntry(pkGen, i5));
        }
        return ((NodeEntry) linkedList.get(0)).nodeValue;
    }

    public boolean verify(byte[] bArr, SIG_XMSS[] sig_xmssArr, byte[] bArr2, long j, int i, byte[] bArr3) {
        ADRS adrs = new ADRS();
        SIG_XMSS sig_xmss = sig_xmssArr[0];
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        byte[] xmss_pkFromSig = xmss_pkFromSig(i, sig_xmss, bArr, bArr2, adrs);
        for (int i2 = 1; i2 < this.engine.f1426D; i2++) {
            int i3 = (int) (((1 << this.engine.H_PRIME) - 1) & j);
            j >>>= this.engine.H_PRIME;
            SIG_XMSS sig_xmss2 = sig_xmssArr[i2];
            adrs.setLayerAddress(i2);
            adrs.setTreeAddress(j);
            xmss_pkFromSig = xmss_pkFromSig(i3, sig_xmss2, xmss_pkFromSig, bArr2, adrs);
        }
        return Arrays.areEqual(bArr3, xmss_pkFromSig);
    }

    byte[] xmss_PKgen(byte[] bArr, byte[] bArr2, ADRS adrs) {
        return treehash(bArr, 0, this.engine.H_PRIME, bArr2, adrs);
    }

    byte[] xmss_pkFromSig(int i, SIG_XMSS sig_xmss, byte[] bArr, byte[] bArr2, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        int i2 = 0;
        adrs2.setTypeAndClear(0);
        adrs2.setKeyPairAddress(i);
        byte[] wOTSSig = sig_xmss.getWOTSSig();
        byte[][] xmssauth = sig_xmss.getXMSSAUTH();
        byte[] pkFromSig = this.wots.pkFromSig(wOTSSig, bArr, bArr2, adrs2);
        adrs2.setTypeAndClear(2);
        adrs2.setTreeIndex(i);
        while (i2 < this.engine.H_PRIME) {
            int i3 = i2 + 1;
            adrs2.setTreeHeight(i3);
            if ((i / (1 << i2)) % 2 == 0) {
                adrs2.setTreeIndex(adrs2.getTreeIndex() / 2);
                pkFromSig = this.engine.mo12H(bArr2, adrs2, pkFromSig, xmssauth[i2]);
            } else {
                adrs2.setTreeIndex((adrs2.getTreeIndex() - 1) / 2);
                pkFromSig = this.engine.mo12H(bArr2, adrs2, xmssauth[i2], pkFromSig);
            }
            i2 = i3;
        }
        return pkFromSig;
    }

    SIG_XMSS xmss_sign(byte[] bArr, byte[] bArr2, int i, byte[] bArr3, ADRS adrs) {
        byte[][] bArr4 = new byte[this.engine.H_PRIME];
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setTypeAndClear(2);
        adrs2.setLayerAddress(adrs.getLayerAddress());
        adrs2.setTreeAddress(adrs.getTreeAddress());
        for (int i2 = 0; i2 < this.engine.H_PRIME; i2++) {
            bArr4[i2] = treehash(bArr2, ((i >>> i2) ^ 1) << i2, i2, bArr3, adrs2);
        }
        ADRS adrs3 = new ADRS(adrs);
        adrs3.setTypeAndClear(0);
        adrs3.setKeyPairAddress(i);
        return new SIG_XMSS(this.wots.sign(bArr, bArr2, bArr3, adrs3), bArr4);
    }
}