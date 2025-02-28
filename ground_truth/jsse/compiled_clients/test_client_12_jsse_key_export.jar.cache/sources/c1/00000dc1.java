package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.pqc.crypto.sphincsplus.HT */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/HT.class */
class C0329HT {
    private final byte[] skSeed;
    private final byte[] pkSeed;
    SPHINCSPlusEngine engine;
    WotsPlus wots;
    final byte[] htPubKey;

    public C0329HT(SPHINCSPlusEngine sPHINCSPlusEngine, byte[] bArr, byte[] bArr2) {
        this.skSeed = bArr;
        this.pkSeed = bArr2;
        this.engine = sPHINCSPlusEngine;
        this.wots = new WotsPlus(sPHINCSPlusEngine);
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(sPHINCSPlusEngine.f913D - 1);
        adrs.setTreeAddress(0L);
        if (bArr != null) {
            this.htPubKey = xmss_PKgen(bArr, bArr2, adrs);
        } else {
            this.htPubKey = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Type inference failed for: r0v18, types: [byte[], byte[][]] */
    public byte[] sign(byte[] bArr, long j, int i) {
        ADRS adrs = new ADRS();
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        SIG_XMSS xmss_sign = xmss_sign(bArr, this.skSeed, i, this.pkSeed, adrs);
        SIG_XMSS[] sig_xmssArr = new SIG_XMSS[this.engine.f913D];
        sig_xmssArr[0] = xmss_sign;
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        byte[] xmss_pkFromSig = xmss_pkFromSig(i, xmss_sign, bArr, this.pkSeed, adrs);
        for (int i2 = 1; i2 < this.engine.f913D; i2++) {
            int i3 = (int) (j & ((1 << this.engine.H_PRIME) - 1));
            j >>>= this.engine.H_PRIME;
            adrs.setLayerAddress(i2);
            adrs.setTreeAddress(j);
            SIG_XMSS xmss_sign2 = xmss_sign(xmss_pkFromSig, this.skSeed, i3, this.pkSeed, adrs);
            sig_xmssArr[i2] = xmss_sign2;
            if (i2 < this.engine.f913D - 1) {
                xmss_pkFromSig = xmss_pkFromSig(i3, xmss_sign2, xmss_pkFromSig, this.pkSeed, adrs);
            }
        }
        ?? r0 = new byte[sig_xmssArr.length];
        for (int i4 = 0; i4 != r0.length; i4++) {
            r0[i4] = Arrays.concatenate(sig_xmssArr[i4].sig, Arrays.concatenate(sig_xmssArr[i4].auth));
        }
        return Arrays.concatenate(r0);
    }

    byte[] xmss_PKgen(byte[] bArr, byte[] bArr2, ADRS adrs) {
        return treehash(bArr, 0, this.engine.H_PRIME, bArr2, adrs);
    }

    byte[] xmss_pkFromSig(int i, SIG_XMSS sig_xmss, byte[] bArr, byte[] bArr2, ADRS adrs) {
        byte[] mo3H;
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setType(0);
        adrs2.setKeyPairAddress(i);
        byte[] wOTSSig = sig_xmss.getWOTSSig();
        byte[][] xmssauth = sig_xmss.getXMSSAUTH();
        byte[] pkFromSig = this.wots.pkFromSig(wOTSSig, bArr, bArr2, adrs2);
        adrs2.setType(2);
        adrs2.setTreeIndex(i);
        for (int i2 = 0; i2 < this.engine.H_PRIME; i2++) {
            adrs2.setTreeHeight(i2 + 1);
            if ((i / (1 << i2)) % 2 == 0) {
                adrs2.setTreeIndex(adrs2.getTreeIndex() / 2);
                mo3H = this.engine.mo3H(bArr2, adrs2, pkFromSig, xmssauth[i2]);
            } else {
                adrs2.setTreeIndex((adrs2.getTreeIndex() - 1) / 2);
                mo3H = this.engine.mo3H(bArr2, adrs2, xmssauth[i2], pkFromSig);
            }
            pkFromSig = mo3H;
        }
        return pkFromSig;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [byte[], byte[][]] */
    SIG_XMSS xmss_sign(byte[] bArr, byte[] bArr2, int i, byte[] bArr3, ADRS adrs) {
        ?? r0 = new byte[this.engine.H_PRIME];
        for (int i2 = 0; i2 < this.engine.H_PRIME; i2++) {
            r0[i2] = treehash(bArr2, ((i / (1 << i2)) ^ 1) * (1 << i2), i2, bArr3, adrs);
        }
        ADRS adrs2 = new ADRS(adrs);
        adrs2.setType(0);
        adrs2.setKeyPairAddress(i);
        return new SIG_XMSS(this.wots.sign(bArr, bArr2, bArr3, adrs2), r0);
    }

    byte[] treehash(byte[] bArr, int i, int i2, byte[] bArr2, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        LinkedList linkedList = new LinkedList();
        if (i % (1 << i2) != 0) {
            return null;
        }
        for (int i3 = 0; i3 < (1 << i2); i3++) {
            adrs2.setType(0);
            adrs2.setKeyPairAddress(i + i3);
            byte[] pkGen = this.wots.pkGen(bArr, bArr2, adrs2);
            adrs2.setType(2);
            adrs2.setTreeHeight(1);
            adrs2.setTreeIndex(i + i3);
            while (!linkedList.isEmpty() && ((NodeEntry) linkedList.get(0)).nodeHeight == adrs2.getTreeHeight()) {
                adrs2.setTreeIndex((adrs2.getTreeIndex() - 1) / 2);
                pkGen = this.engine.mo3H(bArr2, adrs2, ((NodeEntry) linkedList.remove(0)).nodeValue, pkGen);
                adrs2.setTreeHeight(adrs2.getTreeHeight() + 1);
            }
            linkedList.add(0, new NodeEntry(pkGen, adrs2.getTreeHeight()));
        }
        return ((NodeEntry) linkedList.get(0)).nodeValue;
    }

    public boolean verify(byte[] bArr, SIG_XMSS[] sig_xmssArr, byte[] bArr2, long j, int i, byte[] bArr3) {
        ADRS adrs = new ADRS();
        SIG_XMSS sig_xmss = sig_xmssArr[0];
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(j);
        byte[] xmss_pkFromSig = xmss_pkFromSig(i, sig_xmss, bArr, bArr2, adrs);
        for (int i2 = 1; i2 < this.engine.f913D; i2++) {
            int i3 = (int) (j & ((1 << this.engine.H_PRIME) - 1));
            j >>>= this.engine.H_PRIME;
            SIG_XMSS sig_xmss2 = sig_xmssArr[i2];
            adrs.setLayerAddress(i2);
            adrs.setTreeAddress(j);
            xmss_pkFromSig = xmss_pkFromSig(i3, sig_xmss2, xmss_pkFromSig, bArr2, adrs);
        }
        return Arrays.areEqual(bArr3, xmss_pkFromSig);
    }
}