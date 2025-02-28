package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/WotsPlus.class */
class WotsPlus {
    private final SPHINCSPlusEngine engine;

    /* renamed from: w */
    private final int f921w;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WotsPlus(SPHINCSPlusEngine sPHINCSPlusEngine) {
        this.engine = sPHINCSPlusEngine;
        this.f921w = this.engine.WOTS_W;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Type inference failed for: r0v4, types: [byte[], byte[][]] */
    public byte[] pkGen(byte[] bArr, byte[] bArr2, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        ?? r0 = new byte[this.engine.WOTS_LEN];
        for (int i = 0; i < this.engine.WOTS_LEN; i++) {
            ADRS adrs3 = new ADRS(adrs);
            adrs3.setChainAddress(i);
            adrs3.setHashAddress(0);
            r0[i] = chain(this.engine.PRF(bArr, adrs3), 0, this.f921w - 1, bArr2, adrs3);
        }
        adrs2.setType(1);
        adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(bArr2, adrs2, Arrays.concatenate(r0));
    }

    byte[] chain(byte[] bArr, int i, int i2, byte[] bArr2, ADRS adrs) {
        if (i2 == 0) {
            return Arrays.clone(bArr);
        }
        if (i + i2 > this.f921w - 1) {
            return null;
        }
        byte[] chain = chain(bArr, i, i2 - 1, bArr2, adrs);
        adrs.setHashAddress((i + i2) - 1);
        return this.engine.mo4F(bArr2, adrs, chain);
    }

    /* JADX WARN: Type inference failed for: r0v23, types: [byte[], byte[][]] */
    public byte[] sign(byte[] bArr, byte[] bArr2, byte[] bArr3, ADRS adrs) {
        ADRS adrs2 = new ADRS(adrs);
        int i = 0;
        int[] base_w = base_w(bArr, this.f921w, this.engine.WOTS_LEN1);
        for (int i2 = 0; i2 < this.engine.WOTS_LEN1; i2++) {
            i += (this.f921w - 1) - base_w[i2];
        }
        if (this.engine.WOTS_LOGW % 8 != 0) {
            i <<= 8 - ((this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW) % 8);
        }
        int i3 = ((this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW) + 7) / 8;
        byte[] intToBigEndian = Pack.intToBigEndian(i);
        int[] concatenate = Arrays.concatenate(base_w, base_w(Arrays.copyOfRange(intToBigEndian, i3, intToBigEndian.length), this.f921w, this.engine.WOTS_LEN2));
        ?? r0 = new byte[this.engine.WOTS_LEN];
        for (int i4 = 0; i4 < this.engine.WOTS_LEN; i4++) {
            adrs2.setChainAddress(i4);
            adrs2.setHashAddress(0);
            r0[i4] = chain(this.engine.PRF(bArr2, adrs2), 0, concatenate[i4], bArr3, adrs2);
        }
        return Arrays.concatenate(r0);
    }

    int[] base_w(byte[] bArr, int i, int i2) {
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        int[] iArr = new int[i2];
        for (int i7 = 0; i7 < i2; i7++) {
            if (i6 == 0) {
                i5 = bArr[i3];
                i3++;
                i6 += 8;
            }
            i6 -= this.engine.WOTS_LOGW;
            iArr[i4] = (i5 >>> i6) & (i - 1);
            i4++;
        }
        return iArr;
    }

    /* JADX WARN: Type inference failed for: r0v23, types: [byte[], byte[][]] */
    public byte[] pkFromSig(byte[] bArr, byte[] bArr2, byte[] bArr3, ADRS adrs) {
        int i = 0;
        ADRS adrs2 = new ADRS(adrs);
        int[] base_w = base_w(bArr2, this.f921w, this.engine.WOTS_LEN1);
        for (int i2 = 0; i2 < this.engine.WOTS_LEN1; i2++) {
            i += (this.f921w - 1) - base_w[i2];
        }
        int[] concatenate = Arrays.concatenate(base_w, base_w(Arrays.copyOfRange(Pack.intToBigEndian(i << (8 - ((this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW) % 8))), 4 - (((this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW) + 7) / 8), 4), this.f921w, this.engine.WOTS_LEN2));
        byte[] bArr4 = new byte[this.engine.f912N];
        ?? r0 = new byte[this.engine.WOTS_LEN];
        for (int i3 = 0; i3 < this.engine.WOTS_LEN; i3++) {
            adrs.setChainAddress(i3);
            System.arraycopy(bArr, i3 * this.engine.f912N, bArr4, 0, this.engine.f912N);
            r0[i3] = chain(bArr4, concatenate[i3], (this.f921w - 1) - concatenate[i3], bArr3, adrs);
        }
        adrs2.setType(1);
        adrs2.setKeyPairAddress(adrs.getKeyPairAddress());
        return this.engine.T_l(bArr3, adrs2, Arrays.concatenate(r0));
    }
}