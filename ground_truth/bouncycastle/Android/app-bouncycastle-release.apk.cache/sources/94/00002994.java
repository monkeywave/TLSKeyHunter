package org.bouncycastle.pqc.crypto.falcon;

import androidx.core.view.ViewCompat;
import kotlin.UByte;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.NamedGroup;

/* loaded from: classes2.dex */
class SamplerZ {
    FPREngine fpr = new FPREngine();

    int BerExp(FalconRNG falconRNG, FalconFPR falconFPR, FalconFPR falconFPR2) {
        int prng_get_u8;
        FPREngine fPREngine = this.fpr;
        int fpr_trunc = (int) fPREngine.fpr_trunc(fPREngine.fpr_mul(falconFPR, fPREngine.fpr_inv_log2));
        FPREngine fPREngine2 = this.fpr;
        long fpr_expm_p63 = ((this.fpr.fpr_expm_p63(fPREngine2.fpr_sub(falconFPR, fPREngine2.fpr_mul(fPREngine2.fpr_of(fpr_trunc), this.fpr.fpr_log2)), falconFPR2) << 1) - 1) >>> (fpr_trunc ^ ((fpr_trunc ^ 63) & (-((63 - fpr_trunc) >>> 31))));
        int i = 64;
        do {
            i -= 8;
            prng_get_u8 = (falconRNG.prng_get_u8() & UByte.MAX_VALUE) - (((int) (fpr_expm_p63 >>> i)) & 255);
            if (prng_get_u8 != 0) {
                break;
            }
        } while (i > 0);
        return prng_get_u8 >>> 31;
    }

    int gaussian0_sampler(FalconRNG falconRNG) {
        int[] iArr = {10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639, 708981, 4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655, NamedGroup.DRAFT_mlkem1024, 14505003, 7826148, 417, 16768101, 11363290, 31, 8444042, 8086568, 1, 12844466, 265321, 0, 1232676, 13644283, 0, 38047, 9111839, 0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126, 0, 0, 28824, 0, 0, CipherSuite.TLS_SM4_GCM_SM3, 0, 0, 1};
        long prng_get_u64 = falconRNG.prng_get_u64();
        int prng_get_u8 = falconRNG.prng_get_u8() & UByte.MAX_VALUE;
        int i = ((int) prng_get_u64) & ViewCompat.MEASURED_SIZE_MASK;
        int i2 = 16777215 & ((int) (prng_get_u64 >>> 24));
        int i3 = (prng_get_u8 << 16) | ((int) (prng_get_u64 >>> 48));
        int i4 = 0;
        for (int i5 = 0; i5 < 54; i5 += 3) {
            i4 += ((i3 - iArr[i5]) - (((i2 - iArr[i5 + 1]) - ((i - iArr[i5 + 2]) >>> 31)) >>> 31)) >>> 31;
        }
        return i4;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int sample(SamplerCtx samplerCtx, FalconFPR falconFPR, FalconFPR falconFPR2) {
        return sampler(samplerCtx, falconFPR, falconFPR2);
    }

    int sampler(SamplerCtx samplerCtx, FalconFPR falconFPR, FalconFPR falconFPR2) {
        int gaussian0_sampler;
        int i;
        FalconFPR fpr_mul;
        FPREngine fPREngine;
        int fpr_floor = (int) this.fpr.fpr_floor(falconFPR);
        FPREngine fPREngine2 = this.fpr;
        FalconFPR fpr_sub = fPREngine2.fpr_sub(falconFPR, fPREngine2.fpr_of(fpr_floor));
        FPREngine fPREngine3 = this.fpr;
        FalconFPR fpr_half = fPREngine3.fpr_half(fPREngine3.fpr_sqr(falconFPR2));
        FalconFPR fpr_mul2 = this.fpr.fpr_mul(falconFPR2, samplerCtx.sigma_min);
        do {
            gaussian0_sampler = gaussian0_sampler(samplerCtx.f1249p);
            int prng_get_u8 = samplerCtx.f1249p.prng_get_u8() & 1;
            i = prng_get_u8 + (((prng_get_u8 << 1) - 1) * gaussian0_sampler);
            FPREngine fPREngine4 = this.fpr;
            fpr_mul = fPREngine4.fpr_mul(fPREngine4.fpr_sqr(fPREngine4.fpr_sub(fPREngine4.fpr_of(i), fpr_sub)), fpr_half);
            fPREngine = this.fpr;
        } while (BerExp(samplerCtx.f1249p, fPREngine.fpr_sub(fpr_mul, fPREngine.fpr_mul(fPREngine.fpr_of(gaussian0_sampler * gaussian0_sampler), this.fpr.fpr_inv_2sqrsigma0)), fpr_mul2) == 0);
        return fpr_floor + i;
    }
}