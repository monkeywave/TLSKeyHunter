package org.bouncycastle.pqc.crypto.falcon;

/* loaded from: classes2.dex */
class FalconSign {
    FPREngine fpr = new FPREngine();
    FalconFFT fft = new FalconFFT();
    FalconCommon common = new FalconCommon();

    private static int MKN(int i) {
        return 1 << i;
    }

    int do_sign_dyn(SamplerZ samplerZ, SamplerCtx samplerCtx, short[] sArr, int i, byte[] bArr, int i2, byte[] bArr2, int i3, byte[] bArr3, int i4, byte[] bArr4, int i5, short[] sArr2, int i6, int i7, FalconFPR[] falconFPRArr, int i8) {
        int MKN = MKN(i7);
        int i9 = i8 + MKN;
        int i10 = i9 + MKN;
        int i11 = i10 + MKN;
        smallints_to_fpr(falconFPRArr, i9, bArr, i2, i7);
        smallints_to_fpr(falconFPRArr, i8, bArr2, i3, i7);
        smallints_to_fpr(falconFPRArr, i11, bArr3, i4, i7);
        smallints_to_fpr(falconFPRArr, i10, bArr4, i5, i7);
        this.fft.FFT(falconFPRArr, i9, i7);
        this.fft.FFT(falconFPRArr, i8, i7);
        this.fft.FFT(falconFPRArr, i11, i7);
        this.fft.FFT(falconFPRArr, i10, i7);
        this.fft.poly_neg(falconFPRArr, i9, i7);
        this.fft.poly_neg(falconFPRArr, i11, i7);
        int i12 = i11 + MKN;
        int i13 = i12 + MKN;
        System.arraycopy(falconFPRArr, i9, falconFPRArr, i12, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr, i12, i7);
        System.arraycopy(falconFPRArr, i8, falconFPRArr, i13, MKN);
        this.fft.poly_muladj_fft(falconFPRArr, i13, falconFPRArr, i10, i7);
        this.fft.poly_mulselfadj_fft(falconFPRArr, i8, i7);
        this.fft.poly_add(falconFPRArr, i8, falconFPRArr, i12, i7);
        System.arraycopy(falconFPRArr, i9, falconFPRArr, i12, MKN);
        this.fft.poly_muladj_fft(falconFPRArr, i9, falconFPRArr, i11, i7);
        this.fft.poly_add(falconFPRArr, i9, falconFPRArr, i13, i7);
        this.fft.poly_mulselfadj_fft(falconFPRArr, i10, i7);
        System.arraycopy(falconFPRArr, i11, falconFPRArr, i13, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr, i13, i7);
        this.fft.poly_add(falconFPRArr, i10, falconFPRArr, i13, i7);
        int i14 = i13 + MKN;
        int i15 = 0;
        while (i15 < MKN) {
            falconFPRArr[i13 + i15] = this.fpr.fpr_of(sArr2[i6 + i15]);
            i15++;
            i14 = i14;
        }
        int i16 = i14;
        this.fft.FFT(falconFPRArr, i13, i7);
        FalconFPR falconFPR = this.fpr.fpr_inverse_of_q;
        System.arraycopy(falconFPRArr, i13, falconFPRArr, i16, MKN);
        this.fft.poly_mul_fft(falconFPRArr, i16, falconFPRArr, i12, i7);
        this.fft.poly_mulconst(falconFPRArr, i16, this.fpr.fpr_neg(falconFPR), i7);
        this.fft.poly_mul_fft(falconFPRArr, i13, falconFPRArr, i11, i7);
        this.fft.poly_mulconst(falconFPRArr, i13, falconFPR, i7);
        int i17 = MKN * 2;
        System.arraycopy(falconFPRArr, i13, falconFPRArr, i11, i17);
        ffSampling_fft_dyntree(samplerZ, samplerCtx, falconFPRArr, i11, falconFPRArr, i12, falconFPRArr, i8, falconFPRArr, i9, falconFPRArr, i10, i7, i7, falconFPRArr, i13);
        System.arraycopy(falconFPRArr, i11, falconFPRArr, i12, i17);
        smallints_to_fpr(falconFPRArr, i9, bArr, i2, i7);
        smallints_to_fpr(falconFPRArr, i8, bArr2, i3, i7);
        smallints_to_fpr(falconFPRArr, i11, bArr3, i4, i7);
        smallints_to_fpr(falconFPRArr, i10, bArr4, i5, i7);
        this.fft.FFT(falconFPRArr, i9, i7);
        this.fft.FFT(falconFPRArr, i8, i7);
        this.fft.FFT(falconFPRArr, i11, i7);
        this.fft.FFT(falconFPRArr, i10, i7);
        this.fft.poly_neg(falconFPRArr, i9, i7);
        this.fft.poly_neg(falconFPRArr, i11, i7);
        int i18 = i16 + MKN;
        System.arraycopy(falconFPRArr, i12, falconFPRArr, i16, MKN);
        System.arraycopy(falconFPRArr, i13, falconFPRArr, i18, MKN);
        this.fft.poly_mul_fft(falconFPRArr, i16, falconFPRArr, i8, i7);
        this.fft.poly_mul_fft(falconFPRArr, i18, falconFPRArr, i10, i7);
        this.fft.poly_add(falconFPRArr, i16, falconFPRArr, i18, i7);
        System.arraycopy(falconFPRArr, i12, falconFPRArr, i18, MKN);
        this.fft.poly_mul_fft(falconFPRArr, i18, falconFPRArr, i9, i7);
        System.arraycopy(falconFPRArr, i16, falconFPRArr, i12, MKN);
        this.fft.poly_mul_fft(falconFPRArr, i13, falconFPRArr, i11, i7);
        this.fft.poly_add(falconFPRArr, i13, falconFPRArr, i18, i7);
        this.fft.iFFT(falconFPRArr, i12, i7);
        this.fft.iFFT(falconFPRArr, i13, i7);
        short[] sArr3 = new short[MKN];
        int i19 = 0;
        int i20 = 0;
        for (int i21 = 0; i21 < MKN; i21++) {
            int fpr_rint = (sArr2[i6 + i21] & 65535) - ((int) this.fpr.fpr_rint(falconFPRArr[i12 + i21]));
            i19 += fpr_rint * fpr_rint;
            i20 |= i19;
            sArr3[i21] = (short) fpr_rint;
        }
        int i22 = (-(i20 >>> 31)) | i19;
        short[] sArr4 = new short[MKN];
        for (int i23 = 0; i23 < MKN; i23++) {
            sArr4[i23] = (short) (-this.fpr.fpr_rint(falconFPRArr[i13 + i23]));
        }
        if (this.common.is_short_half(i22, sArr4, 0, i7) != 0) {
            System.arraycopy(sArr4, 0, sArr, i, MKN);
            return 1;
        }
        return 0;
    }

    int do_sign_tree(SamplerZ samplerZ, SamplerCtx samplerCtx, short[] sArr, int i, FalconFPR[] falconFPRArr, int i2, short[] sArr2, int i3, int i4, FalconFPR[] falconFPRArr2, int i5) {
        int MKN = MKN(i4);
        int i6 = i5 + MKN;
        int skoff_b00 = i2 + skoff_b00(i4);
        int skoff_b01 = i2 + skoff_b01(i4);
        int skoff_b10 = i2 + skoff_b10(i4);
        int skoff_b11 = i2 + skoff_b11(i4);
        int skoff_tree = i2 + skoff_tree(i4);
        for (int i7 = 0; i7 < MKN; i7++) {
            falconFPRArr2[i5 + i7] = this.fpr.fpr_of(sArr2[i3 + i7]);
        }
        this.fft.FFT(falconFPRArr2, i5, i4);
        FalconFPR falconFPR = this.fpr.fpr_inverse_of_q;
        System.arraycopy(falconFPRArr2, i5, falconFPRArr2, i6, MKN);
        this.fft.poly_mul_fft(falconFPRArr2, i6, falconFPRArr, skoff_b01, i4);
        this.fft.poly_mulconst(falconFPRArr2, i6, this.fpr.fpr_neg(falconFPR), i4);
        this.fft.poly_mul_fft(falconFPRArr2, i5, falconFPRArr, skoff_b11, i4);
        this.fft.poly_mulconst(falconFPRArr2, i5, falconFPR, i4);
        int i8 = i6 + MKN;
        int i9 = i8 + MKN;
        ffSampling_fft(samplerZ, samplerCtx, falconFPRArr2, i8, falconFPRArr2, i9, falconFPRArr, skoff_tree, falconFPRArr2, i5, falconFPRArr2, i6, i4, falconFPRArr2, i9 + MKN);
        System.arraycopy(falconFPRArr2, i8, falconFPRArr2, i5, MKN);
        System.arraycopy(falconFPRArr2, i9, falconFPRArr2, i6, MKN);
        this.fft.poly_mul_fft(falconFPRArr2, i8, falconFPRArr, skoff_b00, i4);
        this.fft.poly_mul_fft(falconFPRArr2, i9, falconFPRArr, skoff_b10, i4);
        this.fft.poly_add(falconFPRArr2, i8, falconFPRArr2, i9, i4);
        System.arraycopy(falconFPRArr2, i5, falconFPRArr2, i9, MKN);
        this.fft.poly_mul_fft(falconFPRArr2, i9, falconFPRArr, skoff_b01, i4);
        System.arraycopy(falconFPRArr2, i8, falconFPRArr2, i5, MKN);
        this.fft.poly_mul_fft(falconFPRArr2, i6, falconFPRArr, skoff_b11, i4);
        this.fft.poly_add(falconFPRArr2, i6, falconFPRArr2, i9, i4);
        this.fft.iFFT(falconFPRArr2, i5, i4);
        this.fft.iFFT(falconFPRArr2, i6, i4);
        short[] sArr3 = new short[MKN];
        int i10 = 0;
        int i11 = 0;
        for (int i12 = 0; i12 < MKN; i12++) {
            int fpr_rint = (sArr2[i3 + i12] & 65535) - ((int) this.fpr.fpr_rint(falconFPRArr2[i5 + i12]));
            i10 += fpr_rint * fpr_rint;
            i11 |= i10;
            sArr3[i12] = (short) fpr_rint;
        }
        int i13 = (-(i11 >>> 31)) | i10;
        short[] sArr4 = new short[MKN];
        for (int i14 = 0; i14 < MKN; i14++) {
            sArr4[i14] = (short) (-this.fpr.fpr_rint(falconFPRArr2[i6 + i14]));
        }
        if (this.common.is_short_half(i13, sArr4, 0, i4) != 0) {
            System.arraycopy(sArr4, 0, sArr, i, MKN);
            System.arraycopy(sArr3, 0, falconFPRArr2, i5, MKN);
            return 1;
        }
        return 0;
    }

    void expand_privkey(FalconFPR[] falconFPRArr, int i, byte[] bArr, int i2, byte[] bArr2, int i3, byte[] bArr3, int i4, byte[] bArr4, int i5, int i6, FalconFPR[] falconFPRArr2, int i7) {
        int MKN = MKN(i6);
        int skoff_b00 = i + skoff_b00(i6);
        int skoff_b01 = i + skoff_b01(i6);
        int skoff_b10 = i + skoff_b10(i6);
        int skoff_b11 = i + skoff_b11(i6);
        int skoff_tree = i + skoff_tree(i6);
        smallints_to_fpr(falconFPRArr, skoff_b01, bArr, i2, i6);
        smallints_to_fpr(falconFPRArr, skoff_b00, bArr2, i3, i6);
        smallints_to_fpr(falconFPRArr, skoff_b11, bArr3, i4, i6);
        smallints_to_fpr(falconFPRArr, skoff_b10, bArr4, i5, i6);
        this.fft.FFT(falconFPRArr, skoff_b01, i6);
        this.fft.FFT(falconFPRArr, skoff_b00, i6);
        this.fft.FFT(falconFPRArr, skoff_b11, i6);
        this.fft.FFT(falconFPRArr, skoff_b10, i6);
        this.fft.poly_neg(falconFPRArr, skoff_b01, i6);
        this.fft.poly_neg(falconFPRArr, skoff_b11, i6);
        int i8 = i7 + MKN;
        int i9 = i8 + MKN;
        int i10 = i9 + MKN;
        System.arraycopy(falconFPRArr, skoff_b00, falconFPRArr2, i7, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr2, i7, i6);
        System.arraycopy(falconFPRArr, skoff_b01, falconFPRArr2, i10, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr2, i10, i6);
        this.fft.poly_add(falconFPRArr2, i7, falconFPRArr2, i10, i6);
        System.arraycopy(falconFPRArr, skoff_b00, falconFPRArr2, i8, MKN);
        this.fft.poly_muladj_fft(falconFPRArr2, i8, falconFPRArr, skoff_b10, i6);
        System.arraycopy(falconFPRArr, skoff_b01, falconFPRArr2, i10, MKN);
        this.fft.poly_muladj_fft(falconFPRArr2, i10, falconFPRArr, skoff_b11, i6);
        this.fft.poly_add(falconFPRArr2, i8, falconFPRArr2, i10, i6);
        System.arraycopy(falconFPRArr, skoff_b10, falconFPRArr2, i9, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr2, i9, i6);
        System.arraycopy(falconFPRArr, skoff_b11, falconFPRArr2, i10, MKN);
        this.fft.poly_mulselfadj_fft(falconFPRArr2, i10, i6);
        this.fft.poly_add(falconFPRArr2, i9, falconFPRArr2, i10, i6);
        ffLDL_fft(falconFPRArr, skoff_tree, falconFPRArr2, i7, falconFPRArr2, i8, falconFPRArr2, i9, i6, falconFPRArr2, i10);
        ffLDL_binary_normalize(falconFPRArr, skoff_tree, i6, i6);
    }

    void ffLDL_binary_normalize(FalconFPR[] falconFPRArr, int i, int i2, int i3) {
        int MKN = MKN(i3);
        if (MKN == 1) {
            FPREngine fPREngine = this.fpr;
            falconFPRArr[i] = fPREngine.fpr_mul(fPREngine.fpr_sqrt(falconFPRArr[i]), this.fpr.fpr_inv_sigma[i2]);
            return;
        }
        int i4 = i + MKN;
        int i5 = i3 - 1;
        ffLDL_binary_normalize(falconFPRArr, i4, i2, i5);
        ffLDL_binary_normalize(falconFPRArr, i4 + ffLDL_treesize(i5), i2, i5);
    }

    void ffLDL_fft(FalconFPR[] falconFPRArr, int i, FalconFPR[] falconFPRArr2, int i2, FalconFPR[] falconFPRArr3, int i3, FalconFPR[] falconFPRArr4, int i4, int i5, FalconFPR[] falconFPRArr5, int i6) {
        int MKN = MKN(i5);
        if (MKN == 1) {
            falconFPRArr[i] = falconFPRArr2[i2];
            return;
        }
        int i7 = MKN >> 1;
        int i8 = i6 + MKN;
        int i9 = i6 + (MKN << 1);
        System.arraycopy(falconFPRArr2, i2, falconFPRArr5, i6, MKN);
        this.fft.poly_LDLmv_fft(falconFPRArr5, i8, falconFPRArr, i, falconFPRArr2, i2, falconFPRArr3, i3, falconFPRArr4, i4, i5);
        this.fft.poly_split_fft(falconFPRArr5, i9, falconFPRArr5, i9 + i7, falconFPRArr5, i6, i5);
        int i10 = i6 + i7;
        this.fft.poly_split_fft(falconFPRArr5, i6, falconFPRArr5, i10, falconFPRArr5, i8, i5);
        System.arraycopy(falconFPRArr5, i9, falconFPRArr5, i8, MKN);
        int i11 = i + MKN;
        int i12 = i5 - 1;
        ffLDL_fft_inner(falconFPRArr, i11, falconFPRArr5, i8, falconFPRArr5, i8 + i7, i12, falconFPRArr5, i9);
        ffLDL_fft_inner(falconFPRArr, i11 + ffLDL_treesize(i12), falconFPRArr5, i6, falconFPRArr5, i10, i12, falconFPRArr5, i9);
    }

    void ffLDL_fft_inner(FalconFPR[] falconFPRArr, int i, FalconFPR[] falconFPRArr2, int i2, FalconFPR[] falconFPRArr3, int i3, int i4, FalconFPR[] falconFPRArr4, int i5) {
        int MKN = MKN(i4);
        if (MKN == 1) {
            falconFPRArr[i] = falconFPRArr2[i2];
            return;
        }
        int i6 = MKN >> 1;
        this.fft.poly_LDLmv_fft(falconFPRArr4, i5, falconFPRArr, i, falconFPRArr2, i2, falconFPRArr3, i3, falconFPRArr2, i2, i4);
        int i7 = i3 + i6;
        this.fft.poly_split_fft(falconFPRArr3, i3, falconFPRArr3, i7, falconFPRArr2, i2, i4);
        int i8 = i2 + i6;
        this.fft.poly_split_fft(falconFPRArr2, i2, falconFPRArr2, i8, falconFPRArr4, i5, i4);
        int i9 = i + MKN;
        int i10 = i4 - 1;
        ffLDL_fft_inner(falconFPRArr, i9, falconFPRArr3, i3, falconFPRArr3, i7, i10, falconFPRArr4, i5);
        ffLDL_fft_inner(falconFPRArr, i9 + ffLDL_treesize(i10), falconFPRArr2, i2, falconFPRArr2, i8, i10, falconFPRArr4, i5);
    }

    int ffLDL_treesize(int i) {
        return (i + 1) << i;
    }

    void ffSampling_fft(SamplerZ samplerZ, SamplerCtx samplerCtx, FalconFPR[] falconFPRArr, int i, FalconFPR[] falconFPRArr2, int i2, FalconFPR[] falconFPRArr3, int i3, FalconFPR[] falconFPRArr4, int i4, FalconFPR[] falconFPRArr5, int i5, int i6, FalconFPR[] falconFPRArr6, int i7) {
        if (i6 != 2) {
            if (i6 != 1) {
                int i8 = 1 << i6;
                int i9 = i8 >> 1;
                int i10 = i3 + i8;
                int i11 = i6 - 1;
                int ffLDL_treesize = i10 + ffLDL_treesize(i11);
                int i12 = i2 + i9;
                this.fft.poly_split_fft(falconFPRArr2, i2, falconFPRArr2, i12, falconFPRArr5, i5, i6);
                int i13 = i7 + i9;
                int i14 = i7 + i8;
                ffSampling_fft(samplerZ, samplerCtx, falconFPRArr6, i7, falconFPRArr6, i13, falconFPRArr3, ffLDL_treesize, falconFPRArr2, i2, falconFPRArr2, i12, i11, falconFPRArr6, i14);
                this.fft.poly_merge_fft(falconFPRArr2, i2, falconFPRArr6, i7, falconFPRArr6, i13, i6);
                System.arraycopy(falconFPRArr5, i5, falconFPRArr6, i7, i8);
                this.fft.poly_sub(falconFPRArr6, i7, falconFPRArr2, i2, i6);
                this.fft.poly_mul_fft(falconFPRArr6, i7, falconFPRArr3, i3, i6);
                this.fft.poly_add(falconFPRArr6, i7, falconFPRArr4, i4, i6);
                int i15 = i + i9;
                this.fft.poly_split_fft(falconFPRArr, i, falconFPRArr, i15, falconFPRArr6, i7, i6);
                ffSampling_fft(samplerZ, samplerCtx, falconFPRArr6, i7, falconFPRArr6, i13, falconFPRArr3, i10, falconFPRArr, i, falconFPRArr, i15, i11, falconFPRArr6, i14);
                this.fft.poly_merge_fft(falconFPRArr, i, falconFPRArr6, i7, falconFPRArr6, i13, i6);
                return;
            }
            FalconFPR falconFPR = falconFPRArr5[i5];
            FalconFPR falconFPR2 = falconFPRArr5[i5 + 1];
            FalconFPR falconFPR3 = falconFPRArr3[i3 + 3];
            FalconFPR fpr_of = this.fpr.fpr_of(samplerZ.sample(samplerCtx, falconFPR, falconFPR3));
            falconFPRArr2[i2] = fpr_of;
            FalconFPR fpr_of2 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, falconFPR2, falconFPR3));
            falconFPRArr2[i2 + 1] = fpr_of2;
            FalconFPR fpr_sub = this.fpr.fpr_sub(falconFPR, fpr_of);
            FalconFPR fpr_sub2 = this.fpr.fpr_sub(falconFPR2, fpr_of2);
            FalconFPR falconFPR4 = falconFPRArr3[i3];
            FalconFPR falconFPR5 = falconFPRArr3[i3 + 1];
            FPREngine fPREngine = this.fpr;
            FalconFPR fpr_sub3 = fPREngine.fpr_sub(fPREngine.fpr_mul(fpr_sub, falconFPR4), this.fpr.fpr_mul(fpr_sub2, falconFPR5));
            FPREngine fPREngine2 = this.fpr;
            FalconFPR fpr_add = fPREngine2.fpr_add(fPREngine2.fpr_mul(fpr_sub, falconFPR5), this.fpr.fpr_mul(fpr_sub2, falconFPR4));
            FalconFPR fpr_add2 = this.fpr.fpr_add(fpr_sub3, falconFPRArr4[i4]);
            FalconFPR fpr_add3 = this.fpr.fpr_add(fpr_add, falconFPRArr4[i4 + 1]);
            FalconFPR falconFPR6 = falconFPRArr3[i3 + 2];
            falconFPRArr[i] = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add2, falconFPR6));
            falconFPRArr[i + 1] = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add3, falconFPR6));
            return;
        }
        FalconFPR falconFPR7 = falconFPRArr5[i5];
        int i16 = i5 + 2;
        FalconFPR falconFPR8 = falconFPRArr5[i16];
        int i17 = i5 + 1;
        FalconFPR falconFPR9 = falconFPRArr5[i17];
        int i18 = i5 + 3;
        FalconFPR falconFPR10 = falconFPRArr5[i18];
        FalconFPR fpr_add4 = this.fpr.fpr_add(falconFPR7, falconFPR9);
        FalconFPR fpr_add5 = this.fpr.fpr_add(falconFPR8, falconFPR10);
        FalconFPR fpr_half = this.fpr.fpr_half(fpr_add4);
        FalconFPR fpr_half2 = this.fpr.fpr_half(fpr_add5);
        FalconFPR fpr_sub4 = this.fpr.fpr_sub(falconFPR7, falconFPR9);
        FalconFPR fpr_sub5 = this.fpr.fpr_sub(falconFPR8, falconFPR10);
        FPREngine fPREngine3 = this.fpr;
        FalconFPR fpr_mul = fPREngine3.fpr_mul(fPREngine3.fpr_add(fpr_sub4, fpr_sub5), this.fpr.fpr_invsqrt8);
        FPREngine fPREngine4 = this.fpr;
        FalconFPR fpr_mul2 = fPREngine4.fpr_mul(fPREngine4.fpr_sub(fpr_sub5, fpr_sub4), this.fpr.fpr_invsqrt8);
        FalconFPR falconFPR11 = falconFPRArr3[i3 + 11];
        FalconFPR fpr_of3 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_mul, falconFPR11));
        FalconFPR fpr_of4 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_mul2, falconFPR11));
        FalconFPR fpr_sub6 = this.fpr.fpr_sub(fpr_mul, fpr_of3);
        FalconFPR fpr_sub7 = this.fpr.fpr_sub(fpr_mul2, fpr_of4);
        FalconFPR falconFPR12 = falconFPRArr3[i3 + 8];
        FalconFPR falconFPR13 = falconFPRArr3[i3 + 9];
        FPREngine fPREngine5 = this.fpr;
        FalconFPR fpr_sub8 = fPREngine5.fpr_sub(fPREngine5.fpr_mul(fpr_sub6, falconFPR12), this.fpr.fpr_mul(fpr_sub7, falconFPR13));
        FPREngine fPREngine6 = this.fpr;
        FalconFPR fpr_add6 = fPREngine6.fpr_add(fPREngine6.fpr_mul(fpr_sub6, falconFPR13), this.fpr.fpr_mul(fpr_sub7, falconFPR12));
        FalconFPR fpr_add7 = this.fpr.fpr_add(fpr_sub8, fpr_half);
        FalconFPR fpr_add8 = this.fpr.fpr_add(fpr_add6, fpr_half2);
        FalconFPR falconFPR14 = falconFPRArr3[i3 + 10];
        FalconFPR fpr_of5 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add7, falconFPR14));
        FalconFPR fpr_of6 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add8, falconFPR14));
        FPREngine fPREngine7 = this.fpr;
        FalconFPR fpr_mul3 = fPREngine7.fpr_mul(fPREngine7.fpr_sub(fpr_of3, fpr_of4), this.fpr.fpr_invsqrt2);
        FPREngine fPREngine8 = this.fpr;
        FalconFPR fpr_mul4 = fPREngine8.fpr_mul(fPREngine8.fpr_add(fpr_of3, fpr_of4), this.fpr.fpr_invsqrt2);
        FalconFPR fpr_add9 = this.fpr.fpr_add(fpr_of5, fpr_mul3);
        falconFPRArr2[i2] = fpr_add9;
        FalconFPR fpr_add10 = this.fpr.fpr_add(fpr_of6, fpr_mul4);
        falconFPRArr2[i2 + 2] = fpr_add10;
        FalconFPR fpr_sub9 = this.fpr.fpr_sub(fpr_of5, fpr_mul3);
        falconFPRArr2[i2 + 1] = fpr_sub9;
        FalconFPR fpr_sub10 = this.fpr.fpr_sub(fpr_of6, fpr_mul4);
        falconFPRArr2[i2 + 3] = fpr_sub10;
        FalconFPR fpr_sub11 = this.fpr.fpr_sub(falconFPRArr5[i5], fpr_add9);
        FalconFPR fpr_sub12 = this.fpr.fpr_sub(falconFPRArr5[i17], fpr_sub9);
        FalconFPR fpr_sub13 = this.fpr.fpr_sub(falconFPRArr5[i16], fpr_add10);
        FalconFPR fpr_sub14 = this.fpr.fpr_sub(falconFPRArr5[i18], fpr_sub10);
        FalconFPR falconFPR15 = falconFPRArr3[i3];
        FalconFPR falconFPR16 = falconFPRArr3[i3 + 2];
        FPREngine fPREngine9 = this.fpr;
        FalconFPR fpr_sub15 = fPREngine9.fpr_sub(fPREngine9.fpr_mul(fpr_sub11, falconFPR15), this.fpr.fpr_mul(fpr_sub13, falconFPR16));
        FPREngine fPREngine10 = this.fpr;
        FalconFPR fpr_add11 = fPREngine10.fpr_add(fPREngine10.fpr_mul(fpr_sub11, falconFPR16), this.fpr.fpr_mul(fpr_sub13, falconFPR15));
        FalconFPR falconFPR17 = falconFPRArr3[i3 + 1];
        FalconFPR falconFPR18 = falconFPRArr3[i3 + 3];
        FPREngine fPREngine11 = this.fpr;
        FalconFPR fpr_sub16 = fPREngine11.fpr_sub(fPREngine11.fpr_mul(fpr_sub12, falconFPR17), this.fpr.fpr_mul(fpr_sub14, falconFPR18));
        FPREngine fPREngine12 = this.fpr;
        FalconFPR fpr_add12 = fPREngine12.fpr_add(fPREngine12.fpr_mul(fpr_sub12, falconFPR18), this.fpr.fpr_mul(fpr_sub14, falconFPR17));
        FalconFPR fpr_add13 = this.fpr.fpr_add(fpr_sub15, falconFPRArr4[i4]);
        FalconFPR fpr_add14 = this.fpr.fpr_add(fpr_sub16, falconFPRArr4[i4 + 1]);
        FalconFPR fpr_add15 = this.fpr.fpr_add(fpr_add11, falconFPRArr4[i4 + 2]);
        FalconFPR fpr_add16 = this.fpr.fpr_add(fpr_add12, falconFPRArr4[i4 + 3]);
        FalconFPR fpr_add17 = this.fpr.fpr_add(fpr_add13, fpr_add14);
        FalconFPR fpr_add18 = this.fpr.fpr_add(fpr_add15, fpr_add16);
        FalconFPR fpr_half3 = this.fpr.fpr_half(fpr_add17);
        FalconFPR fpr_half4 = this.fpr.fpr_half(fpr_add18);
        FalconFPR fpr_sub17 = this.fpr.fpr_sub(fpr_add13, fpr_add14);
        FalconFPR fpr_sub18 = this.fpr.fpr_sub(fpr_add15, fpr_add16);
        FPREngine fPREngine13 = this.fpr;
        FalconFPR fpr_mul5 = fPREngine13.fpr_mul(fPREngine13.fpr_add(fpr_sub17, fpr_sub18), this.fpr.fpr_invsqrt8);
        FPREngine fPREngine14 = this.fpr;
        FalconFPR fpr_mul6 = fPREngine14.fpr_mul(fPREngine14.fpr_sub(fpr_sub18, fpr_sub17), this.fpr.fpr_invsqrt8);
        FalconFPR falconFPR19 = falconFPRArr3[i3 + 7];
        FalconFPR fpr_of7 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_mul5, falconFPR19));
        FalconFPR fpr_of8 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_mul6, falconFPR19));
        FalconFPR fpr_sub19 = this.fpr.fpr_sub(fpr_mul5, fpr_of7);
        FalconFPR fpr_sub20 = this.fpr.fpr_sub(fpr_mul6, fpr_of8);
        FalconFPR falconFPR20 = falconFPRArr3[i3 + 4];
        FalconFPR falconFPR21 = falconFPRArr3[i3 + 5];
        FPREngine fPREngine15 = this.fpr;
        FalconFPR fpr_sub21 = fPREngine15.fpr_sub(fPREngine15.fpr_mul(fpr_sub19, falconFPR20), this.fpr.fpr_mul(fpr_sub20, falconFPR21));
        FPREngine fPREngine16 = this.fpr;
        FalconFPR fpr_add19 = fPREngine16.fpr_add(fPREngine16.fpr_mul(fpr_sub19, falconFPR21), this.fpr.fpr_mul(fpr_sub20, falconFPR20));
        FalconFPR fpr_add20 = this.fpr.fpr_add(fpr_sub21, fpr_half3);
        FalconFPR fpr_add21 = this.fpr.fpr_add(fpr_add19, fpr_half4);
        FalconFPR falconFPR22 = falconFPRArr3[i3 + 6];
        FalconFPR fpr_of9 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add20, falconFPR22));
        FalconFPR fpr_of10 = this.fpr.fpr_of(samplerZ.sample(samplerCtx, fpr_add21, falconFPR22));
        FPREngine fPREngine17 = this.fpr;
        FalconFPR fpr_mul7 = fPREngine17.fpr_mul(fPREngine17.fpr_sub(fpr_of7, fpr_of8), this.fpr.fpr_invsqrt2);
        FPREngine fPREngine18 = this.fpr;
        FalconFPR fpr_mul8 = fPREngine18.fpr_mul(fPREngine18.fpr_add(fpr_of7, fpr_of8), this.fpr.fpr_invsqrt2);
        falconFPRArr[i] = this.fpr.fpr_add(fpr_of9, fpr_mul7);
        falconFPRArr[i + 2] = this.fpr.fpr_add(fpr_of10, fpr_mul8);
        falconFPRArr[i + 1] = this.fpr.fpr_sub(fpr_of9, fpr_mul7);
        falconFPRArr[i + 3] = this.fpr.fpr_sub(fpr_of10, fpr_mul8);
    }

    void ffSampling_fft_dyntree(SamplerZ samplerZ, SamplerCtx samplerCtx, FalconFPR[] falconFPRArr, int i, FalconFPR[] falconFPRArr2, int i2, FalconFPR[] falconFPRArr3, int i3, FalconFPR[] falconFPRArr4, int i4, FalconFPR[] falconFPRArr5, int i5, int i6, int i7, FalconFPR[] falconFPRArr6, int i8) {
        if (i7 == 0) {
            FalconFPR falconFPR = falconFPRArr3[i3];
            FPREngine fPREngine = this.fpr;
            FalconFPR fpr_mul = fPREngine.fpr_mul(fPREngine.fpr_sqrt(falconFPR), this.fpr.fpr_inv_sigma[i6]);
            falconFPRArr[i] = this.fpr.fpr_of(samplerZ.sample(samplerCtx, falconFPRArr[i], fpr_mul));
            falconFPRArr2[i2] = this.fpr.fpr_of(samplerZ.sample(samplerCtx, falconFPRArr2[i2], fpr_mul));
            return;
        }
        int i9 = 1 << i7;
        int i10 = i9 >> 1;
        this.fft.poly_LDL_fft(falconFPRArr3, i3, falconFPRArr4, i4, falconFPRArr5, i5, i7);
        int i11 = i8 + i10;
        this.fft.poly_split_fft(falconFPRArr6, i8, falconFPRArr6, i11, falconFPRArr3, i3, i7);
        System.arraycopy(falconFPRArr6, i8, falconFPRArr3, i3, i9);
        this.fft.poly_split_fft(falconFPRArr6, i8, falconFPRArr6, i11, falconFPRArr5, i5, i7);
        System.arraycopy(falconFPRArr6, i8, falconFPRArr5, i5, i9);
        System.arraycopy(falconFPRArr4, i4, falconFPRArr6, i8, i9);
        System.arraycopy(falconFPRArr3, i3, falconFPRArr4, i4, i10);
        int i12 = i4 + i10;
        System.arraycopy(falconFPRArr5, i5, falconFPRArr4, i12, i10);
        int i13 = i8 + i9;
        int i14 = i13 + i10;
        this.fft.poly_split_fft(falconFPRArr6, i13, falconFPRArr6, i14, falconFPRArr2, i2, i7);
        int i15 = i7 - 1;
        ffSampling_fft_dyntree(samplerZ, samplerCtx, falconFPRArr6, i13, falconFPRArr6, i14, falconFPRArr5, i5, falconFPRArr5, i5 + i10, falconFPRArr4, i12, i6, i15, falconFPRArr6, i13 + i9);
        int i16 = i8 + (i9 << 1);
        this.fft.poly_merge_fft(falconFPRArr6, i16, falconFPRArr6, i13, falconFPRArr6, i14, i7);
        System.arraycopy(falconFPRArr2, i2, falconFPRArr6, i13, i9);
        this.fft.poly_sub(falconFPRArr6, i13, falconFPRArr6, i16, i7);
        System.arraycopy(falconFPRArr6, i16, falconFPRArr2, i2, i9);
        this.fft.poly_mul_fft(falconFPRArr6, i8, falconFPRArr6, i13, i7);
        this.fft.poly_add(falconFPRArr, i, falconFPRArr6, i8, i7);
        this.fft.poly_split_fft(falconFPRArr6, i8, falconFPRArr6, i11, falconFPRArr, i, i7);
        ffSampling_fft_dyntree(samplerZ, samplerCtx, falconFPRArr6, i8, falconFPRArr6, i11, falconFPRArr3, i3, falconFPRArr3, i3 + i10, falconFPRArr4, i4, i6, i15, falconFPRArr6, i13);
        this.fft.poly_merge_fft(falconFPRArr, i, falconFPRArr6, i8, falconFPRArr6, i11, i7);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void sign_dyn(short[] sArr, int i, SHAKE256 shake256, byte[] bArr, int i2, byte[] bArr2, int i3, byte[] bArr3, int i4, byte[] bArr4, int i5, short[] sArr2, int i6, int i7, FalconFPR[] falconFPRArr, int i8) {
        SamplerCtx samplerCtx;
        SamplerZ samplerZ;
        do {
            samplerCtx = new SamplerCtx();
            samplerZ = new SamplerZ();
            samplerCtx.sigma_min = this.fpr.fpr_sigma_min[i7];
            samplerCtx.f1249p.prng_init(shake256);
        } while (do_sign_dyn(samplerZ, samplerCtx, sArr, i, bArr, i2, bArr2, i3, bArr3, i4, bArr4, i5, sArr2, i6, i7, falconFPRArr, i8) == 0);
    }

    void sign_tree(short[] sArr, int i, SHAKE256 shake256, FalconFPR[] falconFPRArr, int i2, short[] sArr2, int i3, int i4, FalconFPR[] falconFPRArr2, int i5) {
        SamplerCtx samplerCtx;
        SamplerZ samplerZ;
        do {
            samplerCtx = new SamplerCtx();
            samplerZ = new SamplerZ();
            samplerCtx.sigma_min = this.fpr.fpr_sigma_min[i4];
            samplerCtx.f1249p.prng_init(shake256);
        } while (do_sign_tree(samplerZ, samplerCtx, sArr, i, falconFPRArr, i2, sArr2, i3, i4, falconFPRArr2, i5) == 0);
    }

    int skoff_b00(int i) {
        return 0;
    }

    int skoff_b01(int i) {
        return MKN(i);
    }

    int skoff_b10(int i) {
        return MKN(i) * 2;
    }

    int skoff_b11(int i) {
        return MKN(i) * 3;
    }

    int skoff_tree(int i) {
        return MKN(i) * 4;
    }

    void smallints_to_fpr(FalconFPR[] falconFPRArr, int i, byte[] bArr, int i2, int i3) {
        int MKN = MKN(i3);
        for (int i4 = 0; i4 < MKN; i4++) {
            falconFPRArr[i + i4] = this.fpr.fpr_of(bArr[i2 + i4]);
        }
    }
}