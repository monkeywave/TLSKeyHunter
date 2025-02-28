package org.bouncycastle.pqc.crypto.gemss;

import java.math.BigInteger;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.gemss.SecretKeyHFE;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class GeMSSEngine {
    final int ACCESS_last_equations8;
    Pointer Buffer_NB_WORD_GFqn;
    Pointer Buffer_NB_WORD_MUL;
    final boolean ENABLED_REMOVE_ODD_DEGREE;
    final int HFEDELTA;
    final int HFEDeg;
    final int HFEDegI;
    final int HFEDegJ;
    final int HFENr8;
    final int HFENr8c;
    int HFE_odd_degree;
    final int HFEm;
    final int HFEmq;
    final int HFEmq8;
    final int HFEmr;
    final int HFEmr8;
    final int HFEn;
    int HFEn1h_rightmost;
    int HFEn_1rightmost;
    final int HFEnq;
    final int HFEnr;
    final int HFEnv;
    final int HFEnvq;
    final int HFEnvr;
    final int HFEnvr8;
    final int HFEv;
    final int HFEvq;
    final int HFEvr;

    /* renamed from: II */
    int f1263II;

    /* renamed from: KP */
    int f1264KP;

    /* renamed from: KX */
    int f1265KX;
    final int LOST_BITS;
    int LTRIANGULAR_NV_SIZE;
    final int LTRIANGULAR_N_SIZE;
    final long MASK_GF2m;
    final long MASK_GF2n;
    final int MATRIXn_SIZE;
    final int MATRIXnv_SIZE;
    final int MLv_GFqn_SIZE;
    int MQv_GFqn_SIZE;
    final int NB_BYTES_EQUATION;
    final int NB_BYTES_GFqm;
    final int NB_BYTES_GFqn;
    final int NB_BYTES_GFqnv;
    int NB_COEFS_HFEPOLY;
    final int NB_ITE;
    int NB_MONOMIAL_PK;
    int NB_MONOMIAL_VINEGAR;
    int NB_UINT_HFEVPOLY;
    int NB_WORD_GF2m;
    int NB_WORD_GF2nv;
    final int NB_WORD_GF2nvm;
    int NB_WORD_GFqn;
    final int NB_WORD_GFqv;
    int NB_WORD_MMUL;
    final int NB_WORD_MUL;
    final int NB_WORD_UNCOMP_EQ;
    int POW_II;
    final int SIZE_DIGEST;
    final int SIZE_DIGEST_UINT;
    final int SIZE_ROW;
    final int SIZE_SEED_SK;
    final int SIZE_SIGN_UNCOMPRESSED;
    final int Sha3BitStrength;
    final int ShakeBitStrength;
    final int VAL_BITS_M;
    private int buffer;
    Mul_GF2x mul;
    private SecureRandom random;
    Rem_GF2n rem;
    SHA3Digest sha3Digest;
    final int NB_BITS_UINT = 64;
    final int LEN_UNROLLED_64 = 4;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: org.bouncycastle.pqc.crypto.gemss.GeMSSEngine$1 */
    /* loaded from: classes2.dex */
    public static /* synthetic */ class C13931 {

        /* renamed from: $SwitchMap$org$bouncycastle$pqc$crypto$gemss$GeMSSEngine$FunctionParams */
        static final /* synthetic */ int[] f1266xb3d0f197;

        static {
            int[] iArr = new int[FunctionParams.values().length];
            f1266xb3d0f197 = iArr;
            try {
                iArr[FunctionParams.N.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f1266xb3d0f197[FunctionParams.NV.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f1266xb3d0f197[FunctionParams.V.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f1266xb3d0f197[FunctionParams.M.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public enum FunctionParams {
        NV,
        V,
        N,
        M
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x0253  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0255  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0260  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0275  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x027f  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x02be  */
    /* JADX WARN: Removed duplicated region for block: B:128:0x02c8  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x02ca  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x02da  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x02dd  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x02e9  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0322  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x03e1 A[LOOP:0: B:170:0x03db->B:172:0x03e1, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:176:0x03f1 A[LOOP:1: B:174:0x03e9->B:176:0x03f1, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:179:0x03e6 A[EDGE_INSN: B:179:0x03e6->B:173:0x03e6 ?: BREAK  , SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:180:0x03f4 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00e1  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x01f6  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01fb  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x020b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public GeMSSEngine(int r35, int r36, int r37, int r38, int r39, int r40, int r41, int r42) {
        /*
            Method dump skipped, instructions count: 1016
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.gemss.GeMSSEngine.<init>(int, int, int, int, int, int, int, int):void");
    }

    private void CMP_AND_SWAP_CST_TIME(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        long j = 0;
        long j2 = 0;
        long j3 = 0;
        for (int i = this.NB_WORD_GFqn - 1; i > 0; i--) {
            j2 |= GeMSSUtils.ORBITS_UINT(pointer2.get(i) ^ pointer.get(i));
            j3 += j2;
        }
        int i2 = 0;
        while (true) {
            int i3 = this.NB_WORD_GFqn;
            if (i2 >= i3) {
                pointer3.setRangeFromXorAndMask_xor(pointer, pointer2, -j, i3);
                return;
            } else {
                j |= (-GeMSSUtils.NORBITS_UINT(i2 ^ j3)) & GeMSSUtils.CMP_LT_UINT(pointer2.get(i2), pointer.get(i2));
                i2++;
            }
        }
    }

    private void LOOPIR(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2, int i3, int i4, boolean z) {
        for (int i5 = 0; i5 < i; i5++) {
            Pointer pointer4 = new Pointer(pointer3);
            int i6 = 1;
            while (i6 <= i2) {
                LOOPJR(pointer, pointer2, pointer4, 64, i4, i6);
                i6++;
            }
            if (z) {
                LOOPJR(pointer, pointer2, pointer4, i3, i4, i6);
            }
            pointer2.move(i4);
        }
    }

    private void LOOPIR_INIT(Pointer pointer, Pointer pointer2, Pointer pointer3, Pointer pointer4, int i, int i2) {
        while (i < i2) {
            pointer.setRangeClear(0, this.NB_WORD_GFqn);
            pointer2.changeIndex(pointer3);
            LOOPK_COMPLETE(pointer, pointer4, pointer2, 0, this.HFEnvq);
            pointer4.move(this.NB_WORD_GF2nv);
            i++;
        }
    }

    private void LOOPIR_LOOPK_COMPLETE(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2) {
        while (i < i2) {
            LOOPK_COMPLETE(pointer, pointer2, pointer3, 0, this.HFEnvq);
            i++;
        }
    }

    private void LOOPJR(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2, int i3) {
        int min = Math.min(i2, i3);
        pointer.set(0L);
        for (int i4 = 0; i4 < i; i4++) {
            pointer.setXor(GeMSSUtils.XORBITS_UINT(pointer2.getDotProduct(0, pointer3, 0, min)) << i4);
            pointer3.move(i3);
        }
        pointer.moveIncremental();
    }

    private long LOOPJR_NOCST_64(Pointer pointer, PointerUnion pointerUnion, int i, int i2, long j, int i3, int i4) {
        while (i < i2) {
            if ((1 & j) != 0) {
                pointer.setXorRange(0, pointerUnion, 0, i4);
            }
            pointerUnion.moveNextBytes(i3);
            j >>>= 1;
            i++;
        }
        return j;
    }

    private void LOOPJR_UNROLLED_64(Pointer pointer, PointerUnion pointerUnion, int i, int i2, long j, int i3, int i4) {
        int i5 = i;
        long j2 = j;
        while (i5 < i2 - 3) {
            j2 = LOOPJR_NOCST_64(pointer, pointerUnion, 0, 4, j2, i3, i4);
            i5 += 4;
        }
        LOOPJR_NOCST_64(pointer, pointerUnion, i5, i2, j2, i3, i4);
    }

    private void LOOPKR(Pointer pointer, Pointer pointer2, long j, int i, int i2) {
        while (i < i2) {
            pointer2.setXorRangeAndMaskMove(pointer, this.NB_WORD_GFqn, -(1 & j));
            j >>>= 1;
            i++;
        }
    }

    private void LOOPK_COMPLETE(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2) {
        while (i < i2) {
            LOOPKR(pointer3, pointer, pointer2.get(i), 0, 64);
            i++;
        }
        if (this.HFEnvr != 0) {
            LOOPKR(pointer3, pointer, pointer2.get(i2), 0, this.HFEnvr);
        }
        pointer.move(this.NB_WORD_GFqn);
    }

    private int chooseRootHFE_gf2nx(Pointer pointer, SecretKeyHFE.complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar, Pointer pointer2) {
        Pointer pointer3 = new Pointer(this.SIZE_DIGEST_UINT);
        Pointer pointer4 = new Pointer(((this.HFEDeg << 1) - 1) * this.NB_WORD_GFqn);
        Pointer pointer5 = new Pointer((this.HFEDeg + 1) * this.NB_WORD_GFqn);
        Pointer pointer6 = new Pointer(this.NB_WORD_GFqn);
        pointer6.setRangeFromXor(complete_sparse_monic_gf2nxVar.poly, pointer2, this.NB_WORD_GFqn);
        int i = this.HFEDeg;
        if (i <= 34 || (this.HFEn > 196 && i < 256)) {
            frobeniusMap_multisqr_HFE_gf2nx(pointer4, complete_sparse_monic_gf2nxVar, pointer6);
        } else {
            int i2 = 2 << this.HFEDegI;
            pointer4.set(this.NB_WORD_GFqn * i2, 1L);
            divsqr_r_HFE_cstdeg_gf2nx(pointer4, i2, i2, this.HFEDeg, complete_sparse_monic_gf2nxVar, pointer6);
            for_sqr_divsqr(pointer4, this.HFEDegI + 1, this.HFEn, complete_sparse_monic_gf2nxVar, pointer6);
        }
        pointer4.setXor(this.NB_WORD_GFqn, 1L);
        int index = pointer5.getIndex();
        pointer5.copyFrom(complete_sparse_monic_gf2nxVar.poly, this.NB_WORD_GFqn);
        for_copy_move(pointer5, complete_sparse_monic_gf2nxVar);
        pointer5.changeIndex(index);
        pointer5.set(this.HFEDeg * this.NB_WORD_GFqn, 1L);
        pointer5.setXorRange(pointer2, this.NB_WORD_GFqn);
        int gcd_gf2nx = gcd_gf2nx(pointer5, this.HFEDeg, pointer4, pointer4.getD_for_not0_or_plus(this.NB_WORD_GFqn, this.HFEDeg - 1));
        if (this.buffer != 0) {
            pointer4.swap(pointer5);
        }
        if (pointer4.is0_gf2n(0, this.NB_WORD_GFqn) == 0) {
            return 0;
        }
        convMonic_gf2nx(pointer5, gcd_gf2nx);
        Pointer pointer7 = new Pointer(this.NB_WORD_GFqn * gcd_gf2nx);
        findRootsSplit_gf2nx(pointer7, pointer5, gcd_gf2nx);
        if (gcd_gf2nx == 1) {
            pointer.copyFrom(pointer7, this.NB_WORD_GFqn);
        } else {
            fast_sort_gf2n(pointer7, gcd_gf2nx);
            getSHA3Hash(pointer3, 0, this.Sha3BitStrength >>> 3, pointer2.toBytes(this.NB_BYTES_GFqn), 0, this.NB_BYTES_GFqn, new byte[this.Sha3BitStrength >>> 3]);
            int i3 = this.NB_WORD_GFqn;
            pointer.copyFrom(0, pointer7, ((int) remainderUnsigned(pointer3.get(), gcd_gf2nx)) * i3, i3);
        }
        return gcd_gf2nx;
    }

    private void choose_LOOPJR(Pointer pointer, PointerUnion pointerUnion, int i, long j, int i2, int i3) {
        int i4 = this.HFEnvr;
        if (i4 < 8) {
            LOOPJR_NOCST_64(pointer, pointerUnion, i, i4, j, i2, i3);
        } else {
            LOOPJR_UNROLLED_64(pointer, pointerUnion, i, i4, j, i2, i3);
        }
    }

    private long convMQ_last_uncompressL_gf2(Pointer pointer, PointerUnion pointerUnion) {
        PointerUnion pointerUnion2 = new PointerUnion(pointerUnion);
        int i = this.HFEnv - 1;
        int i2 = i >>> 6;
        int i3 = i & 63;
        int for_setpk2_end_move_plus = for_setpk2_end_move_plus(pointer, pointerUnion2, i2);
        if (i3 != 0) {
            for_setpk2_end_move_plus = setPk2Value(pointer, pointerUnion2, for_setpk2_end_move_plus, i2, i3 + 1);
        }
        int i4 = this.HFEnv;
        int i5 = this.LOST_BITS;
        int i6 = i4 - i5;
        int i7 = i6 >>> 6;
        int i8 = i6 & 63;
        if (i8 != 0) {
            int i9 = for_setpk2_end_move_plus & 63;
            if (i9 != 0) {
                int i10 = this.NB_MONOMIAL_PK;
                if (((((i10 - i5) + 7) >>> 3) & 7) != 0) {
                    int i11 = (i4 - ((64 - (((i10 - i5) - this.HFEnvr) & 63)) & 63)) >>> 6;
                    pointer.setRangePointerUnion_Check(pointerUnion2, i11, for_setpk2_end_move_plus);
                    pointer.set(i11, pointerUnion2.getWithCheck(i11) >>> i9);
                    if (i11 < i7) {
                        int i12 = i11 + 1;
                        long withCheck = pointerUnion2.getWithCheck(i12);
                        pointer.setXor(i11, withCheck << (64 - i9));
                        pointer.set(i12, withCheck >>> i9);
                    } else if (i8 + i9 > 64) {
                        pointer.setXor(i11, pointerUnion2.getWithCheck(i11 + 1) << (64 - i9));
                    }
                } else {
                    pointer.setRangePointerUnion(pointerUnion2, i7, i9);
                    pointer.set(i7, pointerUnion2.get(i7) >>> i9);
                    if (i8 + i9 > 64) {
                        pointer.setXor(i7, pointerUnion2.get(i7 + 1) << (64 - i9));
                    }
                }
            } else if (((((this.NB_MONOMIAL_PK - i5) + 7) >>> 3) & 7) != 0) {
                pointer.setRangePointerUnion(pointerUnion2, i7);
                pointer.set(i7, pointerUnion2.getWithCheck(i7));
            } else {
                i7++;
                pointer.setRangePointerUnion(pointerUnion2, i7);
            }
        } else if (i7 != 0) {
            int i13 = for_setpk2_end_move_plus & 63;
            if (i13 != 0) {
                if (((((this.NB_MONOMIAL_PK - i5) + 7) >>> 3) & 7) != 0) {
                    int i14 = i7 - 1;
                    pointer.setRangePointerUnion(pointerUnion2, i14, i13);
                    pointer.set(i14, pointerUnion2.get(i14) >>> i13);
                    pointer.setXor(i14, pointerUnion2.getWithCheck(i7) << (64 - i13));
                } else {
                    pointer.setRangePointerUnion(pointerUnion2, i7, i13);
                }
            }
            pointer.setRangePointerUnion(pointerUnion2, i7);
        }
        return pointerUnion.get() & 1;
    }

    private long convMQ_uncompressL_gf2(Pointer pointer, PointerUnion pointerUnion) {
        PointerUnion pointerUnion2 = new PointerUnion(pointerUnion);
        int for_setpk2_end_move_plus = for_setpk2_end_move_plus(pointer, pointerUnion2, this.HFEnvq);
        int i = this.HFEnvr;
        if (i != 0) {
            setPk2Value(pointer, pointerUnion2, for_setpk2_end_move_plus, this.HFEnvq, i + 1);
        }
        return pointerUnion.get() & 1;
    }

    private void convMonic_gf2nx(Pointer pointer, int i) {
        Pointer pointer2 = new Pointer(this.NB_WORD_GFqn);
        int index = pointer.getIndex();
        pointer.move(this.NB_WORD_GFqn * i);
        inv_gf2n(pointer2, pointer, 0);
        pointer.set1_gf2n(0, this.NB_WORD_GFqn);
        while (true) {
            i--;
            if (i == -1) {
                pointer.changeIndex(index);
                return;
            } else {
                pointer.move(-this.NB_WORD_GFqn);
                mul_gf2n(pointer, pointer, pointer2);
            }
        }
    }

    private void copy_for_casct(Pointer pointer, Pointer pointer2, Pointer pointer3, Pointer pointer4, Pointer pointer5, int i, int i2) {
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        while (i > 1) {
            pointer4.changeIndex(pointer3, (i2 + i) * this.NB_WORD_GFqn);
            CMP_AND_SWAP_CST_TIME(pointer, pointer4, pointer5);
            i >>>= 1;
        }
    }

    private void copy_move_matrix_move(Pointer pointer, Pointer pointer2, int i) {
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        pointer2.move(this.NB_WORD_GFqn);
        pointer.setXorMatrix(pointer2, this.NB_WORD_GFqn, i);
        pointer2.move(this.NB_WORD_GFqn * (this.HFEv + 1));
    }

    private void div_q_monic_gf2nx(Pointer pointer, int i, Pointer pointer2, int i2) {
        Pointer pointer3 = new Pointer();
        Pointer pointer4 = new Pointer();
        while (i >= i2) {
            int searchDegree = pointer.searchDegree(i, i2, this.NB_WORD_GFqn);
            if (searchDegree < i2) {
                return;
            }
            pointer3.changeIndex(pointer, this.NB_WORD_GFqn * searchDegree);
            int max = Math.max(0, (i2 << 1) - searchDegree);
            pointer4.changeIndex(pointer, ((searchDegree - i2) + max) * this.NB_WORD_GFqn);
            for_mul_rem_xor_move(pointer4, pointer3, pointer2, max, i2);
            i = searchDegree - 1;
        }
    }

    private void div_r_monic_cst_gf2nx(Pointer pointer, int i, Pointer pointer2, int i2) {
        Pointer pointer3 = new Pointer();
        int index = pointer.getIndex();
        pointer.move(this.NB_WORD_GFqn * i);
        while (i >= i2) {
            pointer3.changeIndex(pointer, (-i2) * this.NB_WORD_GFqn);
            for_mul_rem_xor_move(pointer3, pointer, pointer2, 0, i2);
            pointer.move(-this.NB_WORD_GFqn);
            i--;
        }
        pointer.changeIndex(index);
    }

    private int div_r_monic_gf2nx(Pointer pointer, int i, Pointer pointer2, int i2) {
        Pointer pointer3 = new Pointer();
        Pointer pointer4 = new Pointer();
        while (i >= i2) {
            i = pointer.searchDegree(i, i2, this.NB_WORD_GFqn);
            if (i < i2) {
                break;
            }
            pointer3.changeIndex(pointer, this.NB_WORD_GFqn * i);
            pointer4.changeIndex(pointer3, (-i2) * this.NB_WORD_GFqn);
            for_mul_rem_xor_move(pointer4, pointer3, pointer2, 0, i2);
            i--;
        }
        if (i == -1) {
            i++;
        }
        return pointer.searchDegree(i, 1, this.NB_WORD_GFqn);
    }

    private void divsqr_r_HFE_cstdeg_gf2nx(Pointer pointer, int i, int i2, int i3, SecretKeyHFE.complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar, Pointer pointer2) {
        Pointer pointer3 = new Pointer(pointer, i * this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer();
        while (i2 >= i3) {
            pointer4.changeIndex(pointer3, (-this.HFEDeg) * this.NB_WORD_GFqn);
            mul_rem_xorrange(pointer4, pointer3, pointer2);
            for (int i4 = 1; i4 < this.NB_COEFS_HFEPOLY; i4++) {
                pointer4.move(complete_sparse_monic_gf2nxVar.f1290L[i4]);
                mul_rem_xorrange(pointer4, pointer3, complete_sparse_monic_gf2nxVar.poly, this.NB_WORD_GFqn * i4);
            }
            pointer3.move(-this.NB_WORD_GFqn);
            i2--;
        }
    }

    private void dotProduct_gf2n(Pointer pointer, Pointer pointer2, Pointer pointer3, int i) {
        Pointer pointer4 = new Pointer(this.NB_WORD_MUL);
        int index = pointer2.getIndex();
        int index2 = pointer3.getIndex();
        mul_move(pointer4, pointer2, pointer3);
        for_mul_xorrange_move(pointer4, pointer2, pointer3, i - 1);
        rem_gf2n(pointer, 0, pointer4);
        pointer2.changeIndex(index);
        pointer3.changeIndex(index2);
    }

    private void dotproduct_move_move(Pointer pointer, Pointer pointer2, Pointer pointer3, int i) {
        dotProduct_gf2n(pointer, pointer3, pointer2, i);
        pointer.move(this.NB_WORD_GFqn);
        pointer2.move((i + this.HFEv + 1) * this.NB_WORD_GFqn);
    }

    private void evalMQShybrid8_uncomp_nocst_gf2_m(Pointer pointer, Pointer pointer2, PointerUnion pointerUnion, PointerUnion pointerUnion2) {
        PointerUnion pointerUnion3 = new PointerUnion(pointerUnion2);
        evalMQSnocst8_quo_gf2(pointer, pointer2, pointerUnion);
        if (this.HFEmr < 8) {
            pointer.set(this.HFEmq, 0L);
        }
        for (int i = this.HFEmr - this.HFEmr8; i < this.HFEmr; i++) {
            pointer.setXor(this.HFEmq, evalMQnocst_unrolled_no_simd_gf2(pointer2, pointerUnion3) << i);
            pointerUnion3.move(this.NB_WORD_UNCOMP_EQ);
        }
    }

    private void evalMQSnocst8_quo_gf2(Pointer pointer, Pointer pointer2, PointerUnion pointerUnion) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        PointerUnion pointerUnion2;
        int i7;
        int i8 = this.HFEnv;
        int i9 = this.HFEm;
        if ((i9 >>> 3) != 0) {
            i9 = (i9 >>> 3) << 3;
        }
        int i10 = i9;
        int i11 = (i10 & 7) != 0 ? (i10 >>> 3) + 1 : i10 >>> 3;
        int i12 = (i11 >>> 3) + ((i11 & 7) != 0 ? 1 : 0);
        PointerUnion pointerUnion3 = new PointerUnion(pointerUnion);
        System.arraycopy(pointerUnion3.getArray(), 0, pointer.getArray(), pointer.getIndex(), i12);
        pointerUnion3.moveNextBytes(i11);
        int i13 = 0;
        while (true) {
            i = this.HFEnvq;
            if (i13 >= i) {
                break;
            }
            int i14 = i8;
            long j = pointer2.get(i13);
            int i15 = 0;
            while (i15 < 64) {
                if ((j & 1) != 0) {
                    pointer.setXorRange(0, pointerUnion3, 0, i12);
                    pointerUnion3.moveNextBytes(i11);
                    i4 = i13;
                    i5 = i15;
                    PointerUnion pointerUnion4 = pointerUnion3;
                    i6 = i12;
                    LOOPJR_UNROLLED_64(pointer, pointerUnion3, i15 + 1, 64, j >>> 1, i11, i12);
                    int i16 = i4 + 1;
                    while (true) {
                        i7 = this.HFEnvq;
                        if (i16 >= i7) {
                            break;
                        }
                        LOOPJR_UNROLLED_64(pointer, pointerUnion4, 0, 64, pointer2.get(i16), i11, i6);
                        i16++;
                    }
                    if (this.HFEnvr != 0) {
                        choose_LOOPJR(pointer, pointerUnion4, 0, pointer2.get(i7), i11, i6);
                    }
                    pointerUnion2 = pointerUnion4;
                } else {
                    i4 = i13;
                    i5 = i15;
                    i6 = i12;
                    pointerUnion2 = pointerUnion3;
                    pointerUnion2.moveNextBytes(i14 * i11);
                }
                j >>>= 1;
                i15 = i5 + 1;
                i14--;
                pointerUnion3 = pointerUnion2;
                i12 = i6;
                i13 = i4;
            }
            i13++;
            i8 = i14;
            i12 = i12;
        }
        int i17 = i12;
        PointerUnion pointerUnion5 = pointerUnion3;
        if (this.HFEnvr != 0) {
            int i18 = i8;
            long j2 = pointer2.get(i);
            int i19 = 0;
            while (i19 < this.HFEnvr) {
                if ((j2 & 1) != 0) {
                    int i20 = i17;
                    pointer.setXorRange(0, pointerUnion5, 0, i20);
                    pointerUnion5.moveNextBytes(i11);
                    i2 = i20;
                    i3 = i19;
                    choose_LOOPJR(pointer, pointerUnion5, i19 + 1, j2 >>> 1, i11, i2);
                } else {
                    i2 = i17;
                    i3 = i19;
                    pointerUnion5.moveNextBytes(i18 * i11);
                }
                j2 >>>= 1;
                i19 = i3 + 1;
                i18--;
                i17 = i2;
            }
        }
        int i21 = i17;
        int i22 = i10 & 63;
        if (i22 != 0) {
            pointer.setAnd(i21 - 1, (1 << i22) - 1);
        }
    }

    private long evalMQnocst_unrolled_no_simd_gf2(Pointer pointer, PointerUnion pointerUnion) {
        PointerUnion pointerUnion2 = new PointerUnion(pointerUnion);
        long j = pointer.get();
        long j2 = 0;
        for (int i = 0; i < 64; i++) {
            if ((1 & (j >>> i)) != 0) {
                j2 ^= pointerUnion2.get(i) & j;
            }
        }
        pointerUnion2.move(64);
        int i2 = 1;
        while (true) {
            int i3 = this.NB_WORD_GF2nv;
            if (i2 >= i3) {
                return GeMSSUtils.XORBITS_UINT(j2);
            }
            int i4 = i2 + 1;
            int i5 = (i3 != i4 || (i5 = this.HFEnvr) == 0) ? 64 : 64;
            long j3 = pointer.get(i2);
            for (int i6 = 0; i6 < i5; i6++) {
                if (((j3 >>> i6) & 1) != 0) {
                    j2 ^= pointerUnion2.getDotProduct(0, pointer, 0, i4);
                }
                pointerUnion2.move(i4);
            }
            i2 = i4;
        }
    }

    private void findRootsSplit_gf2nx(Pointer pointer, Pointer pointer2, int i) {
        int i2;
        int gcd_gf2nx;
        int i3;
        if (i == 1) {
            pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        } else if ((this.HFEn & 1) != 0 && i == 2) {
            findRootsSplit2_HT_gf2nx(pointer, pointer2);
        } else {
            int i4 = (i << 1) - 1;
            Pointer pointer3 = new Pointer(this.NB_WORD_GFqn * i4);
            Pointer pointer4 = new Pointer(this.NB_WORD_GFqn * i);
            int i5 = i + 1;
            Pointer pointer5 = new Pointer(this.NB_WORD_GFqn * i5);
            Pointer pointer6 = new Pointer(this.NB_WORD_GFqn);
            while (true) {
                pointer3.setRangeClear(0, this.NB_WORD_GFqn * i4);
                pointer4.setRangeClear(0, this.NB_WORD_GFqn * i);
                do {
                    pointer4.fillRandom(this.NB_WORD_GFqn, this.random, this.NB_BYTES_GFqn);
                    pointer4.setAnd((this.NB_WORD_GFqn << 1) - 1, this.MASK_GF2n);
                    i2 = this.NB_WORD_GFqn;
                } while (pointer4.is0_gf2n(i2, i2) != 0);
                pointer5.copyFrom(pointer2, this.NB_WORD_GFqn * i5);
                traceMap_gf2nx(pointer4, pointer3, pointer5, i);
                gcd_gf2nx = gcd_gf2nx(pointer5, i, pointer4, pointer4.searchDegree(i - 1, 1, this.NB_WORD_GFqn));
                i3 = this.buffer;
                if (gcd_gf2nx != 0 && gcd_gf2nx != i) {
                    break;
                }
            }
            if (i3 != 0) {
                pointer4.swap(pointer5);
            }
            inv_gf2n(pointer6, pointer5, this.NB_WORD_GFqn * gcd_gf2nx);
            int i6 = this.NB_WORD_GFqn;
            pointer5.set1_gf2n(gcd_gf2nx * i6, i6);
            for_mul(pointer5, pointer6, gcd_gf2nx - 1);
            div_q_monic_gf2nx(pointer2, i, pointer5, gcd_gf2nx);
            findRootsSplit_gf2nx(pointer, pointer5, gcd_gf2nx);
            findRootsSplit_gf2nx(new Pointer(pointer, this.NB_WORD_GFqn * gcd_gf2nx), new Pointer(pointer2, this.NB_WORD_GFqn * gcd_gf2nx), i - gcd_gf2nx);
        }
    }

    private void for_and_xor_shift_incre_move(Pointer pointer, int i, int i2) {
        long j = 0;
        for (int i3 = 0; i3 < i2; i3++) {
            pointer.setAnd(j);
            pointer.setXor(1 << i3);
            j = (j << 1) + 1;
            pointer.move(i);
        }
    }

    private void for_casct_move(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2) {
        int i3 = this.NB_WORD_GFqn * i2;
        int i4 = 0;
        while (i4 < i) {
            CMP_AND_SWAP_CST_TIME(pointer, pointer2, pointer3);
            pointer.move(i3);
            pointer2.move(i3);
            i4 += i2;
        }
    }

    private void for_copy_move(Pointer pointer, SecretKeyHFE.complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar) {
        for (int i = 1; i < this.NB_COEFS_HFEPOLY; i++) {
            pointer.move(complete_sparse_monic_gf2nxVar.f1290L[i]);
            Pointer pointer2 = complete_sparse_monic_gf2nxVar.poly;
            int i2 = this.NB_WORD_GFqn;
            pointer.copyFrom(0, pointer2, i * i2, i2);
        }
    }

    private void for_mul(Pointer pointer, Pointer pointer2, int i) {
        Pointer pointer3 = new Pointer(pointer, this.NB_WORD_GFqn * i);
        while (i != -1) {
            mul_gf2n(pointer3, pointer3, pointer2);
            pointer3.move(-this.NB_WORD_GFqn);
            i--;
        }
    }

    private void for_mul_rem_xor_move(Pointer pointer, Pointer pointer2, Pointer pointer3, int i, int i2) {
        int i3 = this.NB_WORD_GFqn * i;
        while (i < i2) {
            mul_rem_xorrange(pointer, pointer2, pointer3, i3);
            pointer.move(this.NB_WORD_GFqn);
            i++;
            i3 += this.NB_WORD_GFqn;
        }
    }

    private int for_setPK(byte[] bArr, byte[] bArr2, int i, int i2, int i3) {
        bArr[i] = (byte) (bArr2[i2] & 3);
        int i4 = 2;
        for (int i5 = 2; i5 < i3; i5++) {
            int i6 = this.HFEnv;
            i4 = setPK(bArr, bArr2, i5, i, i2, i4, i6 - 1, i6 - i5);
        }
        return i4;
    }

    private int for_setpk2_end_move_plus(Pointer pointer, PointerUnion pointerUnion, int i) {
        int i2 = 0;
        int i3 = 1;
        while (i2 < i) {
            int pk2Value = setPk2Value(pointer, pointerUnion, i3, i2, 64);
            setPk2_endValue(pointer, pointerUnion, pk2Value, i2);
            i2++;
            pointerUnion.move(i2);
            pointer.move(i2);
            i3 = pk2Value + (i2 << 6);
        }
        return i3;
    }

    private void for_sqr_divsqr(Pointer pointer, int i, int i2, SecretKeyHFE.complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar, Pointer pointer2) {
        while (i < i2) {
            sqr_gf2nx(pointer, this.HFEDeg - 1);
            int i3 = this.HFEDeg;
            divsqr_r_HFE_cstdeg_gf2nx(pointer, (i3 - 1) << 1, (i3 - 1) << 1, i3, complete_sparse_monic_gf2nxVar, pointer2);
            i++;
        }
    }

    private void frobeniusMap_multisqr_HFE_gf2nx(Pointer pointer, SecretKeyHFE.complete_sparse_monic_gf2nx complete_sparse_monic_gf2nxVar, Pointer pointer2) {
        Pointer pointer3 = new Pointer();
        Pointer pointer4 = new Pointer(this.HFEDeg * this.NB_WORD_GFqn);
        Pointer pointer5 = new Pointer();
        Pointer pointer6 = new Pointer(((this.f1265KX * this.HFEDeg) + this.POW_II) * this.NB_WORD_GFqn);
        int i = (this.POW_II * this.f1264KP) - this.HFEDeg;
        Pointer pointer7 = new Pointer(pointer6, this.NB_WORD_GFqn * i);
        pointer7.copyFrom(pointer2, this.NB_WORD_GFqn);
        for_copy_move(pointer7, complete_sparse_monic_gf2nxVar);
        int i2 = i - 1;
        divsqr_r_HFE_cstdeg_gf2nx(pointer6, i2 + this.HFEDeg, i2, 0, complete_sparse_monic_gf2nxVar, pointer2);
        int i3 = this.f1264KP + 1;
        while (true) {
            int i4 = this.HFEDeg;
            if (i3 >= i4) {
                break;
            }
            pointer7.changeIndex(pointer6, i4 * this.NB_WORD_GFqn);
            pointer7.setRangeClear(0, this.POW_II * this.NB_WORD_GFqn);
            int i5 = this.POW_II;
            int i6 = this.NB_WORD_GFqn;
            pointer7.copyFrom(i5 * i6, pointer6, 0, this.HFEDeg * i6);
            pointer6.changeIndex(pointer7);
            int i7 = this.POW_II;
            divsqr_r_HFE_cstdeg_gf2nx(pointer6, this.HFEDeg + (i7 - 1), i7 - 1, 0, complete_sparse_monic_gf2nxVar, pointer2);
            i3++;
        }
        pointer6.indexReset();
        int i8 = (1 << this.HFEDegI) - this.f1264KP;
        int i9 = this.HFEDeg;
        int i10 = this.NB_WORD_GFqn;
        pointer.copyFrom(0, pointer6, i8 * i9 * i10, i9 * i10);
        int i11 = 0;
        while (true) {
            int i12 = this.HFEn;
            int i13 = this.HFEDegI;
            int i14 = this.f1263II;
            if (i11 >= ((i12 - i13) - i14) / i14) {
                for_sqr_divsqr(pointer, 0, (i12 - i13) % i14, complete_sparse_monic_gf2nxVar, pointer2);
                return;
            }
            loop_sqr(pointer4, pointer);
            for (int i15 = 1; i15 < this.f1263II; i15++) {
                loop_sqr(pointer4, pointer4);
            }
            pointer5.changeIndex(pointer4, this.f1264KP * this.NB_WORD_GFqn);
            pointer7.changeIndex(pointer6);
            pointer3.changeIndex(pointer);
            for (int i16 = 0; i16 < this.HFEDeg; i16++) {
                mul_gf2n(pointer3, pointer7, pointer5);
                pointer3.move(this.NB_WORD_GFqn);
                pointer7.move(this.NB_WORD_GFqn);
            }
            int i17 = this.f1264KP;
            while (true) {
                i17++;
                if (i17 >= this.HFEDeg) {
                    break;
                }
                pointer5.move(this.NB_WORD_GFqn);
                pointer3.changeIndex(pointer);
                for (int i18 = 0; i18 < this.HFEDeg; i18++) {
                    mul_rem_xorrange(pointer3, pointer7, pointer5);
                    pointer3.move(this.NB_WORD_GFqn);
                    pointer7.move(this.NB_WORD_GFqn);
                }
            }
            for (int i19 = 0; i19 < this.f1264KP; i19++) {
                int i20 = this.NB_WORD_GFqn;
                pointer.setXorRange(this.POW_II * i19 * i20, pointer4, i19 * i20, i20);
            }
            i11++;
        }
    }

    private int gcd_gf2nx(Pointer pointer, int i, Pointer pointer2, int i2) {
        int div_r_monic_gf2nx;
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        this.buffer = 0;
        Pointer pointer4 = pointer;
        Pointer pointer5 = pointer2;
        int i3 = i;
        while (i2 != 0) {
            if ((i2 << 1) > i3) {
                div_r_monic_gf2nx = div_r_gf2nx(pointer4, i3, pointer5, i2);
            } else {
                inv_gf2n(pointer3, pointer5, this.NB_WORD_GFqn * i2);
                int i4 = this.NB_WORD_GFqn;
                pointer5.set1_gf2n(i2 * i4, i4);
                for_mul(pointer5, pointer3, i2 - 1);
                div_r_monic_gf2nx = div_r_monic_gf2nx(pointer4, i3, pointer5, i2);
            }
            this.buffer = 1 - this.buffer;
            Pointer pointer6 = pointer4;
            pointer4 = pointer5;
            pointer5 = pointer6;
            int i5 = i2;
            i2 = div_r_monic_gf2nx;
            i3 = i5;
        }
        return i3;
    }

    private void getSHA3Hash(Pointer pointer, int i, int i2, byte[] bArr, int i3, int i4, byte[] bArr2) {
        this.sha3Digest.update(bArr, i3, i4);
        this.sha3Digest.doFinal(bArr2, 0);
        pointer.fill(i, bArr2, 0, i2);
    }

    private void initListDifferences_gf2nx(int[] iArr) {
        iArr[1] = this.NB_WORD_GFqn;
        int i = 2;
        int i2 = 0;
        while (i2 < this.HFEDegI) {
            if (!this.ENABLED_REMOVE_ODD_DEGREE || (1 << i2) + 1 <= this.HFE_odd_degree) {
                iArr[i] = this.NB_WORD_GFqn;
                i = setArrayL(iArr, i + 1, 0, i2);
            } else {
                if (i2 != 0) {
                    iArr[i] = this.NB_WORD_GFqn << 1;
                    i++;
                }
                i = setArrayL(iArr, i, 1, i2);
            }
            i2++;
        }
        int i3 = this.HFEDegJ;
        if (i3 != 0) {
            if (!this.ENABLED_REMOVE_ODD_DEGREE || (1 << i2) + 1 <= this.HFE_odd_degree) {
                iArr[i] = this.NB_WORD_GFqn;
                setArrayL(iArr, i + 1, 0, i3 - 1);
                return;
            }
            iArr[i] = this.NB_WORD_GFqn << 1;
            setArrayL(iArr, i + 1, 1, i3 - 1);
        }
    }

    private void inv_gf2n(Pointer pointer, Pointer pointer2, int i) {
        int index = pointer2.getIndex();
        pointer2.move(i);
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        for (int i2 = this.HFEn_1rightmost - 1; i2 != -1; i2--) {
            int i3 = (this.HFEn - 1) >>> (i2 + 1);
            sqr_gf2n(pointer3, pointer);
            for (int i4 = 1; i4 < i3; i4++) {
                sqr_gf2n(pointer3, pointer3);
            }
            mul_gf2n(pointer, pointer, pointer3);
            if ((((this.HFEn - 1) >>> i2) & 1) != 0) {
                sqr_gf2n(pointer3, pointer);
                mul_gf2n(pointer, pointer2, pointer3);
            }
        }
        sqr_gf2n(pointer, pointer);
        pointer2.changeIndex(index);
    }

    private void loop_sqr(Pointer pointer, Pointer pointer2) {
        for (int i = 0; i < this.HFEDeg; i++) {
            int i2 = this.NB_WORD_GFqn;
            sqr_gf2n(pointer, i * i2, pointer2, i2 * i);
        }
    }

    private int loop_xor_loop_move_xorandmask_move(Pointer pointer, Pointer pointer2, Pointer pointer3, Pointer pointer4, int i, int i2, int i3, int i4, int i5) {
        int i6 = 0;
        int i7 = i;
        while (i6 < i3) {
            pointer.setXor(i2, 1 << i6);
            pointer2.changeIndex(pointer);
            pointer3.changeIndex(pointer4);
            for (int i8 = i7; i8 < i4; i8++) {
                pointer2.move(i5);
                pointer3.move((i8 >>> 6) + 1);
                pointer2.setXorRangeAndMask(pointer, i2 + 1, -((pointer3.get() >>> i6) & 1));
            }
            pointer.move(i5);
            pointer4.move(i2 + 1);
            i6++;
            i7++;
        }
        return i7;
    }

    private void mulMatricesLU_gf2(Pointer pointer, Pointer pointer2, Pointer pointer3, FunctionParams functionParams) {
        int i;
        boolean z;
        int i2;
        int index = pointer.getIndex();
        int i3 = C13931.f1266xb3d0f197[functionParams.ordinal()];
        if (i3 == 1) {
            i = this.HFEnq;
            z = true;
            i2 = this.HFEnr;
        } else if (i3 != 2) {
            throw new IllegalArgumentException("Invalid parameter for MULMATRICESLU_GF2");
        } else {
            int i4 = this.HFEnvq;
            int i5 = this.HFEnvr;
            i = i4;
            i2 = i5;
            z = i5 != 0;
        }
        Pointer pointer4 = new Pointer(pointer2);
        int i6 = 1;
        while (i6 <= i) {
            LOOPIR(pointer, pointer4, pointer3, 64, i, i2, i6, z);
            i6++;
        }
        LOOPIR(pointer, pointer4, pointer3, i2, i, i2, i6, z);
        pointer.changeIndex(index);
    }

    private void precSignHFE(SecretKeyHFE secretKeyHFE, Pointer[] pointerArr, byte[] bArr) {
        precSignHFESeed(secretKeyHFE, bArr);
        initListDifferences_gf2nx(secretKeyHFE.F_struct.f1290L);
        Pointer pointer = new Pointer(secretKeyHFE.F_HFEv);
        Pointer pointer2 = new Pointer(this.NB_COEFS_HFEPOLY * this.NB_WORD_GFqn);
        Pointer pointer3 = new Pointer(pointer, this.MQv_GFqn_SIZE);
        pointerArr[0] = pointer3;
        pointer.changeIndex(pointer3, this.MLv_GFqn_SIZE);
        Pointer pointer4 = new Pointer(pointer2, this.NB_WORD_GFqn * 2);
        int i = 0;
        while (true) {
            int i2 = 1;
            if (i >= this.HFEDegI) {
                break;
            }
            if ((1 << i) + 1 <= this.HFE_odd_degree || !this.ENABLED_REMOVE_ODD_DEGREE) {
                i2 = 0;
            }
            int i3 = i - i2;
            pointer4.copyFrom(pointer, this.NB_WORD_GFqn * i3);
            pointer.move(this.NB_WORD_GFqn * i3);
            pointer4.move(i3 * this.NB_WORD_GFqn);
            i++;
            pointerArr[i] = new Pointer(pointer);
            pointer.move(this.MLv_GFqn_SIZE);
            pointer4.move(this.NB_WORD_GFqn);
        }
        int i4 = this.HFEDegJ;
        if (i4 != 0) {
            pointer4.copyFrom(pointer, (i4 - ((1 << i) + 1 > this.HFE_odd_degree ? 1 : 0)) * this.NB_WORD_GFqn);
        }
        secretKeyHFE.F_struct.poly = new Pointer(pointer2);
    }

    private void precSignHFESeed(SecretKeyHFE secretKeyHFE, byte[] bArr) {
        int i = this.NB_UINT_HFEVPOLY + ((this.LTRIANGULAR_NV_SIZE + this.LTRIANGULAR_N_SIZE) << 1);
        secretKeyHFE.sk_uncomp = new Pointer(this.MATRIXnv_SIZE + i + this.MATRIXn_SIZE);
        SHAKEDigest sHAKEDigest = new SHAKEDigest(this.ShakeBitStrength);
        sHAKEDigest.update(bArr, 0, this.SIZE_SEED_SK);
        int i2 = i << 3;
        byte[] bArr2 = new byte[i2];
        sHAKEDigest.doFinal(bArr2, 0, i2);
        secretKeyHFE.sk_uncomp.fill(0, bArr2, 0, i2);
        secretKeyHFE.f1288S = new Pointer(secretKeyHFE.sk_uncomp, i);
        secretKeyHFE.f1289T = new Pointer(secretKeyHFE.f1288S, this.MATRIXnv_SIZE);
        secretKeyHFE.F_HFEv = new Pointer(secretKeyHFE.sk_uncomp);
        cleanMonicHFEv_gf2nx(secretKeyHFE.F_HFEv);
        Pointer pointer = new Pointer(secretKeyHFE.sk_uncomp, this.NB_UINT_HFEVPOLY);
        Pointer pointer2 = new Pointer(pointer, this.LTRIANGULAR_NV_SIZE);
        cleanLowerMatrix(pointer, FunctionParams.NV);
        cleanLowerMatrix(pointer2, FunctionParams.NV);
        mulMatricesLU_gf2(secretKeyHFE.f1288S, pointer, pointer2, FunctionParams.NV);
        pointer.move(this.LTRIANGULAR_NV_SIZE << 1);
        pointer2.changeIndex(pointer, this.LTRIANGULAR_N_SIZE);
        cleanLowerMatrix(pointer, FunctionParams.N);
        cleanLowerMatrix(pointer2, FunctionParams.N);
        mulMatricesLU_gf2(secretKeyHFE.f1289T, pointer, pointer2, FunctionParams.N);
    }

    private void rem_gf2n(Pointer pointer, int i, Pointer pointer2) {
        this.rem.rem_gf2n(pointer.array, i + pointer.getIndex(), pointer2.array);
    }

    private static long remainderUnsigned(long j, long j2) {
        return (j <= 0 || j2 <= 0) ? new BigInteger(1, Pack.longToBigEndian(j)).mod(new BigInteger(1, Pack.longToBigEndian(j2))).longValue() : j % j2;
    }

    private int setArrayL(int[] iArr, int i, int i2, int i3) {
        while (i2 < i3) {
            iArr[i] = this.NB_WORD_GFqn << i2;
            i2++;
            i++;
        }
        return i;
    }

    private int setPK(byte[] bArr, byte[] bArr2, int i, int i2, int i3, int i4, int i5, int i6) {
        while (i5 >= i6) {
            int i7 = (i4 >>> 3) + i2;
            bArr[i7] = (byte) (bArr[i7] ^ (((bArr2[(i >>> 3) + i3] >>> (i & 7)) & 1) << (i4 & 7)));
            i += i5;
            i5--;
            i4++;
        }
        this.buffer = i;
        return i4;
    }

    private int setPk2Value(Pointer pointer, PointerUnion pointerUnion, int i, int i2, int i3) {
        for (int i4 = 1; i4 < i3; i4++) {
            int i5 = i & 63;
            if (i5 != 0) {
                pointer.setRangePointerUnion(pointerUnion, i2, i5);
                pointer.set(i2, pointerUnion.get(i2) >>> i5);
                int i6 = i5 + i4;
                if (i6 > 64) {
                    pointer.setXor(i2, pointerUnion.get(i2 + 1) << (64 - i5));
                }
                if (i6 >= 64) {
                    pointerUnion.moveIncremental();
                }
            } else {
                pointer.setRangePointerUnion(pointerUnion, i2 + 1);
            }
            pointerUnion.move(i2);
            pointer.setAnd(i2, (1 << i4) - 1);
            pointer.move(i2 + 1);
            i += (i2 << 6) + i4;
        }
        return i;
    }

    private void setPk2_endValue(Pointer pointer, PointerUnion pointerUnion, int i, int i2) {
        int i3 = i & 63;
        int i4 = i2 + 1;
        if (i3 != 0) {
            pointer.setRangePointerUnion(pointerUnion, i4, i3);
        } else {
            pointer.setRangePointerUnion(pointerUnion, i4);
        }
    }

    private void special_buffer(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        int i;
        int index = pointer2.getIndex();
        pointer2.move((this.NB_WORD_GFqn * (this.HFEv + 1)) << 1);
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        pointer.move(this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer(pointer2, this.NB_WORD_GFqn * (this.HFEv + 2));
        int i2 = 2;
        while (i2 < this.SIZE_ROW - 1) {
            copy_move_matrix_move(pointer, pointer4, i2 - 1);
            i2++;
        }
        if (this.ENABLED_REMOVE_ODD_DEGREE) {
            while (i2 < this.SIZE_ROW - 1) {
                copy_move_matrix_move(pointer, pointer4, i2 - 2);
                i2++;
            }
        }
        pointer.set1_gf2n(0, this.NB_WORD_GFqn);
        pointer.setXorMatrix(pointer4, this.NB_WORD_GFqn, this.HFEDegJ);
        for (int i3 = 0; i3 < this.HFEn - 1; i3++) {
            mul_gf2n(pointer, pointer3, pointer2);
            pointer.move(this.NB_WORD_GFqn);
            pointer4.changeIndex(pointer2, this.NB_WORD_GFqn * (this.HFEv + 2));
            int i4 = 2;
            while (i4 < this.HFEDegI) {
                dotproduct_move_move(pointer, pointer4, pointer3, i4);
                i4++;
            }
            if (this.ENABLED_REMOVE_ODD_DEGREE) {
                pointer3.move(this.NB_WORD_GFqn);
                while (i4 < this.SIZE_ROW - 1) {
                    dotproduct_move_move(pointer, pointer4, pointer3, i4 - 1);
                    i4++;
                }
                pointer3.move(-this.NB_WORD_GFqn);
            }
            int i5 = this.HFEDegJ;
            if (i5 == 0) {
                pointer.copyFrom(pointer3, this.NB_WORD_GFqn);
                pointer.move(this.NB_WORD_GFqn);
                i = this.SIZE_ROW;
            } else {
                dotProduct_gf2n(pointer, pointer3, pointer4, i5);
                pointer3.move(this.HFEDegJ * this.NB_WORD_GFqn);
                pointer.setXorRange_SelfMove(pointer3, this.NB_WORD_GFqn);
                i = this.SIZE_ROW - this.HFEDegJ;
            }
            pointer3.move(i * this.NB_WORD_GFqn);
        }
        pointer.indexReset();
        pointer2.changeIndex(index);
        pointer3.indexReset();
    }

    private void sqr_gf2n(Pointer pointer, int i, Pointer pointer2, int i2) {
        this.mul.sqr_gf2x(this.Buffer_NB_WORD_MUL.array, pointer2.array, i2 + pointer2.f1275cp);
        rem_gf2n(pointer, i, this.Buffer_NB_WORD_MUL);
    }

    private void sqr_gf2n(Pointer pointer, Pointer pointer2) {
        this.mul.sqr_gf2x(this.Buffer_NB_WORD_MUL.array, pointer2.array, pointer2.f1275cp);
        this.rem.rem_gf2n(pointer.array, pointer.f1275cp, this.Buffer_NB_WORD_MUL.array);
    }

    private void sqr_gf2nx(Pointer pointer, int i) {
        int i2 = this.NB_WORD_GFqn * i;
        int index = pointer.getIndex();
        pointer.move(i2);
        Pointer pointer2 = new Pointer(pointer, i2);
        for (int i3 = 0; i3 < i; i3++) {
            sqr_gf2n(pointer2, pointer);
            pointer.move(-this.NB_WORD_GFqn);
            pointer2.move(-this.NB_WORD_GFqn);
            pointer2.setRangeClear(0, this.NB_WORD_GFqn);
            pointer2.move(-this.NB_WORD_GFqn);
        }
        sqr_gf2n(pointer, pointer);
        pointer.changeIndex(index);
    }

    private void traceMap_gf2nx(Pointer pointer, Pointer pointer2, Pointer pointer3, int i) {
        int i2;
        int i3 = 1;
        while (true) {
            i2 = 1 << i3;
            if (i2 >= i) {
                break;
            }
            int i4 = this.NB_WORD_GFqn;
            sqr_gf2n(pointer, i4 << i3, pointer, i4 << (i3 - 1));
            i3++;
        }
        if (i3 < this.HFEn) {
            int i5 = this.NB_WORD_GFqn;
            sqr_gf2n(pointer2, i5 << i3, pointer, i5 << (i3 - 1));
            div_r_monic_cst_gf2nx(pointer2, i2, pointer3, i);
            pointer.setXorRange(pointer2, this.NB_WORD_GFqn * i);
            for (int i6 = i3 + 1; i6 < this.HFEn; i6++) {
                int i7 = i - 1;
                sqr_gf2nx(pointer2, i7);
                div_r_monic_cst_gf2nx(pointer2, i7 << 1, pointer3, i);
                pointer.setXorRange(pointer2, this.NB_WORD_GFqn * i);
            }
        }
    }

    private void uncompress_signHFE(Pointer pointer, byte[] bArr) {
        PointerUnion pointerUnion = new PointerUnion(pointer);
        int i = (1 << this.HFEnvr8) - 1;
        pointerUnion.fillBytes(0, bArr, 0, this.NB_BYTES_GFqnv);
        if (this.HFEnvr8 != 0) {
            pointerUnion.setAndByte(this.NB_BYTES_GFqnv - 1, i);
        }
        int i2 = this.HFEnv;
        pointerUnion.moveNextBytes((this.NB_WORD_GF2nv << 3) + (this.HFEmq8 & 7));
        for (int i3 = 1; i3 < this.NB_ITE; i3++) {
            int i4 = i2 & 7;
            int min = Math.min(this.HFEDELTA + this.HFEv, (8 - i4) & 7);
            if (i4 != 0) {
                pointerUnion.setXorByte(((bArr[i2 >>> 3] & UByte.MAX_VALUE) >>> i4) << this.HFEmr8);
                int i5 = min - this.VAL_BITS_M;
                if (i5 >= 0) {
                    pointerUnion.moveNextByte();
                }
                if (i5 > 0) {
                    int i6 = i2 + this.VAL_BITS_M;
                    pointerUnion.setXorByte((bArr[i6 >>> 3] & UByte.MAX_VALUE) >>> (i6 & 7));
                    i2 = i6 + i5;
                } else {
                    i2 += min;
                }
            }
            int i7 = (this.HFEDELTA + this.HFEv) - min;
            int i8 = (this.HFEm + min) & 7;
            if (i8 != 0) {
                for (int i9 = 0; i9 < ((i7 - 1) >>> 3); i9++) {
                    int i10 = i2 >>> 3;
                    pointerUnion.setXorByte((bArr[i10] & UByte.MAX_VALUE) << i8);
                    pointerUnion.moveNextByte();
                    pointerUnion.setXorByte((bArr[i10] & UByte.MAX_VALUE) >>> (8 - i8));
                    i2 += 8;
                }
                int i11 = i2 >>> 3;
                pointerUnion.setXorByte((bArr[i11] & UByte.MAX_VALUE) << i8);
                pointerUnion.moveNextByte();
                int i12 = ((i7 + 7) & 7) + 1;
                int i13 = 8 - i8;
                if (i12 > i13) {
                    pointerUnion.setByte((bArr[i11] & UByte.MAX_VALUE) >>> i13);
                    pointerUnion.moveNextByte();
                }
                i2 += i12;
            } else {
                for (int i14 = 0; i14 < ((i7 + 7) >>> 3); i14++) {
                    pointerUnion.setByte(bArr[i2 >>> 3]);
                    i2 += 8;
                    pointerUnion.moveNextByte();
                }
                i2 -= (8 - (i7 & 7)) & 7;
            }
            if (this.HFEnvr8 != 0) {
                pointerUnion.setAndByte(-1, i);
            }
            pointerUnion.moveNextBytes(((8 - (this.NB_BYTES_GFqnv & 7)) & 7) + (this.HFEmq8 & 7));
        }
    }

    private void vmpv_xorrange_move(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        vecMatProduct(pointer, pointer2, new Pointer(pointer3, this.NB_WORD_GFqn), FunctionParams.V);
        pointer.setXorRange(pointer3, this.NB_WORD_GFqn);
        pointer3.move(this.MLv_GFqn_SIZE);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void changeVariablesMQS64_gf2(Pointer pointer, Pointer pointer2) {
        Pointer pointer3 = new Pointer();
        int i = this.HFEnv;
        Pointer pointer4 = new Pointer(i * i * this.NB_WORD_GFqn);
        Pointer pointer5 = new Pointer(pointer, this.NB_WORD_GFqn);
        Pointer pointer6 = new Pointer(pointer4);
        Pointer pointer7 = new Pointer(pointer2);
        int i2 = 0;
        while (true) {
            int i3 = 64;
            if (i2 >= this.HFEnv) {
                break;
            }
            pointer3.changeIndex(pointer5);
            int i4 = 0;
            while (i4 < this.HFEnvq) {
                int i5 = 0;
                while (i5 < i3) {
                    int i6 = i4;
                    int i7 = i5;
                    LOOPKR(pointer3, pointer6, pointer7.get() >>> i5, i7, 64);
                    LOOPK_COMPLETE(pointer6, pointer7, pointer3, 1, this.HFEnvq - i6);
                    i5 = i7 + 1;
                    i3 = i3;
                    i2 = i2;
                    i4 = i6;
                }
                pointer7.moveIncremental();
                i4++;
            }
            int i8 = i2;
            if (this.HFEnvr != 0) {
                for (int i9 = 0; i9 < this.HFEnvr; i9++) {
                    LOOPKR(pointer3, pointer6, pointer7.get() >>> i9, i9, this.HFEnvr);
                    pointer6.move(this.NB_WORD_GFqn);
                }
                pointer7.moveIncremental();
            }
            i2 = i8 + 1;
        }
        int i10 = 64;
        pointer5.changeIndex(pointer4);
        pointer6.changeIndex(pointer, this.NB_WORD_GFqn);
        Pointer pointer8 = new Pointer(pointer2);
        int i11 = 0;
        while (i11 < this.HFEnvq) {
            int i12 = 0;
            while (i12 < i10) {
                pointer7.changeIndex(pointer8);
                int i13 = i12;
                int i14 = i11;
                Pointer pointer9 = pointer8;
                LOOPIR_INIT(pointer6, pointer3, pointer5, pointer7, i13, 64);
                for (int i15 = i14 + 1; i15 < this.HFEnvq; i15++) {
                    LOOPIR_INIT(pointer6, pointer3, pointer5, pointer7, 0, 64);
                }
                int i16 = this.HFEnvr;
                if (i16 != 0) {
                    LOOPIR_INIT(pointer6, pointer3, pointer5, pointer7, 0, i16);
                }
                pointer5.changeIndex(pointer3);
                pointer9.move(this.NB_WORD_GF2nv);
                i12 = i13 + 1;
                pointer8 = pointer9;
                i11 = i14;
                i10 = 64;
            }
            i11++;
            i10 = 64;
        }
        Pointer pointer10 = pointer8;
        if (this.HFEnvr != 0) {
            for (int i17 = 0; i17 < this.HFEnvr; i17++) {
                pointer7.changeIndex(pointer10);
                pointer3.changeIndex(pointer5);
                LOOPIR_INIT(pointer6, pointer3, pointer5, pointer7, i17, this.HFEnvr);
                pointer5.changeIndex(pointer3);
                pointer10.move(this.NB_WORD_GF2nv);
            }
        }
        pointer5.changeIndex(pointer4);
        pointer6.changeIndex(pointer, this.NB_WORD_GFqn);
        pointer7.changeIndex(pointer2);
        for (int i18 = 0; i18 < this.HFEnvq; i18++) {
            int i19 = 0;
            while (i19 < 64) {
                pointer6.move(this.NB_WORD_GFqn);
                pointer5.move(this.HFEnv * this.NB_WORD_GFqn);
                pointer3.changeIndex(pointer5);
                int i20 = i19 + 1;
                LOOPIR_LOOPK_COMPLETE(pointer6, pointer7, pointer3, i20, 64);
                for (int i21 = i18 + 1; i21 < this.HFEnvq; i21++) {
                    LOOPIR_LOOPK_COMPLETE(pointer6, pointer7, pointer3, 0, 64);
                }
                int i22 = this.HFEnvr;
                if (i22 != 0) {
                    LOOPIR_LOOPK_COMPLETE(pointer6, pointer7, pointer3, 0, i22);
                }
                pointer7.move(this.NB_WORD_GF2nv);
                i19 = i20;
            }
        }
        if (this.HFEnvr != 0) {
            int i23 = 0;
            while (i23 < this.HFEnvr - 1) {
                pointer6.move(this.NB_WORD_GFqn);
                pointer5.move(this.HFEnv * this.NB_WORD_GFqn);
                pointer3.changeIndex(pointer5);
                i23++;
                LOOPIR_LOOPK_COMPLETE(pointer6, pointer7, pointer3, i23, this.HFEnvr);
                pointer7.move(this.NB_WORD_GF2nv);
            }
        }
        pointer.indexReset();
        pointer2.indexReset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void cleanLowerMatrix(Pointer pointer, FunctionParams functionParams) {
        int i;
        int i2;
        int i3 = C13931.f1266xb3d0f197[functionParams.ordinal()];
        int i4 = 1;
        if (i3 == 1) {
            i = this.HFEnq;
            i2 = this.HFEnr;
        } else if (i3 != 2) {
            throw new IllegalArgumentException("");
        } else {
            i = this.HFEnvq;
            i2 = this.HFEnvr;
        }
        Pointer pointer2 = new Pointer(pointer);
        while (i4 <= i) {
            for_and_xor_shift_incre_move(pointer2, i4, 64);
            pointer2.moveIncremental();
            i4++;
        }
        for_and_xor_shift_incre_move(pointer2, i4, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void cleanMonicHFEv_gf2nx(Pointer pointer) {
        int i = this.NB_WORD_GFqn - 1;
        while (i < this.NB_UINT_HFEVPOLY) {
            pointer.setAnd(i, this.MASK_GF2n);
            i += this.NB_WORD_GFqn;
        }
    }

    public void compress_signHFE(byte[] bArr, Pointer pointer) {
        int i;
        byte[] bytes = pointer.toBytes(pointer.getLength() << 3);
        System.arraycopy(bytes, 0, bArr, 0, this.NB_BYTES_GFqnv);
        int i2 = this.HFEnv;
        int i3 = (this.NB_WORD_GF2nv << 3) + (this.HFEmq8 & 7);
        for (int i4 = 1; i4 < this.NB_ITE; i4++) {
            int i5 = i2 & 7;
            int min = Math.min(this.HFEDELTA + this.HFEv, (8 - i5) & 7);
            if (i5 != 0) {
                int i6 = this.HFEmr8;
                if (i6 != 0) {
                    int i7 = i2 >>> 3;
                    bArr[i7] = (byte) ((((bytes[i3] & UByte.MAX_VALUE) >>> i6) << i5) ^ bArr[i7]);
                    int i8 = this.VAL_BITS_M;
                    int i9 = min - i8;
                    if (i9 >= 0) {
                        i3++;
                    }
                    if (i9 > 0) {
                        int i10 = i2 + i8;
                        int i11 = i10 >>> 3;
                        bArr[i11] = (byte) (bArr[i11] ^ ((bytes[i3] & UByte.MAX_VALUE) << (i10 & 7)));
                        i2 = i10 + i9;
                    }
                } else {
                    int i12 = i2 >>> 3;
                    bArr[i12] = (byte) (((bytes[i3] & UByte.MAX_VALUE) << i5) ^ bArr[i12]);
                }
                i2 += min;
            }
            int i13 = (this.HFEDELTA + this.HFEv) - min;
            int i14 = (this.HFEm + min) & 7;
            if (i14 != 0) {
                for (int i15 = 0; i15 < ((i13 - 1) >>> 3); i15++) {
                    i3++;
                    bArr[i2 >>> 3] = (byte) (((bytes[i3] & UByte.MAX_VALUE) >>> i14) ^ ((bytes[i3] & UByte.MAX_VALUE) << (8 - i14)));
                    i2 += 8;
                }
                int i16 = i2 >>> 3;
                i = i3 + 1;
                byte b = (byte) ((bytes[i3] & UByte.MAX_VALUE) >>> i14);
                bArr[i16] = b;
                int i17 = ((i13 + 7) & 7) + 1;
                int i18 = 8 - i14;
                if (i17 > i18) {
                    bArr[i16] = (byte) (((byte) ((bytes[i] & UByte.MAX_VALUE) << i18)) ^ b);
                    i = i3 + 2;
                }
                i2 += i17;
            } else {
                int i19 = 0;
                while (i19 < ((i13 + 7) >>> 3)) {
                    bArr[i2 >>> 3] = bytes[i3];
                    i2 += 8;
                    i19++;
                    i3++;
                }
                i2 -= (8 - (i13 & 7)) & 7;
                i = i3;
            }
            i3 = ((8 - (this.NB_BYTES_GFqnv & 7)) & 7) + (this.HFEmq8 & 7) + i;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void convMQS_one_eq_to_hybrid_rep8_comp_gf2(byte[] bArr, PointerUnion pointerUnion, byte[] bArr2) {
        convMQ_UL_gf2(bArr, bArr2, this.HFEmr8);
        int i = 0;
        for (int i2 = 0; i2 < this.NB_MONOMIAL_PK; i2++) {
            i = pointerUnion.toBytesMove(bArr, i, this.HFEmq8);
            if (this.HFEmr8 != 0) {
                pointerUnion.moveNextByte();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void convMQS_one_eq_to_hybrid_rep8_uncomp_gf2(byte[] bArr, PointerUnion pointerUnion, byte[] bArr2) {
        int i = this.HFEmr8 - 1;
        convMQ_UL_gf2(bArr, bArr2, i);
        int i2 = this.ACCESS_last_equations8;
        int i3 = this.NB_BYTES_EQUATION;
        int i4 = i2 + (i * i3);
        int i5 = i * i3;
        int for_setPK = for_setPK(bArr, bArr2, i4, i5, this.HFEnv);
        int i6 = this.HFEnv;
        setPK(bArr, bArr2, i6, i4, i5, for_setPK, i6 - 1, this.LOST_BITS);
        int i7 = this.buffer;
        long j = 0;
        for (int i8 = this.LOST_BITS - 1; i8 >= 0; i8--) {
            j ^= ((bArr2[(i7 >>> 3) + i5] >>> (i7 & 7)) & 1) << ((this.LOST_BITS - 1) - i8);
            i7 += i8;
        }
        int i9 = this.ACCESS_last_equations8 - 1;
        for (int i10 = 0; i10 < this.HFEmr8 - 1; i10++) {
            i9 += this.NB_BYTES_EQUATION;
            bArr[i9] = (byte) (bArr[i9] ^ (((byte) (j >>> (this.HFENr8c * i10))) << this.HFENr8));
        }
        pointerUnion.indexReset();
        int i11 = 0;
        for (int i12 = 0; i12 < this.NB_MONOMIAL_PK; i12++) {
            i11 = pointerUnion.toBytesMove(bArr, i11, this.HFEmq8);
            pointerUnion.moveNextByte();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void convMQS_one_to_last_mr8_equations_gf2(byte[] bArr, PointerUnion pointerUnion) {
        int i;
        pointerUnion.moveNextBytes(this.HFEmq8);
        PointerUnion pointerUnion2 = new PointerUnion(pointerUnion);
        int i2 = this.NB_MONOMIAL_PK >>> 3;
        int i3 = 0;
        for (int i4 = 0; i4 < this.HFEmr8; i4++) {
            pointerUnion2.changeIndex(pointerUnion);
            int i5 = 0;
            while (true) {
                if (i5 >= i2) {
                    break;
                }
                int i6 = (pointerUnion2.getByte() >>> i4) & 1;
                pointerUnion2.moveNextBytes(this.NB_BYTES_GFqm);
                for (int i7 = 1; i7 < 8; i7++) {
                    i6 ^= ((pointerUnion2.getByte() >>> i4) & 1) << i7;
                    pointerUnion2.moveNextBytes(this.NB_BYTES_GFqm);
                }
                bArr[i3] = (byte) i6;
                i5++;
                i3++;
            }
            if (this.HFENr8 != 0) {
                long withCheck = (pointerUnion2.getWithCheck() >>> i4) & 1;
                pointerUnion2.moveNextBytes(this.NB_BYTES_GFqm);
                for (i = 1; i < this.HFENr8; i++) {
                    withCheck ^= ((pointerUnion2.getWithCheck() >>> i4) & 1) << i;
                    pointerUnion2.moveNextBytes(this.NB_BYTES_GFqm);
                }
                bArr[i3] = (byte) withCheck;
                i3++;
            }
        }
    }

    void convMQ_UL_gf2(byte[] bArr, byte[] bArr2, int i) {
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = this.ACCESS_last_equations8;
            int i4 = this.NB_BYTES_EQUATION;
            for_setPK(bArr, bArr2, i3 + (i2 * i4), i2 * i4, this.HFEnv + 1);
        }
    }

    public int crypto_sign_open(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        long j;
        int i;
        long j2;
        PointerUnion pointerUnion = new PointerUnion(bArr);
        int i2 = 0;
        long j3 = 0;
        if (this.HFENr8 == 0 || this.HFEmr8 <= 1) {
            j = 0;
        } else {
            PointerUnion pointerUnion2 = new PointerUnion(pointerUnion);
            pointerUnion2.moveNextBytes(this.ACCESS_last_equations8 - 1);
            j = 0;
            for (int i3 = 0; i3 < this.HFEmr8 - 1; i3++) {
                pointerUnion2.moveNextBytes(this.NB_BYTES_EQUATION);
                j ^= ((pointerUnion2.getByte() & 255) >>> this.HFENr8) << (this.HFENr8c * i3);
            }
        }
        if (this.HFEmr8 == 0) {
            Pointer pointer = new Pointer(this.SIZE_SIGN_UNCOMPRESSED);
            Pointer pointer2 = new Pointer(new Pointer(this.NB_WORD_GF2nv));
            Pointer pointer3 = new Pointer(this.SIZE_DIGEST_UINT);
            pointer.fill(0, bArr3, 0, this.NB_BYTES_GFqnv);
            getSHA3Hash(pointer3, 0, 64, bArr2, 0, bArr2.length, new byte[64]);
            evalMQSnocst8_quo_gf2(pointer2, pointer, pointerUnion);
            return pointer2.isEqual_nocst_gf2(pointer3, this.NB_WORD_GF2m);
        }
        Pointer pointer4 = new Pointer((this.NB_WORD_UNCOMP_EQ * this.HFEmr8) + 1);
        PointerUnion pointerUnion3 = new PointerUnion(pointerUnion);
        while (i2 < this.HFEmr8 - 1) {
            pointerUnion3.setByteIndex(this.ACCESS_last_equations8 + (this.NB_BYTES_EQUATION * i2));
            j3 ^= convMQ_uncompressL_gf2(new Pointer(pointer4, (this.NB_WORD_UNCOMP_EQ * i2) + 1), pointerUnion3) << i2;
            i2++;
        }
        pointerUnion3.setByteIndex(this.ACCESS_last_equations8 + (this.NB_BYTES_EQUATION * i2));
        long convMQ_last_uncompressL_gf2 = j3 ^ (convMQ_last_uncompressL_gf2(new Pointer(pointer4, (this.NB_WORD_UNCOMP_EQ * i2) + 1), pointerUnion3) << i2);
        if (this.HFENr8 != 0) {
            int i4 = this.HFEnvr;
            if (i4 == 0) {
                i = (i2 + 1) * this.NB_WORD_UNCOMP_EQ;
                j2 = j << (64 - this.LOST_BITS);
            } else {
                int i5 = this.LOST_BITS;
                int i6 = i2 + 1;
                if (i4 > i5) {
                    i = i6 * this.NB_WORD_UNCOMP_EQ;
                    j2 = j << (i4 - i5);
                } else if (i4 == i5) {
                    pointer4.set(i6 * this.NB_WORD_UNCOMP_EQ, j);
                } else {
                    pointer4.setXor((this.NB_WORD_UNCOMP_EQ * i6) - 1, j << (64 - (i5 - i4)));
                    pointer4.set(i6 * this.NB_WORD_UNCOMP_EQ, j >>> (this.LOST_BITS - this.HFEnvr));
                }
            }
            pointer4.setXor(i, j2);
        }
        pointer4.set(convMQ_last_uncompressL_gf2 << (this.HFEmr - this.HFEmr8));
        return sign_openHFE_huncomp_pk(bArr2, bArr2.length, bArr3, pointerUnion, new PointerUnion(pointer4));
    }

    int div_r_gf2nx(Pointer pointer, int i, Pointer pointer2, int i2) {
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer5 = new Pointer(pointer);
        inv_gf2n(pointer4, pointer2, this.NB_WORD_GFqn * i2);
        while (i >= i2) {
            i = pointer.searchDegree(i, i2, this.NB_WORD_GFqn);
            if (i < i2) {
                break;
            }
            pointer5.changeIndex((i - i2) * this.NB_WORD_GFqn);
            mul_gf2n(pointer3, pointer, this.NB_WORD_GFqn * i, pointer4);
            for_mul_rem_xor_move(pointer5, pointer3, pointer2, 0, i2);
            i--;
        }
        return pointer.searchDegree(i, 1, this.NB_WORD_GFqn);
    }

    void evalHFEv_gf2nx(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        Pointer pointer4 = new Pointer(this.NB_WORD_MUL);
        Pointer pointer5 = new Pointer(this.NB_WORD_MUL);
        Pointer pointer6 = new Pointer((this.HFEDegI + 1) * this.NB_WORD_GFqn);
        Pointer pointer7 = new Pointer();
        int index = pointer2.getIndex();
        Pointer pointer8 = new Pointer(this.NB_WORD_GFqv);
        Pointer pointer9 = new Pointer(pointer6, this.NB_WORD_GFqn);
        pointer6.copyFrom(pointer3, this.NB_WORD_GFqn);
        pointer6.setAnd(this.NB_WORD_GFqn - 1, this.MASK_GF2n);
        for (int i = 1; i <= this.HFEDegI; i++) {
            sqr_gf2n(pointer9, 0, pointer9, -this.NB_WORD_GFqn);
            pointer9.move(this.NB_WORD_GFqn);
        }
        int i2 = this.NB_WORD_GFqn;
        int i3 = this.NB_WORD_GFqv;
        if (i2 + i3 != this.NB_WORD_GF2nv) {
            i3--;
        }
        int i4 = i3;
        pointer8.setRangeRotate(0, pointer3, i2 - 1, i4, 64 - this.HFEnr);
        int i5 = this.NB_WORD_GFqn;
        if (this.NB_WORD_GFqv + i5 != this.NB_WORD_GF2nv) {
            pointer8.set(i4, pointer3.get((i5 - 1) + i4) >>> this.HFEnr);
        }
        evalMQSv_unrolled_gf2(pointer4, pointer8, pointer2);
        pointer2.move(this.MQv_GFqn_SIZE);
        vmpv_xorrange_move(pointer5, pointer8, pointer2);
        pointer9.changeIndex(pointer6);
        mul_xorrange(pointer4, pointer9, pointer5);
        for (int i6 = 1; i6 < this.HFEDegI; i6++) {
            vmpv_xorrange_move(pointer5, pointer8, pointer2);
            int i7 = this.NB_WORD_GFqn;
            pointer5.setRangeClear(i7, this.NB_WORD_MMUL - i7);
            pointer7.changeIndex(pointer9);
            for_mul_xorrange_move(pointer5, pointer2, pointer7, i6);
            rem_gf2n(pointer5, 0, pointer5);
            mul_xorrange(pointer4, pointer7, pointer5);
        }
        vmpv_xorrange_move(pointer5, pointer8, pointer2);
        pointer7.changeIndex(pointer9);
        if (this.HFEDegJ != 0) {
            int i8 = this.NB_WORD_GFqn;
            pointer5.setRangeClear(i8, this.NB_WORD_MMUL - i8);
            for_mul_xorrange_move(pointer5, pointer2, pointer7, this.HFEDegJ);
            pointer5.setXorRange(pointer7, this.NB_WORD_GFqn);
            rem_gf2n(pointer5, 0, pointer5);
        } else {
            pointer5.setRangeFromXor(pointer5, pointer7, this.NB_WORD_GFqn);
        }
        pointer9.move(this.HFEDegI * this.NB_WORD_GFqn);
        mul_xorrange(pointer4, pointer9, pointer5);
        rem_gf2n(pointer, 0, pointer4);
        pointer2.changeIndex(index);
    }

    void evalMQSv_unrolled_gf2(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        Pointer pointer4 = new Pointer(this.HFEv);
        int i = this.HFEv;
        int i2 = i >>> 6;
        int i3 = i & 63;
        int i4 = this.HFEn;
        int i5 = 0;
        int i6 = (i4 >>> 6) + ((i4 & 63) != 0 ? 1 : 0);
        int index = pointer3.getIndex();
        Pointer pointer5 = new Pointer(i6);
        int i7 = 0;
        int i8 = 0;
        while (i7 < i2) {
            i8 = pointer4.setRange_xi(pointer2.get(i7), i8, 64);
            i7++;
        }
        if (i3 != 0) {
            pointer4.setRange_xi(pointer2.get(i7), i8, i3);
        }
        pointer.copyFrom(pointer3, i6);
        pointer3.move(i6);
        while (i5 < this.HFEv) {
            pointer5.copyFrom(pointer3, i6);
            pointer3.move(i6);
            int i9 = i5 + 1;
            int i10 = i9;
            while (i10 < this.HFEv - 3) {
                pointer5.setXorRangeAndMaskMove(pointer3, i6, pointer4.get(i10));
                pointer5.setXorRangeAndMaskMove(pointer3, i6, pointer4.get(i10 + 1));
                pointer5.setXorRangeAndMaskMove(pointer3, i6, pointer4.get(i10 + 2));
                pointer5.setXorRangeAndMaskMove(pointer3, i6, pointer4.get(i10 + 3));
                i10 += 4;
            }
            while (i10 < this.HFEv) {
                pointer5.setXorRangeAndMaskMove(pointer3, i6, pointer4.get(i10));
                i10++;
            }
            pointer.setXorRangeAndMask(pointer5, i6, pointer4.get(i5));
            i5 = i9;
        }
        pointer3.changeIndex(index);
    }

    void fast_sort_gf2n(Pointer pointer, int i) {
        int i2;
        int i3;
        int i4;
        int i5;
        Pointer pointer2 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer();
        Pointer pointer5 = new Pointer();
        int i6 = i - 1;
        int Highest_One = GeMSSUtils.Highest_One(i6);
        int i7 = Highest_One;
        while (true) {
            i2 = 0;
            if (i7 <= 1) {
                break;
            }
            int i8 = i7 << 1;
            int i9 = i / i8;
            int max = Math.max(0, (i - (i8 * i9)) - i7);
            pointer4.changeIndex(pointer);
            pointer5.changeIndex(pointer, this.NB_WORD_GFqn * i7);
            int i10 = 0;
            while (i10 < i9) {
                for_casct_move(pointer4, pointer5, pointer3, i7, 1);
                pointer4.move(this.NB_WORD_GFqn * i7);
                pointer5.move(this.NB_WORD_GFqn * i7);
                i10++;
                i9 = i9;
            }
            for_casct_move(pointer4, pointer5, pointer3, max, 1);
            int i11 = Highest_One;
            while (i11 > i7) {
                while (i2 < i - i11) {
                    if ((i2 & i7) == 0) {
                        pointer5.changeIndex(pointer, (i2 + i7) * this.NB_WORD_GFqn);
                        i3 = i11;
                        i4 = i2;
                        i5 = i7;
                        copy_for_casct(pointer2, pointer5, pointer, pointer4, pointer3, i3, i4);
                        pointer5.copyFrom(pointer2, this.NB_WORD_GFqn);
                    } else {
                        i3 = i11;
                        i4 = i2;
                        i5 = i7;
                    }
                    i2 = i4 + 1;
                    i11 = i3;
                    i7 = i5;
                }
                i11 >>>= 1;
            }
            i7 >>>= 1;
        }
        pointer4.changeIndex(pointer);
        pointer5.changeIndex(pointer, this.NB_WORD_GFqn);
        for_casct_move(pointer4, pointer5, pointer3, i6, 2);
        pointer5.changeIndex(pointer, this.NB_WORD_GFqn);
        while (Highest_One > 1) {
            int i12 = i2;
            while (i12 < i - Highest_One) {
                copy_for_casct(pointer2, pointer5, pointer, pointer4, pointer3, Highest_One, i12);
                pointer5.copyFrom(pointer2, this.NB_WORD_GFqn);
                pointer5.move(this.NB_WORD_GFqn << 1);
                i12 += 2;
            }
            Highest_One >>>= 1;
            i2 = i12;
        }
    }

    void findRootsSplit2_HT_gf2nx(Pointer pointer, Pointer pointer2) {
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer(this.NB_WORD_GFqn);
        int index = pointer2.getIndex();
        sqr_gf2n(pointer3, 0, pointer2, this.NB_WORD_GFqn);
        inv_gf2n(pointer, pointer3, 0);
        mul_gf2n(pointer3, pointer2, pointer);
        findRootsSplit_x2_x_c_HT_gf2nx(pointer4, pointer3);
        pointer2.move(this.NB_WORD_GFqn);
        mul_gf2n(pointer, pointer4, pointer2);
        int i = this.NB_WORD_GFqn;
        pointer.setRangeFromXor(i, pointer, 0, pointer2, 0, i);
        pointer2.changeIndex(index);
    }

    void findRootsSplit_x2_x_c_HT_gf2nx(Pointer pointer, Pointer pointer2) {
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        int i = (this.HFEn + 1) >>> 1;
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        int i2 = 1;
        for (int i3 = this.HFEn1h_rightmost; i3 != -1; i3--) {
            int i4 = i2 << 1;
            sqr_gf2n(pointer3, pointer);
            for (int i5 = 1; i5 < i4; i5++) {
                sqr_gf2n(pointer3, pointer3);
            }
            pointer.setXorRange(pointer3, this.NB_WORD_GFqn);
            i2 = i >>> i3;
            if ((i2 & 1) != 0) {
                sqr_gf2n(pointer3, pointer);
                sqr_gf2n(pointer, pointer3);
                pointer.setXorRange(pointer2, this.NB_WORD_GFqn);
            }
        }
    }

    void for_mul_xorrange_move(Pointer pointer, Pointer pointer2, Pointer pointer3, int i) {
        for (int i2 = 0; i2 < i; i2++) {
            this.mul.mul_gf2x_xor(pointer, pointer2, pointer3);
            pointer2.move(this.NB_WORD_GFqn);
            pointer3.move(this.NB_WORD_GFqn);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void genSecretMQS_gf2_opt(Pointer pointer, Pointer pointer2) {
        Pointer pointer3 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer4 = new Pointer((this.HFEDegI + 1) * (this.HFEv + 1) * this.NB_WORD_GFqn);
        Pointer pointer5 = new Pointer(pointer2, this.MQv_GFqn_SIZE);
        for (int i = 0; i <= this.HFEDegI; i++) {
            for (int i2 = 0; i2 <= this.HFEv; i2++) {
                int i3 = this.NB_WORD_GFqn;
                pointer4.copyFrom((((this.HFEDegI + 1) * i2) + i) * i3, pointer5, 0, i3);
                pointer5.move(this.NB_WORD_GFqn);
            }
            pointer5.move(this.NB_WORD_GFqn * i);
        }
        Pointer pointer6 = new Pointer(this.SIZE_ROW * (this.HFEn - 1) * this.NB_WORD_GFqn);
        for (int i4 = 1; i4 < this.HFEn; i4++) {
            pointer6.set(i4 >>> 6, 1 << (i4 & 63));
            for (int i5 = 0; i5 < this.HFEDegI; i5++) {
                sqr_gf2n(pointer6, this.NB_WORD_GFqn, pointer6, 0);
                pointer6.move(this.NB_WORD_GFqn);
            }
            pointer6.move(this.NB_WORD_GFqn);
        }
        pointer6.indexReset();
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        pointer2.move(this.MQv_GFqn_SIZE);
        pointer.move(this.NB_WORD_GFqn);
        Pointer pointer7 = new Pointer(this.HFEDegI * this.HFEn * this.NB_WORD_GFqn);
        special_buffer(pointer7, pointer2, pointer6);
        Pointer pointer8 = new Pointer(pointer7);
        Pointer pointer9 = new Pointer(pointer7);
        pointer.copyFrom(pointer9, this.NB_WORD_GFqn);
        pointer9.move(this.NB_WORD_GFqn);
        pointer.setXorMatrix_NoMove(pointer9, this.NB_WORD_GFqn, this.HFEDegI - 1);
        pointer5.changeIndex(pointer4);
        pointer.setXorMatrix(pointer5, this.NB_WORD_GFqn, this.HFEDegI + 1);
        Pointer pointer10 = new Pointer(pointer6, this.NB_WORD_GFqn);
        int i6 = 1;
        while (i6 < this.HFEn) {
            dotProduct_gf2n(pointer, pointer10, pointer8, this.HFEDegI);
            pointer10.move(this.SIZE_ROW * this.NB_WORD_GFqn);
            pointer.setXorMatrix(pointer9, this.NB_WORD_GFqn, this.HFEDegI);
            i6++;
        }
        while (i6 < this.HFEnv) {
            pointer.copyFrom(pointer5, this.NB_WORD_GFqn);
            pointer5.move(this.NB_WORD_GFqn);
            pointer.setXorMatrix(pointer5, this.NB_WORD_GFqn, this.HFEDegI);
            i6++;
        }
        Pointer pointer11 = new Pointer(pointer6, this.NB_WORD_GFqn);
        Pointer pointer12 = new Pointer(this.NB_WORD_MUL);
        int i7 = 1;
        while (i7 < this.HFEn) {
            pointer8.move(this.HFEDegI * this.NB_WORD_GFqn);
            pointer10.changeIndex(pointer11);
            pointer9.changeIndex(pointer8);
            this.mul.mul_gf2x(this.Buffer_NB_WORD_MUL, pointer4, new Pointer(pointer10, -this.NB_WORD_GFqn));
            int i8 = 1;
            while (i8 <= this.HFEDegI) {
                int i9 = this.NB_WORD_GFqn;
                Pointer pointer13 = pointer10;
                Pointer pointer14 = pointer9;
                pointer3.setRangeFromXor(0, pointer9, 0, pointer4, i8 * i9, i9);
                mul_xorrange(this.Buffer_NB_WORD_MUL, pointer3, pointer13);
                pointer14.move(this.NB_WORD_GFqn);
                pointer13.move(this.NB_WORD_GFqn);
                i8++;
                pointer9 = pointer14;
                pointer10 = pointer13;
                pointer11 = pointer11;
                i7 = i7;
                pointer12 = pointer12;
            }
            Pointer pointer15 = pointer12;
            Pointer pointer16 = pointer11;
            Pointer pointer17 = pointer10;
            Pointer pointer18 = pointer9;
            pointer17.move(this.NB_WORD_GFqn);
            rem_gf2n(pointer, 0, this.Buffer_NB_WORD_MUL);
            pointer.move(this.NB_WORD_GFqn);
            int i10 = i7 + 1;
            int i11 = i10;
            while (i11 < this.HFEn) {
                int index = pointer17.getIndex();
                int index2 = pointer8.getIndex();
                int index3 = pointer16.getIndex();
                int index4 = pointer18.getIndex();
                mul_move(pointer15, pointer17, pointer8);
                for_mul_xorrange_move(pointer15, pointer17, pointer8, this.HFEDegI - 1);
                int i12 = i10;
                Pointer pointer19 = pointer16;
                for_mul_xorrange_move(pointer15, pointer19, pointer18, this.HFEDegI);
                rem_gf2n(pointer, 0, pointer15);
                pointer17.changeIndex(index + (this.SIZE_ROW * this.NB_WORD_GFqn));
                pointer8.changeIndex(index2);
                pointer19.changeIndex(index3);
                pointer18.changeIndex(index4 + (this.HFEDegI * this.NB_WORD_GFqn));
                pointer.move(this.NB_WORD_GFqn);
                i11++;
                pointer3 = pointer3;
                pointer16 = pointer19;
                i10 = i12;
            }
            int i13 = i10;
            Pointer pointer20 = pointer16;
            Pointer pointer21 = pointer3;
            pointer5.changeIndex(pointer4);
            pointer20.move(-this.NB_WORD_GFqn);
            while (i11 < this.HFEnv) {
                pointer5.move((this.HFEDegI + 1) * this.NB_WORD_GFqn);
                dotProduct_gf2n(pointer, pointer20, pointer5, this.HFEDegI + 1);
                pointer.move(this.NB_WORD_GFqn);
                i11++;
            }
            int i14 = this.NB_WORD_GFqn;
            pointer20.move(i14 + (this.SIZE_ROW * i14));
            pointer9 = pointer18;
            pointer10 = pointer17;
            pointer11 = pointer20;
            pointer12 = pointer15;
            i7 = i13;
            pointer3 = pointer21;
        }
        pointer2.move(this.NB_WORD_GFqn - this.MQv_GFqn_SIZE);
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn * (this.NB_MONOMIAL_VINEGAR - 1));
        pointer.indexReset();
        pointer2.indexReset();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int interpolateHFE_FS_ref(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        Pointer pointer4 = new Pointer(this.NB_WORD_GF2nv);
        Pointer pointer5 = new Pointer();
        Pointer pointer6 = new Pointer();
        Pointer pointer7 = new Pointer(this.HFEnv * this.NB_WORD_GFqn);
        pointer.copyFrom(pointer2, this.NB_WORD_GFqn);
        Pointer pointer8 = new Pointer(pointer3);
        Pointer pointer9 = new Pointer(pointer7);
        for (int i = 0; i < this.HFEnv; i++) {
            evalHFEv_gf2nx(pointer9, pointer2, pointer8);
            pointer9.move(this.NB_WORD_GFqn);
            pointer8.move(this.NB_WORD_GF2nv);
        }
        pointer8.changeIndex(pointer3);
        pointer9.changeIndex(pointer7);
        int i2 = 0;
        while (i2 < this.HFEnv) {
            pointer.move(this.NB_WORD_GFqn);
            pointer9.setXorRange(pointer2, this.NB_WORD_GFqn);
            pointer.copyFrom(pointer9, this.NB_WORD_GFqn);
            pointer5.changeIndex(pointer9);
            pointer6.changeIndex(pointer8);
            int i3 = i2 + 1;
            for (int i4 = i3; i4 < this.HFEnv; i4++) {
                pointer.move(this.NB_WORD_GFqn);
                pointer5.move(this.NB_WORD_GFqn);
                pointer6.move(this.NB_WORD_GF2nv);
                pointer4.setRangeFromXor(pointer8, pointer6, this.NB_WORD_GF2nv);
                evalHFEv_gf2nx(pointer, pointer2, pointer4);
                pointer.setXorRangeXor(0, pointer9, 0, pointer5, 0, this.NB_WORD_GFqn);
            }
            pointer9.move(this.NB_WORD_GFqn);
            pointer8.move(this.NB_WORD_GF2nv);
            i2 = i3;
        }
        pointer.indexReset();
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:22:0x00de  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void invMatrixLU_gf2(org.bouncycastle.pqc.crypto.gemss.Pointer r21, org.bouncycastle.pqc.crypto.gemss.Pointer r22, org.bouncycastle.pqc.crypto.gemss.Pointer r23, org.bouncycastle.pqc.crypto.gemss.GeMSSEngine.FunctionParams r24) {
        /*
            Method dump skipped, instructions count: 269
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.gemss.GeMSSEngine.invMatrixLU_gf2(org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.GeMSSEngine$FunctionParams):void");
    }

    void mul_gf2n(Pointer pointer, Pointer pointer2, int i, Pointer pointer3) {
        int index = pointer2.getIndex();
        pointer2.move(i);
        this.mul.mul_gf2x(this.Buffer_NB_WORD_MUL, pointer2, pointer3);
        pointer2.changeIndex(index);
        rem_gf2n(pointer, 0, this.Buffer_NB_WORD_MUL);
    }

    void mul_gf2n(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        this.mul.mul_gf2x(this.Buffer_NB_WORD_MUL, pointer2, pointer3);
        rem_gf2n(pointer, 0, this.Buffer_NB_WORD_MUL);
    }

    void mul_move(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        this.mul.mul_gf2x(pointer, pointer2, pointer3);
        pointer2.move(this.NB_WORD_GFqn);
        pointer3.move(this.NB_WORD_GFqn);
    }

    public void mul_rem_xorrange(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        this.mul.mul_gf2x(this.Buffer_NB_WORD_MUL, pointer2, pointer3);
        this.rem.rem_gf2n_xor(pointer.array, pointer.f1275cp, this.Buffer_NB_WORD_MUL.array);
    }

    public void mul_rem_xorrange(Pointer pointer, Pointer pointer2, Pointer pointer3, int i) {
        int index = pointer3.getIndex();
        pointer3.move(i);
        this.mul.mul_gf2x(this.Buffer_NB_WORD_MUL, pointer2, pointer3);
        this.rem.rem_gf2n_xor(pointer.array, pointer.f1275cp, this.Buffer_NB_WORD_MUL.array);
        pointer3.changeIndex(index);
    }

    public void mul_xorrange(Pointer pointer, Pointer pointer2, Pointer pointer3) {
        this.mul.mul_gf2x_xor(pointer, pointer2, pointer3);
    }

    public void signHFE_FeistelPatarin(SecureRandom secureRandom, byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3) {
        int i3;
        Pointer pointer;
        int i4;
        int i5;
        SecretKeyHFE secretKeyHFE;
        Pointer pointer2;
        long j;
        PointerUnion pointerUnion;
        PointerUnion pointerUnion2;
        Pointer pointer3;
        Pointer pointer4;
        SecretKeyHFE secretKeyHFE2;
        Pointer pointer5;
        long j2;
        Pointer pointer6;
        this.random = secureRandom;
        Pointer pointer7 = new Pointer(this.NB_WORD_GFqn);
        Pointer pointer8 = new Pointer(this.SIZE_DIGEST_UINT);
        Pointer pointer9 = new Pointer(new Pointer(this.SIZE_DIGEST_UINT));
        int i6 = this.HFEv;
        int i7 = i6 & 7;
        int i8 = (i6 >>> 3) + (i7 != 0 ? 1 : 0);
        long maskUINT = GeMSSUtils.maskUINT(this.HFEvr);
        SecretKeyHFE secretKeyHFE3 = new SecretKeyHFE(this);
        Pointer pointer10 = new Pointer(this.NB_WORD_GFqv);
        Pointer[] pointerArr = new Pointer[this.HFEDegI + 1];
        precSignHFE(secretKeyHFE3, pointerArr, bArr3);
        Pointer pointer11 = new Pointer(secretKeyHFE3.F_struct.poly);
        Pointer pointer12 = new Pointer(pointer8);
        int i9 = this.Sha3BitStrength >>> 3;
        Pointer pointer13 = pointer10;
        SecretKeyHFE secretKeyHFE4 = secretKeyHFE3;
        long j3 = maskUINT;
        Pointer pointer14 = pointer9;
        getSHA3Hash(pointer12, 0, i9, bArr2, i, i2, new byte[i9]);
        Pointer pointer15 = new Pointer(this.SIZE_SIGN_UNCOMPRESSED);
        Pointer pointer16 = new Pointer(this.NB_WORD_GF2nv);
        PointerUnion pointerUnion3 = new PointerUnion(pointer16);
        long j4 = 0;
        int i10 = 1;
        while (true) {
            i3 = this.NB_ITE;
            if (i10 > i3) {
                break;
            }
            pointer16.setRangeFromXor(pointer15, pointer12, this.NB_WORD_GF2m);
            if (this.HFEmr8 != 0) {
                pointer16.setAnd(this.NB_WORD_GF2m - 1, this.MASK_GF2m);
                j4 = pointerUnion3.getByte(this.HFEmq8);
            }
            long j5 = j4;
            while (true) {
                if (this.HFEmr8 != 0) {
                    pointerUnion3.fillRandomBytes(this.HFEmq8, secureRandom, (this.NB_BYTES_GFqn - this.NB_BYTES_GFqm) + 1);
                    pointer = pointer12;
                    i4 = i10;
                    pointerUnion3.setAndThenXorByte(this.HFEmq8, -(1 << this.HFEmr8), j5);
                } else {
                    pointer = pointer12;
                    i4 = i10;
                    int i11 = this.NB_BYTES_GFqm;
                    pointerUnion3.fillRandomBytes(i11, secureRandom, this.NB_BYTES_GFqn - i11);
                }
                if ((this.HFEn & 7) != 0) {
                    i5 = 1;
                    pointer16.setAnd(this.NB_WORD_GFqn - 1, this.MASK_GF2n);
                } else {
                    i5 = 1;
                }
                secretKeyHFE = secretKeyHFE4;
                vecMatProduct(pointer7, pointer16, secretKeyHFE.f1289T, FunctionParams.N);
                pointer2 = pointer13;
                pointer2.fillRandom(0, secureRandom, i8);
                if (i7 != 0) {
                    j = j3;
                    pointer2.setAnd(this.NB_WORD_GFqv - i5, j);
                } else {
                    j = j3;
                }
                evalMQSv_unrolled_gf2(pointer11, pointer2, secretKeyHFE.F_HFEv);
                int i12 = 0;
                while (i12 <= this.HFEDegI) {
                    PointerUnion pointerUnion4 = pointerUnion3;
                    vecMatProduct(this.Buffer_NB_WORD_GFqn, pointer2, new Pointer(pointerArr[i12], this.NB_WORD_GFqn), FunctionParams.V);
                    int i13 = this.NB_WORD_GFqn;
                    int i14 = i12 + 1;
                    pointer11.setRangeFromXor(i13 * (((i12 * i14) >>> 1) + 1), pointerArr[i12], 0, this.Buffer_NB_WORD_GFqn, 0, i13);
                    pointerUnion3 = pointerUnion4;
                    i12 = i14;
                    j = j;
                }
                pointerUnion = pointerUnion3;
                j3 = j;
                if (chooseRootHFE_gf2nx(pointer16, secretKeyHFE.F_struct, pointer7) != 0) {
                    break;
                }
                pointerUnion3 = pointerUnion;
                pointer13 = pointer2;
                secretKeyHFE4 = secretKeyHFE;
                i10 = i4;
                pointer12 = pointer;
            }
            pointer16.setXor(this.NB_WORD_GFqn - 1, pointer2.get() << this.HFEnr);
            pointer16.setRangeRotate(this.NB_WORD_GFqn, pointer2, 0, this.NB_WORD_GFqv - 1, 64 - this.HFEnr);
            int i15 = this.NB_WORD_GFqn;
            int i16 = this.NB_WORD_GFqv;
            if (i15 + i16 == this.NB_WORD_GF2nv) {
                pointer16.set((i15 + i16) - 1, pointer2.get(i16 - 1) >>> (64 - this.HFEnr));
            }
            vecMatProduct(pointer15, pointer16, secretKeyHFE.f1288S, FunctionParams.NV);
            int i17 = this.NB_ITE;
            if (i4 != i17) {
                int i18 = this.NB_WORD_GF2nv;
                int i19 = this.NB_WORD_GF2nvm;
                int i20 = (((i17 - 1) - i4) * i19) + i18;
                pointer15.copyFrom(i20, pointer15, i18 - i19, i19);
                if (this.HFEmr != 0) {
                    pointer15.setAnd(i20, ~this.MASK_GF2m);
                }
                Pointer pointer17 = pointer;
                byte[] bytes = pointer17.toBytes(this.SIZE_DIGEST);
                pointerUnion2 = pointerUnion;
                j2 = j3;
                pointer4 = pointer2;
                secretKeyHFE2 = secretKeyHFE;
                pointer5 = pointer16;
                getSHA3Hash(pointer14, 0, this.SIZE_DIGEST, bytes, 0, bytes.length, bytes);
                pointer6 = pointer14;
                pointer3 = pointer17;
                pointer6.swap(pointer3);
            } else {
                pointerUnion2 = pointerUnion;
                pointer3 = pointer;
                pointer4 = pointer2;
                secretKeyHFE2 = secretKeyHFE;
                pointer5 = pointer16;
                j2 = j3;
                pointer6 = pointer14;
            }
            i10 = i4 + 1;
            pointer14 = pointer6;
            pointer12 = pointer3;
            secretKeyHFE4 = secretKeyHFE2;
            pointerUnion3 = pointerUnion2;
            pointer16 = pointer5;
            pointer13 = pointer4;
            j3 = j2;
            j4 = j5;
        }
        if (i3 == 1) {
            System.arraycopy(pointer15.toBytes(pointer15.getLength() << 3), 0, bArr, 0, this.NB_BYTES_GFqnv);
        } else {
            compress_signHFE(bArr, pointer15);
        }
    }

    public int sign_openHFE_huncomp_pk(byte[] bArr, int i, byte[] bArr2, PointerUnion pointerUnion, PointerUnion pointerUnion2) {
        Pointer pointer = new Pointer(this.SIZE_SIGN_UNCOMPRESSED);
        Pointer pointer2 = new Pointer(this.NB_WORD_GF2nv);
        Pointer pointer3 = new Pointer(this.NB_WORD_GF2nv);
        Pointer pointer4 = new Pointer(pointer2);
        Pointer pointer5 = new Pointer(pointer3);
        byte[] bArr3 = new byte[64];
        Pointer pointer6 = new Pointer(this.NB_ITE * this.SIZE_DIGEST_UINT);
        long j = pointerUnion2.get();
        pointerUnion2.move(1);
        uncompress_signHFE(pointer, bArr2);
        getSHA3Hash(pointer6, 0, 64, bArr, 0, i, bArr3);
        int i2 = 1;
        while (i2 < this.NB_ITE) {
            int i3 = i2;
            getSHA3Hash(pointer6, i2 * this.SIZE_DIGEST_UINT, 64, bArr3, 0, this.SIZE_DIGEST, bArr3);
            pointer6.setAnd(((this.SIZE_DIGEST_UINT * (i3 - 1)) + this.NB_WORD_GF2m) - 1, this.MASK_GF2m);
            i2 = i3 + 1;
        }
        pointer6.setAnd(((this.SIZE_DIGEST_UINT * (i2 - 1)) + this.NB_WORD_GF2m) - 1, this.MASK_GF2m);
        evalMQShybrid8_uncomp_nocst_gf2_m(pointer4, pointer, pointerUnion, pointerUnion2);
        pointer4.setXor(this.HFEmq, j);
        for (int i4 = this.NB_ITE - 1; i4 > 0; i4--) {
            pointer4.setXorRange(pointer6, this.SIZE_DIGEST_UINT * i4, this.NB_WORD_GF2m);
            int i5 = this.NB_WORD_GF2nv + (((this.NB_ITE - 1) - i4) * this.NB_WORD_GF2nvm);
            pointer4.setAnd(this.NB_WORD_GF2m - 1, this.MASK_GF2m);
            pointer4.setXor(this.NB_WORD_GF2m - 1, pointer.get(i5));
            int i6 = this.NB_WORD_GF2nvm;
            if (i6 != 1) {
                pointer4.copyFrom(this.NB_WORD_GF2m, pointer, i5 + 1, i6 - 1);
            }
            evalMQShybrid8_uncomp_nocst_gf2_m(pointer5, pointer4, pointerUnion, pointerUnion2);
            pointer5.setXor(this.HFEmq, j);
            pointer5.swap(pointer4);
        }
        return pointer4.isEqual_nocst_gf2(pointer6, this.NB_WORD_GF2m);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:16:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00ba A[LOOP:2: B:42:0x00b8->B:43:0x00ba, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:54:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public void vecMatProduct(org.bouncycastle.pqc.crypto.gemss.Pointer r19, org.bouncycastle.pqc.crypto.gemss.Pointer r20, org.bouncycastle.pqc.crypto.gemss.Pointer r21, org.bouncycastle.pqc.crypto.gemss.GeMSSEngine.FunctionParams r22) {
        /*
            Method dump skipped, instructions count: 218
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.gemss.GeMSSEngine.vecMatProduct(org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.Pointer, org.bouncycastle.pqc.crypto.gemss.GeMSSEngine$FunctionParams):void");
    }
}