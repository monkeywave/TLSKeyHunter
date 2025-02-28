package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.asn1.cmc.BodyPartID;

/* loaded from: classes2.dex */
abstract class Mul_GF2x {

    /* loaded from: classes2.dex */
    public static class Mul12 extends Mul_GF2x {
        private long[] Buffer = new long[12];

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul384_no_simd_gf2x(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul384_no_simd_gf2x_xor(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void sqr_gf2x(long[] jArr, long[] jArr2, int i) {
            Mul_GF2x.SQR128_NO_SIMD_GF2X(jArr, 8, jArr2, i + 4);
            Mul_GF2x.SQR256_NO_SIMD_GF2X(jArr, 0, jArr2, i);
        }
    }

    /* loaded from: classes2.dex */
    public static class Mul13 extends Mul_GF2x {
        private long[] Buffer = new long[13];
        private long[] Buffer2 = new long[4];

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul416_no_simd_gf2x(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul416_no_simd_gf2x_xor(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer, this.Buffer2);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void sqr_gf2x(long[] jArr, long[] jArr2, int i) {
            jArr[12] = Mul_GF2x.SQR32_NO_SIMD_GF2X(jArr2[i + 6]);
            Mul_GF2x.SQR128_NO_SIMD_GF2X(jArr, 8, jArr2, i + 4);
            Mul_GF2x.SQR256_NO_SIMD_GF2X(jArr, 0, jArr2, i);
        }
    }

    /* loaded from: classes2.dex */
    public static class Mul17 extends Mul_GF2x {

        /* renamed from: AA */
        private long[] f1273AA = new long[5];

        /* renamed from: BB */
        private long[] f1274BB = new long[5];
        private long[] Buffer1 = new long[17];
        private long[] Buffer2 = new long[4];

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul544_no_simd_gf2x(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.f1273AA, this.f1274BB, this.Buffer1);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul544_no_simd_gf2x_xor(pointer.array, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.f1273AA, this.f1274BB, this.Buffer1, this.Buffer2);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void sqr_gf2x(long[] jArr, long[] jArr2, int i) {
            jArr[16] = Mul_GF2x.SQR32_NO_SIMD_GF2X(jArr2[i + 8]);
            Mul_GF2x.SQR256_NO_SIMD_GF2X(jArr, 8, jArr2, i + 4);
            Mul_GF2x.SQR256_NO_SIMD_GF2X(jArr, 0, jArr2, i);
        }
    }

    /* loaded from: classes2.dex */
    public static class Mul6 extends Mul_GF2x {
        private long[] Buffer = new long[6];

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            mul192_no_simd_gf2x(pointer.array, 0, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            mul192_no_simd_gf2x_xor(pointer.array, pointer.f1275cp, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void sqr_gf2x(long[] jArr, long[] jArr2, int i) {
            Mul_GF2x.SQR64_NO_SIMD_GF2X(jArr, 4, jArr2[i + 2]);
            Mul_GF2x.SQR128_NO_SIMD_GF2X(jArr, 0, jArr2, i);
        }
    }

    /* loaded from: classes2.dex */
    public static class Mul9 extends Mul_GF2x {
        private long[] Buffer = new long[9];

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul288_no_simd_gf2x(pointer.array, 0, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3) {
            Mul_GF2x.mul288_no_simd_gf2x_xor(pointer.array, pointer.f1275cp, pointer2.array, pointer2.f1275cp, pointer3.array, pointer3.f1275cp, this.Buffer);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Mul_GF2x
        public void sqr_gf2x(long[] jArr, long[] jArr2, int i) {
            jArr[8] = Mul_GF2x.SQR32_NO_SIMD_GF2X(jArr2[i + 4]);
            Mul_GF2x.SQR256_NO_SIMD_GF2X(jArr, 0, jArr2, i);
        }
    }

    Mul_GF2x() {
    }

    private static long MUL32_NO_SIMD_GF2X(long j, long j2) {
        return ((j & (-((j2 >>> 31) & 1))) << 31) ^ ((((((((((((((((((((((((((((((((-(j2 & 1)) & j) ^ (((-((j2 >>> 1) & 1)) & j) << 1)) ^ (((-((j2 >>> 2) & 1)) & j) << 2)) ^ (((-((j2 >>> 3) & 1)) & j) << 3)) ^ (((-((j2 >>> 4) & 1)) & j) << 4)) ^ (((-((j2 >>> 5) & 1)) & j) << 5)) ^ (((-((j2 >>> 6) & 1)) & j) << 6)) ^ (((-((j2 >>> 7) & 1)) & j) << 7)) ^ (((-((j2 >>> 8) & 1)) & j) << 8)) ^ (((-((j2 >>> 9) & 1)) & j) << 9)) ^ (((-((j2 >>> 10) & 1)) & j) << 10)) ^ (((-((j2 >>> 11) & 1)) & j) << 11)) ^ (((-((j2 >>> 12) & 1)) & j) << 12)) ^ (((-((j2 >>> 13) & 1)) & j) << 13)) ^ (((-((j2 >>> 14) & 1)) & j) << 14)) ^ (((-((j2 >>> 15) & 1)) & j) << 15)) ^ (((-((j2 >>> 16) & 1)) & j) << 16)) ^ (((-((j2 >>> 17) & 1)) & j) << 17)) ^ (((-((j2 >>> 18) & 1)) & j) << 18)) ^ (((-((j2 >>> 19) & 1)) & j) << 19)) ^ (((-((j2 >>> 20) & 1)) & j) << 20)) ^ (((-((j2 >>> 21) & 1)) & j) << 21)) ^ (((-((j2 >>> 22) & 1)) & j) << 22)) ^ (((-((j2 >>> 23) & 1)) & j) << 23)) ^ (((-((j2 >>> 24) & 1)) & j) << 24)) ^ (((-((j2 >>> 25) & 1)) & j) << 25)) ^ (((-((j2 >>> 26) & 1)) & j) << 26)) ^ (((-((j2 >>> 27) & 1)) & j) << 27)) ^ (((-((j2 >>> 28) & 1)) & j) << 28)) ^ (((-((j2 >>> 29) & 1)) & j) << 29)) ^ (((-((j2 >>> 30) & 1)) & j) << 30));
    }

    private static void MUL64_NO_SIMD_GF2X(long[] jArr, int i, long j, long j2) {
        long j3 = (-(j2 >>> 63)) & j;
        long j4 = (-((j2 >>> 1) & 1)) & j;
        long j5 = (j3 >>> 1) ^ (j4 >>> 63);
        long j6 = (-((j2 >>> 2) & 1)) & j;
        long j7 = (-((j2 >>> 3) & 1)) & j;
        long j8 = (-((j2 >>> 4) & 1)) & j;
        long j9 = (-((j2 >>> 5) & 1)) & j;
        long j10 = (-((j2 >>> 6) & 1)) & j;
        long j11 = (-((j2 >>> 7) & 1)) & j;
        long j12 = (-((j2 >>> 8) & 1)) & j;
        long j13 = (-((j2 >>> 9) & 1)) & j;
        long j14 = (-((j2 >>> 10) & 1)) & j;
        long j15 = (-((j2 >>> 11) & 1)) & j;
        long j16 = (((((((((j5 ^ (j6 >>> 62)) ^ (j7 >>> 61)) ^ (j8 >>> 60)) ^ (j9 >>> 59)) ^ (j10 >>> 58)) ^ (j11 >>> 57)) ^ (j12 >>> 56)) ^ (j13 >>> 55)) ^ (j14 >>> 54)) ^ (j15 >>> 53);
        long j17 = (-((j2 >>> 12) & 1)) & j;
        long j18 = j16 ^ (j17 >>> 52);
        long j19 = (-((j2 >>> 13) & 1)) & j;
        long j20 = j18 ^ (j19 >>> 51);
        long j21 = (-((j2 >>> 14) & 1)) & j;
        long j22 = j20 ^ (j21 >>> 50);
        long j23 = (-((j2 >>> 15) & 1)) & j;
        long j24 = j22 ^ (j23 >>> 49);
        long j25 = (-((j2 >>> 16) & 1)) & j;
        long j26 = j24 ^ (j25 >>> 48);
        long j27 = (-((j2 >>> 17) & 1)) & j;
        long j28 = j26 ^ (j27 >>> 47);
        long j29 = (-((j2 >>> 18) & 1)) & j;
        long j30 = j28 ^ (j29 >>> 46);
        long j31 = (-((j2 >>> 19) & 1)) & j;
        long j32 = j30 ^ (j31 >>> 45);
        long j33 = (-((j2 >>> 20) & 1)) & j;
        long j34 = j32 ^ (j33 >>> 44);
        long j35 = (-((j2 >>> 21) & 1)) & j;
        long j36 = j34 ^ (j35 >>> 43);
        long j37 = (-((j2 >>> 22) & 1)) & j;
        long j38 = j36 ^ (j37 >>> 42);
        long j39 = (-((j2 >>> 23) & 1)) & j;
        long j40 = j38 ^ (j39 >>> 41);
        long j41 = (-((j2 >>> 24) & 1)) & j;
        long j42 = j40 ^ (j41 >>> 40);
        long j43 = (-((j2 >>> 25) & 1)) & j;
        long j44 = j42 ^ (j43 >>> 39);
        long j45 = (-((j2 >>> 26) & 1)) & j;
        long j46 = j44 ^ (j45 >>> 38);
        long j47 = (-((j2 >>> 27) & 1)) & j;
        long j48 = j46 ^ (j47 >>> 37);
        long j49 = (-((j2 >>> 28) & 1)) & j;
        long j50 = j48 ^ (j49 >>> 36);
        long j51 = (-((j2 >>> 29) & 1)) & j;
        long j52 = j50 ^ (j51 >>> 35);
        long j53 = (-((j2 >>> 30) & 1)) & j;
        long j54 = j52 ^ (j53 >>> 34);
        long j55 = (-((j2 >>> 31) & 1)) & j;
        long j56 = j54 ^ (j55 >>> 33);
        long j57 = (-((j2 >>> 32) & 1)) & j;
        long j58 = j56 ^ (j57 >>> 32);
        long j59 = (-((j2 >>> 33) & 1)) & j;
        long j60 = j58 ^ (j59 >>> 31);
        long j61 = (-((j2 >>> 34) & 1)) & j;
        long j62 = j60 ^ (j61 >>> 30);
        long j63 = (-((j2 >>> 35) & 1)) & j;
        long j64 = j62 ^ (j63 >>> 29);
        long j65 = (-((j2 >>> 36) & 1)) & j;
        long j66 = j64 ^ (j65 >>> 28);
        long j67 = (-((j2 >>> 37) & 1)) & j;
        long j68 = j66 ^ (j67 >>> 27);
        long j69 = (-((j2 >>> 38) & 1)) & j;
        long j70 = j68 ^ (j69 >>> 26);
        long j71 = (-((j2 >>> 39) & 1)) & j;
        long j72 = j70 ^ (j71 >>> 25);
        long j73 = (-((j2 >>> 40) & 1)) & j;
        long j74 = j72 ^ (j73 >>> 24);
        long j75 = (-((j2 >>> 41) & 1)) & j;
        long j76 = j74 ^ (j75 >>> 23);
        long j77 = (-((j2 >>> 42) & 1)) & j;
        long j78 = j76 ^ (j77 >>> 22);
        long j79 = (-((j2 >>> 43) & 1)) & j;
        long j80 = j78 ^ (j79 >>> 21);
        long j81 = (-((j2 >>> 44) & 1)) & j;
        long j82 = j80 ^ (j81 >>> 20);
        long j83 = (-((j2 >>> 45) & 1)) & j;
        long j84 = j82 ^ (j83 >>> 19);
        long j85 = (-((j2 >>> 46) & 1)) & j;
        long j86 = j84 ^ (j85 >>> 18);
        long j87 = (-((j2 >>> 47) & 1)) & j;
        long j88 = j86 ^ (j87 >>> 17);
        long j89 = (-((j2 >>> 48) & 1)) & j;
        long j90 = j88 ^ (j89 >>> 16);
        long j91 = (-((j2 >>> 49) & 1)) & j;
        long j92 = j90 ^ (j91 >>> 15);
        long j93 = (-((j2 >>> 50) & 1)) & j;
        long j94 = j92 ^ (j93 >>> 14);
        long j95 = (-((j2 >>> 51) & 1)) & j;
        long j96 = j94 ^ (j95 >>> 13);
        long j97 = (-((j2 >>> 52) & 1)) & j;
        long j98 = j96 ^ (j97 >>> 12);
        long j99 = (-((j2 >>> 53) & 1)) & j;
        long j100 = j98 ^ (j99 >>> 11);
        long j101 = (-((j2 >>> 54) & 1)) & j;
        long j102 = j100 ^ (j101 >>> 10);
        long j103 = (-((j2 >>> 55) & 1)) & j;
        long j104 = j102 ^ (j103 >>> 9);
        long j105 = (-((j2 >>> 56) & 1)) & j;
        long j106 = j104 ^ (j105 >>> 8);
        long j107 = (-((j2 >>> 57) & 1)) & j;
        long j108 = j106 ^ (j107 >>> 7);
        long j109 = (-((j2 >>> 58) & 1)) & j;
        long j110 = (-((j2 >>> 59) & 1)) & j;
        long j111 = (-((j2 >>> 60) & 1)) & j;
        long j112 = (-((j2 >>> 61) & 1)) & j;
        long j113 = (-(1 & (j2 >>> 62))) & j;
        jArr[i] = ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((-(j2 & 1)) & j) ^ (j3 << 63)) ^ (j4 << 1)) ^ (j6 << 2)) ^ (j7 << 3)) ^ (j8 << 4)) ^ (j9 << 5)) ^ (j10 << 6)) ^ (j11 << 7)) ^ (j12 << 8)) ^ (j13 << 9)) ^ (j14 << 10)) ^ (j15 << 11)) ^ (j17 << 12)) ^ (j19 << 13)) ^ (j21 << 14)) ^ (j23 << 15)) ^ (j25 << 16)) ^ (j27 << 17)) ^ (j29 << 18)) ^ (j31 << 19)) ^ (j33 << 20)) ^ (j35 << 21)) ^ (j37 << 22)) ^ (j39 << 23)) ^ (j41 << 24)) ^ (j43 << 25)) ^ (j45 << 26)) ^ (j47 << 27)) ^ (j49 << 28)) ^ (j51 << 29)) ^ (j53 << 30)) ^ (j55 << 31)) ^ (j57 << 32)) ^ (j59 << 33)) ^ (j61 << 34)) ^ (j63 << 35)) ^ (j65 << 36)) ^ (j67 << 37)) ^ (j69 << 38)) ^ (j71 << 39)) ^ (j73 << 40)) ^ (j75 << 41)) ^ (j77 << 42)) ^ (j79 << 43)) ^ (j81 << 44)) ^ (j83 << 45)) ^ (j85 << 46)) ^ (j87 << 47)) ^ (j89 << 48)) ^ (j91 << 49)) ^ (j93 << 50)) ^ (j95 << 51)) ^ (j97 << 52)) ^ (j99 << 53)) ^ (j101 << 54)) ^ (j103 << 55)) ^ (j105 << 56)) ^ (j107 << 57)) ^ (j109 << 58)) ^ (j110 << 59)) ^ (j111 << 60)) ^ (j112 << 61)) ^ (j113 << 62);
        jArr[i + 1] = (j113 >>> 2) ^ ((((j108 ^ (j109 >>> 6)) ^ (j110 >>> 5)) ^ (j111 >>> 4)) ^ (j112 >>> 3));
    }

    private static void MUL64_NO_SIMD_GF2X_XOR(long[] jArr, int i, long j, long j2) {
        long j3 = (-(j2 >>> 63)) & j;
        long j4 = (-((j2 >>> 1) & 1)) & j;
        long j5 = (j3 >>> 1) ^ (j4 >>> 63);
        long j6 = (-((j2 >>> 2) & 1)) & j;
        long j7 = (-((j2 >>> 3) & 1)) & j;
        long j8 = (-((j2 >>> 4) & 1)) & j;
        long j9 = (-((j2 >>> 5) & 1)) & j;
        long j10 = (-((j2 >>> 6) & 1)) & j;
        long j11 = (-((j2 >>> 7) & 1)) & j;
        long j12 = (-((j2 >>> 8) & 1)) & j;
        long j13 = (-((j2 >>> 9) & 1)) & j;
        long j14 = (-((j2 >>> 10) & 1)) & j;
        long j15 = (-((j2 >>> 11) & 1)) & j;
        long j16 = (((((((((j5 ^ (j6 >>> 62)) ^ (j7 >>> 61)) ^ (j8 >>> 60)) ^ (j9 >>> 59)) ^ (j10 >>> 58)) ^ (j11 >>> 57)) ^ (j12 >>> 56)) ^ (j13 >>> 55)) ^ (j14 >>> 54)) ^ (j15 >>> 53);
        long j17 = (-((j2 >>> 12) & 1)) & j;
        long j18 = j16 ^ (j17 >>> 52);
        long j19 = (-((j2 >>> 13) & 1)) & j;
        long j20 = j18 ^ (j19 >>> 51);
        long j21 = (-((j2 >>> 14) & 1)) & j;
        long j22 = j20 ^ (j21 >>> 50);
        long j23 = (-((j2 >>> 15) & 1)) & j;
        long j24 = j22 ^ (j23 >>> 49);
        long j25 = (-((j2 >>> 16) & 1)) & j;
        long j26 = j24 ^ (j25 >>> 48);
        long j27 = (-((j2 >>> 17) & 1)) & j;
        long j28 = j26 ^ (j27 >>> 47);
        long j29 = (-((j2 >>> 18) & 1)) & j;
        long j30 = j28 ^ (j29 >>> 46);
        long j31 = (-((j2 >>> 19) & 1)) & j;
        long j32 = j30 ^ (j31 >>> 45);
        long j33 = (-((j2 >>> 20) & 1)) & j;
        long j34 = j32 ^ (j33 >>> 44);
        long j35 = (-((j2 >>> 21) & 1)) & j;
        long j36 = j34 ^ (j35 >>> 43);
        long j37 = (-((j2 >>> 22) & 1)) & j;
        long j38 = j36 ^ (j37 >>> 42);
        long j39 = (-((j2 >>> 23) & 1)) & j;
        long j40 = j38 ^ (j39 >>> 41);
        long j41 = (-((j2 >>> 24) & 1)) & j;
        long j42 = j40 ^ (j41 >>> 40);
        long j43 = (-((j2 >>> 25) & 1)) & j;
        long j44 = j42 ^ (j43 >>> 39);
        long j45 = (-((j2 >>> 26) & 1)) & j;
        long j46 = j44 ^ (j45 >>> 38);
        long j47 = (-((j2 >>> 27) & 1)) & j;
        long j48 = j46 ^ (j47 >>> 37);
        long j49 = (-((j2 >>> 28) & 1)) & j;
        long j50 = j48 ^ (j49 >>> 36);
        long j51 = (-((j2 >>> 29) & 1)) & j;
        long j52 = j50 ^ (j51 >>> 35);
        long j53 = (-((j2 >>> 30) & 1)) & j;
        long j54 = j52 ^ (j53 >>> 34);
        long j55 = (-((j2 >>> 31) & 1)) & j;
        long j56 = j54 ^ (j55 >>> 33);
        long j57 = (-((j2 >>> 32) & 1)) & j;
        long j58 = j56 ^ (j57 >>> 32);
        long j59 = (-((j2 >>> 33) & 1)) & j;
        long j60 = j58 ^ (j59 >>> 31);
        long j61 = (-((j2 >>> 34) & 1)) & j;
        long j62 = j60 ^ (j61 >>> 30);
        long j63 = (-((j2 >>> 35) & 1)) & j;
        long j64 = j62 ^ (j63 >>> 29);
        long j65 = (-((j2 >>> 36) & 1)) & j;
        long j66 = j64 ^ (j65 >>> 28);
        long j67 = (-((j2 >>> 37) & 1)) & j;
        long j68 = j66 ^ (j67 >>> 27);
        long j69 = (-((j2 >>> 38) & 1)) & j;
        long j70 = j68 ^ (j69 >>> 26);
        long j71 = (-((j2 >>> 39) & 1)) & j;
        long j72 = j70 ^ (j71 >>> 25);
        long j73 = (-((j2 >>> 40) & 1)) & j;
        long j74 = j72 ^ (j73 >>> 24);
        long j75 = (-((j2 >>> 41) & 1)) & j;
        long j76 = j74 ^ (j75 >>> 23);
        long j77 = (-((j2 >>> 42) & 1)) & j;
        long j78 = j76 ^ (j77 >>> 22);
        long j79 = (-((j2 >>> 43) & 1)) & j;
        long j80 = j78 ^ (j79 >>> 21);
        long j81 = (-((j2 >>> 44) & 1)) & j;
        long j82 = j80 ^ (j81 >>> 20);
        long j83 = (-((j2 >>> 45) & 1)) & j;
        long j84 = j82 ^ (j83 >>> 19);
        long j85 = (-((j2 >>> 46) & 1)) & j;
        long j86 = j84 ^ (j85 >>> 18);
        long j87 = (-((j2 >>> 47) & 1)) & j;
        long j88 = j86 ^ (j87 >>> 17);
        long j89 = (-((j2 >>> 48) & 1)) & j;
        long j90 = j88 ^ (j89 >>> 16);
        long j91 = (-((j2 >>> 49) & 1)) & j;
        long j92 = j90 ^ (j91 >>> 15);
        long j93 = (-((j2 >>> 50) & 1)) & j;
        long j94 = j92 ^ (j93 >>> 14);
        long j95 = (-((j2 >>> 51) & 1)) & j;
        long j96 = j94 ^ (j95 >>> 13);
        long j97 = (-((j2 >>> 52) & 1)) & j;
        long j98 = j96 ^ (j97 >>> 12);
        long j99 = (-((j2 >>> 53) & 1)) & j;
        long j100 = j98 ^ (j99 >>> 11);
        long j101 = (-((j2 >>> 54) & 1)) & j;
        long j102 = j100 ^ (j101 >>> 10);
        long j103 = (-((j2 >>> 55) & 1)) & j;
        long j104 = j102 ^ (j103 >>> 9);
        long j105 = (-((j2 >>> 56) & 1)) & j;
        long j106 = j104 ^ (j105 >>> 8);
        long j107 = (-((j2 >>> 57) & 1)) & j;
        long j108 = j106 ^ (j107 >>> 7);
        long j109 = (-((j2 >>> 58) & 1)) & j;
        long j110 = (-((j2 >>> 59) & 1)) & j;
        long j111 = (-((j2 >>> 60) & 1)) & j;
        long j112 = (-((j2 >>> 61) & 1)) & j;
        long j113 = (-(1 & (j2 >>> 62))) & j;
        jArr[i] = (((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((-(j2 & 1)) & j) ^ (j3 << 63)) ^ (j4 << 1)) ^ (j6 << 2)) ^ (j7 << 3)) ^ (j8 << 4)) ^ (j9 << 5)) ^ (j10 << 6)) ^ (j11 << 7)) ^ (j12 << 8)) ^ (j13 << 9)) ^ (j14 << 10)) ^ (j15 << 11)) ^ (j17 << 12)) ^ (j19 << 13)) ^ (j21 << 14)) ^ (j23 << 15)) ^ (j25 << 16)) ^ (j27 << 17)) ^ (j29 << 18)) ^ (j31 << 19)) ^ (j33 << 20)) ^ (j35 << 21)) ^ (j37 << 22)) ^ (j39 << 23)) ^ (j41 << 24)) ^ (j43 << 25)) ^ (j45 << 26)) ^ (j47 << 27)) ^ (j49 << 28)) ^ (j51 << 29)) ^ (j53 << 30)) ^ (j55 << 31)) ^ (j57 << 32)) ^ (j59 << 33)) ^ (j61 << 34)) ^ (j63 << 35)) ^ (j65 << 36)) ^ (j67 << 37)) ^ (j69 << 38)) ^ (j71 << 39)) ^ (j73 << 40)) ^ (j75 << 41)) ^ (j77 << 42)) ^ (j79 << 43)) ^ (j81 << 44)) ^ (j83 << 45)) ^ (j85 << 46)) ^ (j87 << 47)) ^ (j89 << 48)) ^ (j91 << 49)) ^ (j93 << 50)) ^ (j95 << 51)) ^ (j97 << 52)) ^ (j99 << 53)) ^ (j101 << 54)) ^ (j103 << 55)) ^ (j105 << 56)) ^ (j107 << 57)) ^ (j109 << 58)) ^ (j110 << 59)) ^ (j111 << 60)) ^ (j112 << 61)) ^ (j113 << 62)) ^ jArr[i];
        int i2 = i + 1;
        jArr[i2] = ((j113 >>> 2) ^ ((((j108 ^ (j109 >>> 6)) ^ (j110 >>> 5)) ^ (j111 >>> 4)) ^ (j112 >>> 3))) ^ jArr[i2];
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void SQR128_NO_SIMD_GF2X(long[] jArr, int i, long[] jArr2, int i2) {
        SQR64_NO_SIMD_GF2X(jArr, i + 2, jArr2[i2 + 1]);
        SQR64_NO_SIMD_GF2X(jArr, i, jArr2[i2]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void SQR256_NO_SIMD_GF2X(long[] jArr, int i, long[] jArr2, int i2) {
        SQR128_NO_SIMD_GF2X(jArr, i + 4, jArr2, i2 + 2);
        SQR128_NO_SIMD_GF2X(jArr, i, jArr2, i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static long SQR32_NO_SIMD_GF2X(long j) {
        long j2 = (j ^ (j << 16)) & 281470681808895L;
        long j3 = (j2 ^ (j2 << 8)) & 71777214294589695L;
        long j4 = (j3 ^ (j3 << 4)) & 1085102592571150095L;
        long j5 = (j4 ^ (j4 << 2)) & 3689348814741910323L;
        return (j5 ^ (j5 << 1)) & 6148914691236517205L;
    }

    private static long SQR64LOW_NO_SIMD_GF2X(long j) {
        long j2 = ((j << 16) ^ (BodyPartID.bodyIdMax & j)) & 281470681808895L;
        long j3 = (j2 ^ (j2 << 8)) & 71777214294589695L;
        long j4 = (j3 ^ (j3 << 4)) & 1085102592571150095L;
        long j5 = (j4 ^ (j4 << 2)) & 3689348814741910323L;
        return (j5 ^ (j5 << 1)) & 6148914691236517205L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void SQR64_NO_SIMD_GF2X(long[] jArr, int i, long j) {
        jArr[i + 1] = SQR32_NO_SIMD_GF2X(j >>> 32);
        jArr[i] = SQR64LOW_NO_SIMD_GF2X(j);
    }

    private static void mul128_no_simd_gf2x(long[] jArr, int i, long j, long j2, long j3, long j4) {
        MUL64_NO_SIMD_GF2X(jArr, i, j, j3);
        int i2 = i + 2;
        MUL64_NO_SIMD_GF2X(jArr, i2, j2, j4);
        int i3 = i + 1;
        long j5 = jArr[i2] ^ jArr[i3];
        jArr[i2] = j5;
        jArr[i3] = j5 ^ jArr[i];
        jArr[i2] = jArr[i2] ^ jArr[i + 3];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i3, j ^ j2, j3 ^ j4);
    }

    private static void mul128_no_simd_gf2x(long[] jArr, int i, long[] jArr2, int i2, long[] jArr3, int i3) {
        MUL64_NO_SIMD_GF2X(jArr, i, jArr2[i2], jArr3[i3]);
        int i4 = i + 2;
        int i5 = i2 + 1;
        int i6 = i3 + 1;
        MUL64_NO_SIMD_GF2X(jArr, i4, jArr2[i5], jArr3[i6]);
        int i7 = i + 1;
        long j = jArr[i4] ^ jArr[i7];
        jArr[i4] = j;
        jArr[i7] = j ^ jArr[i];
        jArr[i4] = jArr[i4] ^ jArr[i + 3];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i7, jArr2[i2] ^ jArr2[i5], jArr3[i3] ^ jArr3[i6]);
    }

    private static void mul128_no_simd_gf2x_xor(long[] jArr, int i, long j, long j2, long j3, long j4, long[] jArr2) {
        MUL64_NO_SIMD_GF2X(jArr2, 0, j, j3);
        MUL64_NO_SIMD_GF2X(jArr2, 2, j2, j4);
        jArr[i] = jArr[i] ^ jArr2[0];
        long j5 = jArr2[2] ^ jArr2[1];
        jArr2[2] = j5;
        int i2 = i + 1;
        jArr[i2] = (jArr2[0] ^ j5) ^ jArr[i2];
        int i3 = i + 2;
        jArr[i3] = jArr[i3] ^ (jArr2[2] ^ jArr2[3]);
        int i4 = i + 3;
        jArr[i4] = jArr[i4] ^ jArr2[3];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i2, j ^ j2, j3 ^ j4);
    }

    public static void mul192_no_simd_gf2x(long[] jArr, int i, long[] jArr2, int i2, long[] jArr3, int i3) {
        MUL64_NO_SIMD_GF2X(jArr, i, jArr2[i2], jArr3[i3]);
        int i4 = i + 4;
        int i5 = i2 + 2;
        int i6 = i3 + 2;
        MUL64_NO_SIMD_GF2X(jArr, i4, jArr2[i5], jArr3[i6]);
        int i7 = i + 2;
        int i8 = i2 + 1;
        int i9 = i3 + 1;
        MUL64_NO_SIMD_GF2X(jArr, i7, jArr2[i8], jArr3[i9]);
        int i10 = i + 1;
        jArr[i10] = jArr[i10] ^ jArr[i7];
        int i11 = i + 3;
        long j = jArr[i11] ^ jArr[i4];
        jArr[i11] = j;
        jArr[i4] = j ^ jArr[i + 5];
        jArr[i7] = (jArr[i11] ^ jArr[i10]) ^ jArr[i];
        jArr[i11] = jArr[i10] ^ jArr[i4];
        jArr[i10] = jArr[i10] ^ jArr[i];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i10, jArr2[i2] ^ jArr2[i8], jArr3[i3] ^ jArr3[i9]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i11, jArr2[i5] ^ jArr2[i8], jArr3[i6] ^ jArr3[i9]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i7, jArr2[i2] ^ jArr2[i5], jArr3[i3] ^ jArr3[i6]);
    }

    public static void mul192_no_simd_gf2x_xor(long[] jArr, int i, long[] jArr2, int i2, long[] jArr3, int i3, long[] jArr4) {
        MUL64_NO_SIMD_GF2X(jArr4, 0, jArr2[i2], jArr3[i3]);
        int i4 = i2 + 2;
        int i5 = i3 + 2;
        MUL64_NO_SIMD_GF2X(jArr4, 4, jArr2[i4], jArr3[i5]);
        int i6 = i2 + 1;
        int i7 = i3 + 1;
        MUL64_NO_SIMD_GF2X(jArr4, 2, jArr2[i6], jArr3[i7]);
        jArr[i] = jArr[i] ^ jArr4[0];
        long j = jArr4[1] ^ jArr4[2];
        jArr4[1] = j;
        long j2 = jArr4[3] ^ jArr4[4];
        jArr4[3] = j2;
        jArr4[4] = j2 ^ jArr4[5];
        long j3 = j ^ jArr4[0];
        jArr4[0] = j3;
        int i8 = i + 1;
        jArr[i8] = j3 ^ jArr[i8];
        int i9 = i + 2;
        jArr[i9] = (jArr4[0] ^ jArr4[3]) ^ jArr[i9];
        int i10 = i + 3;
        jArr[i10] = jArr[i10] ^ (jArr4[1] ^ jArr4[4]);
        int i11 = i + 4;
        jArr[i11] = jArr[i11] ^ jArr4[4];
        int i12 = i + 5;
        jArr[i12] = jArr[i12] ^ jArr4[5];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i8, jArr2[i6] ^ jArr2[i2], jArr3[i7] ^ jArr3[i3]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i10, jArr2[i4] ^ jArr2[i6], jArr3[i5] ^ jArr3[i7]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i9, jArr2[i2] ^ jArr2[i4], jArr3[i3] ^ jArr3[i5]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul288_no_simd_gf2x(long[] jArr, int i, long[] jArr2, int i2, long[] jArr3, int i3, long[] jArr4) {
        int i4 = i2 + 1;
        int i5 = i3 + 1;
        mul128_no_simd_gf2x(jArr, i, jArr2[i2], jArr2[i4], jArr3[i3], jArr3[i5]);
        int i6 = i + 4;
        int i7 = i2 + 2;
        int i8 = i3 + 2;
        MUL64_NO_SIMD_GF2X(jArr, i6, jArr2[i7], jArr3[i8]);
        int i9 = i + 7;
        int i10 = i2 + 3;
        int i11 = i3 + 3;
        MUL64_NO_SIMD_GF2X(jArr, i9, jArr2[i10], jArr3[i11]);
        int i12 = i + 5;
        jArr[i9] = jArr[i9] ^ jArr[i12];
        int i13 = i + 8;
        int i14 = i2 + 4;
        int i15 = i3 + 4;
        jArr[i13] = jArr[i13] ^ MUL32_NO_SIMD_GF2X(jArr2[i14], jArr3[i15]);
        jArr[i12] = jArr[i9] ^ jArr[i6];
        long j = jArr[i9] ^ jArr[i13];
        jArr[i9] = j;
        int i16 = i + 6;
        jArr[i16] = j ^ jArr[i6];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i12, jArr2[i10] ^ jArr2[i7], jArr3[i11] ^ jArr3[i8]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i9, jArr2[i14] ^ jArr2[i10], jArr3[i15] ^ jArr3[i11]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i16, jArr2[i14] ^ jArr2[i7], jArr3[i15] ^ jArr3[i8]);
        int i17 = i + 2;
        jArr[i6] = jArr[i6] ^ jArr[i17];
        int i18 = i + 3;
        jArr[i12] = jArr[i12] ^ jArr[i18];
        long j2 = jArr2[i2] ^ jArr2[i7];
        long j3 = jArr2[i4] ^ jArr2[i10];
        long j4 = jArr3[i3] ^ jArr3[i8];
        long j5 = jArr3[i5] ^ jArr3[i11];
        MUL64_NO_SIMD_GF2X(jArr4, 0, j2, j4);
        MUL64_NO_SIMD_GF2X(jArr4, 2, j3, j5);
        jArr4[2] = jArr4[2] ^ jArr4[1];
        jArr4[3] = MUL32_NO_SIMD_GF2X(jArr2[i14], jArr3[i15]) ^ jArr4[3];
        jArr[i17] = (jArr[i6] ^ jArr[i]) ^ jArr4[0];
        jArr[i18] = ((jArr[i12] ^ jArr[i + 1]) ^ jArr4[2]) ^ jArr4[0];
        long j6 = jArr4[2] ^ jArr4[3];
        jArr4[2] = j6;
        jArr[i6] = ((j6 ^ jArr[i16]) ^ jArr4[0]) ^ jArr[i6];
        jArr[i12] = jArr[i12] ^ (jArr4[2] ^ jArr[i9]);
        jArr[i16] = jArr[i16] ^ (jArr[i13] ^ jArr4[3]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i18, j2 ^ j3, j4 ^ j5);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i12, j3 ^ jArr2[i14], j5 ^ jArr3[i15]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i6, j2 ^ jArr2[i14], jArr3[i15] ^ j4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul288_no_simd_gf2x_xor(long[] jArr, int i, long[] jArr2, int i2, long[] jArr3, int i3, long[] jArr4) {
        int i4 = i2 + 1;
        int i5 = i3 + 1;
        mul128_no_simd_gf2x(jArr4, 0, jArr2[i2], jArr2[i4], jArr3[i3], jArr3[i5]);
        int i6 = i2 + 2;
        int i7 = i3 + 2;
        MUL64_NO_SIMD_GF2X(jArr4, 4, jArr2[i6], jArr3[i7]);
        int i8 = i2 + 3;
        int i9 = i3 + 3;
        MUL64_NO_SIMD_GF2X(jArr4, 7, jArr2[i8], jArr3[i9]);
        jArr4[7] = jArr4[7] ^ jArr4[5];
        int i10 = i2 + 4;
        int i11 = i3 + 4;
        long MUL32_NO_SIMD_GF2X = jArr4[8] ^ MUL32_NO_SIMD_GF2X(jArr2[i10], jArr3[i11]);
        jArr4[8] = MUL32_NO_SIMD_GF2X;
        long j = jArr4[7];
        long j2 = jArr4[4];
        long j3 = j ^ j2;
        jArr4[5] = j3;
        long j4 = MUL32_NO_SIMD_GF2X ^ j;
        jArr4[7] = j4;
        jArr4[6] = j4 ^ j2;
        jArr4[4] = jArr4[2] ^ j2;
        jArr4[5] = j3 ^ jArr4[3];
        jArr[i] = jArr[i] ^ jArr4[0];
        int i12 = i + 1;
        jArr[i12] = jArr[i12] ^ jArr4[1];
        int i13 = i + 2;
        jArr[i13] = jArr[i13] ^ (jArr4[4] ^ jArr4[0]);
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 5, jArr2[i8] ^ jArr2[i6], jArr3[i9] ^ jArr3[i7]);
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 7, jArr2[i10] ^ jArr2[i8], jArr3[i11] ^ jArr3[i9]);
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 6, jArr2[i10] ^ jArr2[i6], jArr3[i11] ^ jArr3[i7]);
        int i14 = i + 3;
        jArr[i14] = jArr[i14] ^ (jArr4[5] ^ jArr4[1]);
        int i15 = i + 4;
        jArr[i15] = jArr[i15] ^ (jArr4[4] ^ jArr4[6]);
        int i16 = i + 5;
        jArr[i16] = jArr[i16] ^ (jArr4[5] ^ jArr4[7]);
        int i17 = i + 6;
        jArr[i17] = jArr[i17] ^ (jArr4[6] ^ jArr4[8]);
        int i18 = i + 7;
        jArr[i18] = jArr[i18] ^ jArr4[7];
        int i19 = i + 8;
        jArr[i19] = jArr[i19] ^ jArr4[8];
        long j5 = jArr2[i2] ^ jArr2[i6];
        long j6 = jArr2[i4] ^ jArr2[i8];
        long j7 = jArr3[i3] ^ jArr3[i7];
        long j8 = jArr3[i5] ^ jArr3[i9];
        MUL64_NO_SIMD_GF2X(jArr4, 0, j5, j7);
        MUL64_NO_SIMD_GF2X(jArr4, 2, j6, j8);
        jArr4[2] = jArr4[2] ^ jArr4[1];
        jArr4[3] = jArr4[3] ^ MUL32_NO_SIMD_GF2X(jArr2[i10], jArr3[i11]);
        jArr[i13] = jArr[i13] ^ jArr4[0];
        jArr[i14] = jArr[i14] ^ (jArr4[2] ^ jArr4[0]);
        long j9 = jArr4[2] ^ jArr4[3];
        jArr4[2] = j9;
        jArr[i15] = (j9 ^ jArr4[0]) ^ jArr[i15];
        jArr[i16] = jArr[i16] ^ jArr4[2];
        jArr[i17] = jArr[i17] ^ jArr4[3];
        MUL64_NO_SIMD_GF2X_XOR(jArr, i14, j5 ^ j6, j7 ^ j8);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i16, j6 ^ jArr2[i10], j8 ^ jArr3[i11]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, i15, j5 ^ jArr2[i10], jArr3[i11] ^ j7);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul384_no_simd_gf2x(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4) {
        mul192_no_simd_gf2x(jArr, 0, jArr2, i, jArr3, i2);
        int i3 = i + 3;
        int i4 = i2 + 3;
        mul192_no_simd_gf2x(jArr, 6, jArr2, i3, jArr3, i4);
        long j = jArr2[i] ^ jArr2[i3];
        long j2 = jArr2[i + 1] ^ jArr2[i + 4];
        long j3 = jArr2[i + 2] ^ jArr2[i + 5];
        long j4 = jArr3[i2] ^ jArr3[i4];
        long j5 = jArr3[i2 + 1] ^ jArr3[i2 + 4];
        long j6 = jArr3[i2 + 2] ^ jArr3[i2 + 5];
        jArr[6] = jArr[6] ^ jArr[3];
        jArr[7] = jArr[7] ^ jArr[4];
        jArr[8] = jArr[8] ^ jArr[5];
        MUL64_NO_SIMD_GF2X(jArr4, 0, j, j4);
        MUL64_NO_SIMD_GF2X(jArr4, 4, j3, j6);
        MUL64_NO_SIMD_GF2X(jArr4, 2, j2, j5);
        long j7 = jArr[6];
        long j8 = jArr4[0];
        jArr[3] = (jArr[0] ^ j7) ^ j8;
        long j9 = jArr4[1] ^ jArr4[2];
        jArr4[1] = j9;
        long j10 = j8 ^ j9;
        jArr4[0] = j10;
        long j11 = jArr4[3] ^ jArr4[4];
        jArr4[3] = j11;
        long j12 = j11 ^ jArr4[5];
        jArr4[4] = j12;
        long j13 = jArr[8];
        jArr[5] = ((j13 ^ jArr[2]) ^ j11) ^ j10;
        jArr[6] = j7 ^ ((jArr[9] ^ j9) ^ j12);
        long j14 = jArr[7];
        jArr[4] = (jArr[1] ^ j14) ^ j10;
        jArr[7] = j14 ^ (jArr[10] ^ jArr4[4]);
        jArr[8] = j13 ^ (jArr[11] ^ jArr4[5]);
        MUL64_NO_SIMD_GF2X_XOR(jArr, 4, j ^ j2, j4 ^ j5);
        MUL64_NO_SIMD_GF2X_XOR(jArr, 6, j2 ^ j3, j5 ^ j6);
        MUL64_NO_SIMD_GF2X_XOR(jArr, 5, j ^ j3, j4 ^ j6);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul384_no_simd_gf2x_xor(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4) {
        mul192_no_simd_gf2x(jArr4, 0, jArr2, i, jArr3, i2);
        int i3 = i + 3;
        int i4 = i2 + 3;
        mul192_no_simd_gf2x(jArr4, 6, jArr2, i3, jArr3, i4);
        long j = jArr2[i] ^ jArr2[i3];
        long j2 = jArr2[i + 1] ^ jArr2[i + 4];
        long j3 = jArr2[i + 2] ^ jArr2[i + 5];
        long j4 = jArr3[i2] ^ jArr3[i4];
        long j5 = jArr3[i2 + 1] ^ jArr3[i2 + 4];
        long j6 = jArr3[i2 + 2] ^ jArr3[i2 + 5];
        long j7 = jArr4[6] ^ jArr4[3];
        jArr4[6] = j7;
        long j8 = jArr4[7] ^ jArr4[4];
        jArr4[7] = j8;
        long j9 = jArr4[8] ^ jArr4[5];
        jArr4[8] = j9;
        jArr[0] = jArr[0] ^ jArr4[0];
        jArr[1] = jArr[1] ^ jArr4[1];
        jArr[2] = jArr[2] ^ jArr4[2];
        jArr[3] = jArr[3] ^ (j7 ^ jArr4[0]);
        jArr[5] = jArr[5] ^ (j9 ^ jArr4[2]);
        long j10 = jArr[6];
        long j11 = jArr4[9];
        jArr[6] = j10 ^ (j7 ^ j11);
        jArr[4] = jArr[4] ^ (j8 ^ jArr4[1]);
        long j12 = jArr[7];
        long j13 = jArr4[10];
        jArr[7] = j12 ^ (j8 ^ j13);
        long j14 = jArr[8];
        long j15 = jArr4[11];
        jArr[8] = j14 ^ (j9 ^ j15);
        jArr[9] = jArr[9] ^ j11;
        jArr[10] = jArr[10] ^ j13;
        jArr[11] = jArr[11] ^ j15;
        MUL64_NO_SIMD_GF2X(jArr4, 0, j, j4);
        MUL64_NO_SIMD_GF2X(jArr4, 4, j3, j6);
        MUL64_NO_SIMD_GF2X(jArr4, 2, j2, j5);
        long j16 = jArr[3];
        long j17 = jArr4[0];
        jArr[3] = j16 ^ j17;
        long j18 = jArr4[1] ^ jArr4[2];
        jArr4[1] = j18;
        long j19 = j17 ^ j18;
        jArr4[0] = j19;
        long j20 = jArr4[3] ^ jArr4[4];
        jArr4[3] = j20;
        long j21 = j20 ^ jArr4[5];
        jArr4[4] = j21;
        jArr[5] = jArr[5] ^ (j20 ^ j19);
        jArr[6] = (j18 ^ j21) ^ jArr[6];
        jArr[4] = jArr[4] ^ j19;
        jArr[7] = jArr[7] ^ jArr4[4];
        jArr[8] = jArr[8] ^ jArr4[5];
        MUL64_NO_SIMD_GF2X_XOR(jArr, 4, j ^ j2, j4 ^ j5);
        MUL64_NO_SIMD_GF2X_XOR(jArr, 6, j2 ^ j3, j5 ^ j6);
        MUL64_NO_SIMD_GF2X_XOR(jArr, 5, j ^ j3, j4 ^ j6);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul416_no_simd_gf2x(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4) {
        mul192_no_simd_gf2x(jArr, 0, jArr2, i, jArr3, i2);
        int i3 = i + 3;
        int i4 = i + 4;
        int i5 = i2 + 3;
        int i6 = i2 + 4;
        mul128_no_simd_gf2x(jArr, 6, jArr2[i3], jArr2[i4], jArr3[i5], jArr3[i6]);
        int i7 = i + 5;
        int i8 = i2 + 5;
        MUL64_NO_SIMD_GF2X(jArr, 10, jArr2[i7], jArr3[i8]);
        int i9 = i + 6;
        int i10 = i2 + 6;
        long MUL32_NO_SIMD_GF2X = MUL32_NO_SIMD_GF2X(jArr2[i9], jArr3[i10]) ^ jArr[11];
        jArr[12] = MUL32_NO_SIMD_GF2X;
        jArr[11] = MUL32_NO_SIMD_GF2X ^ jArr[10];
        MUL64_NO_SIMD_GF2X_XOR(jArr, 11, jArr2[i9] ^ jArr2[i7], jArr3[i10] ^ jArr3[i8]);
        long j = jArr[8] ^ jArr[10];
        jArr[8] = j;
        long j2 = jArr[11] ^ jArr[9];
        jArr[11] = j2;
        jArr[10] = jArr[12] ^ j;
        jArr[8] = j ^ jArr[6];
        jArr[9] = jArr[7] ^ j2;
        mul128_no_simd_gf2x_xor(jArr, 8, jArr2[i7] ^ jArr2[i3], jArr2[i9] ^ jArr2[i4], jArr3[i8] ^ jArr3[i5], jArr3[i10] ^ jArr3[i6], jArr4);
        long j3 = jArr2[i] ^ jArr2[i3];
        long j4 = jArr2[i + 1] ^ jArr2[i4];
        long j5 = jArr2[i + 2] ^ jArr2[i7];
        long j6 = jArr2[i9];
        long j7 = jArr3[i2] ^ jArr3[i5];
        long j8 = jArr3[i2 + 1] ^ jArr3[i6];
        long j9 = jArr3[i2 + 2] ^ jArr3[i8];
        long j10 = jArr3[i10];
        jArr[6] = jArr[6] ^ jArr[3];
        jArr[7] = jArr[7] ^ jArr[4];
        jArr[8] = jArr[8] ^ jArr[5];
        mul128_no_simd_gf2x(jArr4, 0, j3, j4, j7, j8);
        MUL64_NO_SIMD_GF2X(jArr4, 4, j5, j9);
        long MUL32_NO_SIMD_GF2X2 = MUL32_NO_SIMD_GF2X(j6, j10) ^ jArr4[5];
        jArr4[6] = MUL32_NO_SIMD_GF2X2;
        jArr4[5] = MUL32_NO_SIMD_GF2X2 ^ jArr4[4];
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 5, j5 ^ j6, j9 ^ j10);
        long j11 = jArr[6];
        long j12 = jArr4[0];
        jArr[3] = (jArr[0] ^ j11) ^ j12;
        long j13 = jArr[7];
        long j14 = jArr4[1];
        jArr[4] = (j13 ^ jArr[1]) ^ j14;
        long j15 = jArr4[2] ^ jArr4[4];
        jArr4[2] = j15;
        long j16 = jArr4[3] ^ jArr4[5];
        jArr4[3] = j16;
        long j17 = jArr[8];
        jArr[5] = ((j17 ^ jArr[2]) ^ j15) ^ j12;
        long j18 = jArr[9];
        jArr[6] = j11 ^ ((j18 ^ j16) ^ j14);
        long j19 = jArr4[6];
        jArr[7] = ((jArr[10] ^ j15) ^ j19) ^ j13;
        jArr[8] = j17 ^ (jArr[11] ^ j16);
        jArr[9] = (jArr[12] ^ j19) ^ j18;
        mul128_no_simd_gf2x_xor(jArr, 5, j3 ^ j5, j4 ^ j6, j7 ^ j9, j8 ^ j10, jArr4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul416_no_simd_gf2x_xor(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4, long[] jArr5) {
        mul192_no_simd_gf2x(jArr4, 0, jArr2, i, jArr3, i2);
        int i3 = i + 3;
        int i4 = i + 4;
        int i5 = i2 + 3;
        int i6 = i2 + 4;
        mul128_no_simd_gf2x(jArr4, 6, jArr2[i3], jArr2[i4], jArr3[i5], jArr3[i6]);
        int i7 = i + 5;
        int i8 = i2 + 5;
        MUL64_NO_SIMD_GF2X(jArr4, 10, jArr2[i7], jArr3[i8]);
        int i9 = i + 6;
        int i10 = i2 + 6;
        long MUL32_NO_SIMD_GF2X = MUL32_NO_SIMD_GF2X(jArr2[i9], jArr3[i10]) ^ jArr4[11];
        jArr4[12] = MUL32_NO_SIMD_GF2X;
        jArr4[11] = MUL32_NO_SIMD_GF2X ^ jArr4[10];
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 11, jArr2[i9] ^ jArr2[i7], jArr3[i10] ^ jArr3[i8]);
        long j = jArr4[8] ^ jArr4[10];
        jArr4[8] = j;
        long j2 = jArr4[11] ^ jArr4[9];
        jArr4[11] = j2;
        jArr4[10] = jArr4[12] ^ j;
        long j3 = jArr4[6];
        long j4 = j ^ j3;
        jArr4[8] = j4;
        long j5 = jArr4[7];
        jArr4[9] = j2 ^ j5;
        jArr4[6] = jArr4[3] ^ j3;
        jArr4[7] = jArr4[4] ^ j5;
        jArr4[8] = j4 ^ jArr4[5];
        mul128_no_simd_gf2x_xor(jArr4, 8, jArr2[i7] ^ jArr2[i3], jArr2[i9] ^ jArr2[i4], jArr3[i8] ^ jArr3[i5], jArr3[i10] ^ jArr3[i6], jArr5);
        jArr[0] = jArr[0] ^ jArr4[0];
        jArr[1] = jArr[1] ^ jArr4[1];
        jArr[2] = jArr[2] ^ jArr4[2];
        long j6 = jArr[3];
        long j7 = jArr4[6];
        jArr[3] = j6 ^ (jArr4[0] ^ j7);
        long j8 = jArr[4];
        long j9 = jArr4[7];
        jArr[4] = j8 ^ (jArr4[1] ^ j9);
        long j10 = jArr[5];
        long j11 = jArr4[8];
        jArr[5] = j10 ^ (jArr4[2] ^ j11);
        long j12 = jArr[6];
        long j13 = jArr4[9];
        jArr[6] = j12 ^ (j7 ^ j13);
        long j14 = jArr[7];
        long j15 = jArr4[10];
        jArr[7] = j14 ^ (j9 ^ j15);
        long j16 = jArr[8];
        long j17 = jArr4[11];
        jArr[8] = j16 ^ (j11 ^ j17);
        long j18 = jArr[9];
        long j19 = jArr4[12];
        jArr[9] = j18 ^ (j13 ^ j19);
        jArr[10] = jArr[10] ^ j15;
        jArr[11] = jArr[11] ^ j17;
        jArr[12] = jArr[12] ^ j19;
        long j20 = jArr2[i] ^ jArr2[i3];
        long j21 = jArr2[i + 1] ^ jArr2[i4];
        long j22 = jArr2[i + 2] ^ jArr2[i7];
        long j23 = jArr2[i9];
        long j24 = jArr3[i2] ^ jArr3[i5];
        long j25 = jArr3[i2 + 1] ^ jArr3[i6];
        long j26 = jArr3[i2 + 2] ^ jArr3[i8];
        long j27 = jArr3[i10];
        mul128_no_simd_gf2x(jArr4, 0, j20, j21, j24, j25);
        MUL64_NO_SIMD_GF2X(jArr4, 4, j22, j26);
        long MUL32_NO_SIMD_GF2X2 = MUL32_NO_SIMD_GF2X(j23, j27) ^ jArr4[5];
        jArr4[6] = MUL32_NO_SIMD_GF2X2;
        jArr4[5] = MUL32_NO_SIMD_GF2X2 ^ jArr4[4];
        MUL64_NO_SIMD_GF2X_XOR(jArr4, 5, j22 ^ j23, j26 ^ j27);
        long j28 = jArr[3];
        long j29 = jArr4[0];
        jArr[3] = j28 ^ j29;
        long j30 = jArr[4];
        long j31 = jArr4[1];
        jArr[4] = j30 ^ j31;
        long j32 = jArr4[2] ^ jArr4[4];
        jArr4[2] = j32;
        long j33 = jArr4[3] ^ jArr4[5];
        jArr4[3] = j33;
        jArr[5] = jArr[5] ^ (j29 ^ j32);
        jArr[6] = jArr[6] ^ (j31 ^ j33);
        long j34 = jArr[7];
        long j35 = jArr4[6];
        jArr[7] = (j32 ^ j35) ^ j34;
        jArr[8] = jArr[8] ^ j33;
        jArr[9] = jArr[9] ^ j35;
        mul128_no_simd_gf2x_xor(jArr, 5, j20 ^ j22, j21 ^ j23, j24 ^ j26, j25 ^ j27, jArr4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul544_no_simd_gf2x(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4, long[] jArr5, long[] jArr6) {
        int i3 = i + 1;
        int i4 = i2 + 1;
        mul128_no_simd_gf2x(jArr, 0, jArr2[i], jArr2[i3], jArr3[i2], jArr3[i4]);
        int i5 = i + 2;
        int i6 = i + 3;
        int i7 = i2 + 2;
        int i8 = i2 + 3;
        mul128_no_simd_gf2x(jArr, 4, jArr2[i5], jArr2[i6], jArr3[i7], jArr3[i8]);
        long j = jArr[4] ^ jArr[2];
        jArr[4] = j;
        long j2 = jArr[5] ^ jArr[3];
        jArr[5] = j2;
        jArr[2] = jArr[0] ^ j;
        jArr[3] = jArr[1] ^ j2;
        jArr[4] = j ^ jArr[6];
        jArr[5] = jArr[7] ^ j2;
        mul128_no_simd_gf2x_xor(jArr, 2, jArr2[i5] ^ jArr2[i], jArr2[i6] ^ jArr2[i3], jArr3[i7] ^ jArr3[i2], jArr3[i8] ^ jArr3[i4], jArr6);
        int i9 = i + 4;
        int i10 = i2 + 4;
        mul288_no_simd_gf2x(jArr, 8, jArr2, i9, jArr3, i10, jArr6);
        long j3 = jArr[8] ^ jArr[4];
        jArr[8] = j3;
        long j4 = jArr[9] ^ jArr[5];
        jArr[9] = j4;
        long j5 = jArr[10] ^ jArr[6];
        jArr[10] = j5;
        long j6 = jArr[11] ^ jArr[7];
        jArr[11] = j6;
        jArr[4] = j3 ^ jArr[0];
        jArr[5] = j4 ^ jArr[1];
        jArr[6] = j5 ^ jArr[2];
        jArr[7] = j6 ^ jArr[3];
        long j7 = jArr[12];
        jArr[8] = j3 ^ j7;
        jArr[9] = jArr[13] ^ j4;
        jArr[10] = jArr[14] ^ j5;
        jArr[11] = j6 ^ jArr[15];
        jArr[12] = j7 ^ jArr[16];
        jArr4[0] = jArr2[i] ^ jArr2[i9];
        jArr4[1] = jArr2[i3] ^ jArr2[i + 5];
        jArr4[2] = jArr2[i5] ^ jArr2[i + 6];
        jArr4[3] = jArr2[i6] ^ jArr2[i + 7];
        jArr4[4] = jArr2[i + 8];
        jArr5[0] = jArr3[i2] ^ jArr3[i10];
        jArr5[1] = jArr3[i4] ^ jArr3[i2 + 5];
        jArr5[2] = jArr3[i7] ^ jArr3[i2 + 6];
        jArr5[3] = jArr3[i8] ^ jArr3[i2 + 7];
        jArr5[4] = jArr3[i2 + 8];
        mul288_no_simd_gf2x_xor(jArr, 4, jArr4, 0, jArr5, 0, jArr6);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void mul544_no_simd_gf2x_xor(long[] jArr, long[] jArr2, int i, long[] jArr3, int i2, long[] jArr4, long[] jArr5, long[] jArr6, long[] jArr7) {
        int i3 = i + 1;
        int i4 = i2 + 1;
        mul128_no_simd_gf2x(jArr6, 0, jArr2[i], jArr2[i3], jArr3[i2], jArr3[i4]);
        int i5 = i + 2;
        int i6 = i + 3;
        int i7 = i2 + 2;
        int i8 = i2 + 3;
        mul128_no_simd_gf2x(jArr6, 4, jArr2[i5], jArr2[i6], jArr3[i7], jArr3[i8]);
        long j = jArr6[4] ^ jArr6[2];
        jArr6[4] = j;
        long j2 = jArr6[5] ^ jArr6[3];
        jArr6[5] = j2;
        jArr6[2] = jArr6[0] ^ j;
        jArr6[3] = jArr6[1] ^ j2;
        jArr6[4] = j ^ jArr6[6];
        jArr6[5] = jArr6[7] ^ j2;
        mul128_no_simd_gf2x_xor(jArr6, 2, jArr2[i5] ^ jArr2[i], jArr2[i6] ^ jArr2[i3], jArr3[i7] ^ jArr3[i2], jArr3[i8] ^ jArr3[i4], jArr7);
        int i9 = i + 4;
        int i10 = i2 + 4;
        mul288_no_simd_gf2x(jArr6, 8, jArr2, i9, jArr3, i10, jArr7);
        long j3 = jArr6[8] ^ jArr6[4];
        jArr6[8] = j3;
        long j4 = jArr6[9] ^ jArr6[5];
        jArr6[9] = j4;
        long j5 = jArr6[10] ^ jArr6[6];
        jArr6[10] = j5;
        long j6 = jArr6[11] ^ jArr6[7];
        jArr6[11] = j6;
        jArr[0] = jArr[0] ^ jArr6[0];
        jArr[1] = jArr[1] ^ jArr6[1];
        jArr[2] = jArr[2] ^ jArr6[2];
        jArr[3] = jArr[3] ^ jArr6[3];
        jArr[4] = jArr[4] ^ (j3 ^ jArr6[0]);
        jArr[5] = jArr[5] ^ (j4 ^ jArr6[1]);
        jArr[6] = jArr[6] ^ (j5 ^ jArr6[2]);
        jArr[7] = jArr[7] ^ (j6 ^ jArr6[3]);
        long j7 = jArr[8];
        long j8 = jArr6[12];
        jArr[8] = j7 ^ (j3 ^ j8);
        long j9 = jArr[9];
        long j10 = jArr6[13];
        jArr[9] = j9 ^ (j4 ^ j10);
        long j11 = jArr[10];
        long j12 = jArr6[14];
        jArr[10] = j11 ^ (j5 ^ j12);
        long j13 = jArr[11];
        long j14 = jArr6[15];
        jArr[11] = j13 ^ (j6 ^ j14);
        long j15 = jArr[12];
        long j16 = jArr6[16];
        jArr[12] = j15 ^ (j8 ^ j16);
        jArr[13] = jArr[13] ^ j10;
        jArr[14] = jArr[14] ^ j12;
        jArr[15] = jArr[15] ^ j14;
        jArr[16] = jArr[16] ^ j16;
        jArr4[0] = jArr2[i] ^ jArr2[i9];
        jArr4[1] = jArr2[i3] ^ jArr2[i + 5];
        jArr4[2] = jArr2[i5] ^ jArr2[i + 6];
        jArr4[3] = jArr2[i6] ^ jArr2[i + 7];
        jArr4[4] = jArr2[i + 8];
        jArr5[0] = jArr3[i2] ^ jArr3[i10];
        jArr5[1] = jArr3[i4] ^ jArr3[i2 + 5];
        jArr5[2] = jArr3[i7] ^ jArr3[i2 + 6];
        jArr5[3] = jArr3[i8] ^ jArr3[i2 + 7];
        jArr5[4] = jArr3[i2 + 8];
        mul288_no_simd_gf2x_xor(jArr, 4, jArr4, 0, jArr5, 0, jArr6);
    }

    public abstract void mul_gf2x(Pointer pointer, Pointer pointer2, Pointer pointer3);

    public abstract void mul_gf2x_xor(Pointer pointer, Pointer pointer2, Pointer pointer3);

    public abstract void sqr_gf2x(long[] jArr, long[] jArr2, int i);
}