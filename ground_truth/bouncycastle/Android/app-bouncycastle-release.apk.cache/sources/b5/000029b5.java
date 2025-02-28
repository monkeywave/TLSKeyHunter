package org.bouncycastle.pqc.crypto.gemss;

/* loaded from: classes2.dex */
abstract class Rem_GF2n {

    /* renamed from: ki */
    protected int f1276ki;
    protected int ki64;
    protected long mask;

    /* loaded from: classes2.dex */
    public static class REM192_SPECIALIZED_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1277k3;
        private final int k364;
        private final int ki_k3;

        /* JADX INFO: Access modifiers changed from: package-private */
        public REM192_SPECIALIZED_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1277k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
            this.ki_k3 = i2 - i;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[2] >>> this.f1276ki) ^ (jArr2[3] << this.ki64);
            long j2 = (jArr2[3] >>> this.f1276ki) ^ (jArr2[4] << this.ki64);
            long j3 = (jArr2[4] >>> this.f1276ki) ^ (jArr2[5] << this.ki64);
            int i2 = this.k364;
            long j4 = (jArr2[1] ^ j2) ^ (j >>> i2);
            int i3 = this.f1277k3;
            jArr[i + 1] = j4 ^ (j2 << i3);
            jArr[i + 2] = (((j2 >>> i2) ^ (jArr2[2] ^ j3)) ^ (j3 << i3)) & this.mask;
            long j5 = j ^ (j3 >>> this.ki_k3);
            jArr[i] = (j5 << this.f1277k3) ^ (jArr2[0] ^ j5);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[2] >>> this.f1276ki) ^ (jArr2[3] << this.ki64);
            long j2 = (jArr2[3] >>> this.f1276ki) ^ (jArr2[4] << this.ki64);
            long j3 = (jArr2[4] >>> this.f1276ki) ^ (jArr2[5] << this.ki64);
            int i2 = i + 1;
            long j4 = jArr[i2];
            int i3 = this.k364;
            long j5 = (jArr2[1] ^ j2) ^ (j >>> i3);
            int i4 = this.f1277k3;
            jArr[i2] = j4 ^ (j5 ^ (j2 << i4));
            int i5 = i + 2;
            jArr[i5] = ((((j2 >>> i3) ^ (jArr2[2] ^ j3)) ^ (j3 << i4)) & this.mask) ^ jArr[i5];
            long j6 = j ^ (j3 >>> this.ki_k3);
            jArr[i] = ((j6 << this.f1277k3) ^ (jArr2[0] ^ j6)) ^ jArr[i];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM288_SPECIALIZED_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1278k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM288_SPECIALIZED_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1278k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
            this.k364ki = i4 + i2;
            this.k3_ki = i - i2;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64);
            long j2 = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            jArr[i + 2] = ((jArr2[2] ^ j2) ^ (j >>> this.k364)) ^ (j2 << this.f1278k3);
            long j3 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            jArr[i + 3] = ((j2 >>> this.k364) ^ (jArr2[3] ^ j3)) ^ (j3 << this.f1278k3);
            long j4 = jArr2[8] >>> this.f1276ki;
            long j5 = (((jArr2[4] >>> this.f1276ki) ^ (jArr2[5] << this.ki64)) ^ (j3 >>> this.k364ki)) ^ (j4 << this.k3_ki);
            long j6 = j3 >>> this.k364;
            jArr[i + 4] = ((j4 << this.f1278k3) ^ (j6 ^ (jArr2[4] ^ j4))) & this.mask;
            int i2 = this.f1278k3;
            jArr[i] = (jArr2[0] ^ j5) ^ (j5 << i2);
            jArr[i + 1] = ((j << i2) ^ (jArr2[1] ^ j)) ^ (j5 >>> this.k364);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64);
            long j2 = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            int i2 = i + 2;
            jArr[i2] = jArr[i2] ^ (((jArr2[2] ^ j2) ^ (j >>> this.k364)) ^ (j2 << this.f1278k3));
            long j3 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            int i3 = i + 3;
            jArr[i3] = (((j2 >>> this.k364) ^ (jArr2[3] ^ j3)) ^ (j3 << this.f1278k3)) ^ jArr[i3];
            long j4 = jArr2[8] >>> this.f1276ki;
            int i4 = i + 4;
            jArr[i4] = jArr[i4] ^ ((((jArr2[4] ^ j4) ^ (j3 >>> this.k364)) ^ (j4 << this.f1278k3)) & this.mask);
            long j5 = j3 >>> this.k364ki;
            long j6 = (j4 << this.k3_ki) ^ (j5 ^ ((jArr2[4] >>> this.f1276ki) ^ (jArr2[5] << this.ki64)));
            long j7 = jArr[i];
            int i5 = this.f1278k3;
            jArr[i] = j7 ^ ((jArr2[0] ^ j6) ^ (j6 << i5));
            int i6 = i + 1;
            jArr[i6] = (((j << i5) ^ (jArr2[1] ^ j)) ^ (j6 >>> this.k364)) ^ jArr[i6];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM384_SPECIALIZED358_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1279k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM384_SPECIALIZED358_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1279k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
            this.k364ki = i4 + i2;
            this.k3_ki = i - i2;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            long j2 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            jArr[i + 2] = ((jArr2[2] ^ j2) ^ (j >>> this.k364)) ^ (j2 << this.f1279k3);
            long j3 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            jArr[i + 3] = ((j2 >>> this.k364) ^ (jArr2[3] ^ j3)) ^ (j3 << this.f1279k3);
            long j4 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            jArr[i + 4] = ((j3 >>> this.k364) ^ (jArr2[4] ^ j4)) ^ (j4 << this.f1279k3);
            long j5 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j6 = (((jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64)) ^ (j4 >>> this.k364ki)) ^ (j5 << this.k3_ki);
            jArr[i + 5] = ((j4 >>> this.k364) ^ (j5 ^ jArr2[5])) & this.mask;
            int i2 = this.f1279k3;
            jArr[i] = (jArr2[0] ^ j6) ^ (j6 << i2);
            jArr[i + 1] = (j << i2) ^ ((jArr2[1] ^ j) ^ (j6 >>> this.k364));
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            long j2 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            int i2 = i + 2;
            jArr[i2] = jArr[i2] ^ (((jArr2[2] ^ j2) ^ (j >>> this.k364)) ^ (j2 << this.f1279k3));
            long j3 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            int i3 = i + 3;
            jArr[i3] = (((j2 >>> this.k364) ^ (jArr2[3] ^ j3)) ^ (j3 << this.f1279k3)) ^ jArr[i3];
            long j4 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            int i4 = i + 4;
            jArr[i4] = (((j3 >>> this.k364) ^ (jArr2[4] ^ j4)) ^ (j4 << this.f1279k3)) ^ jArr[i4];
            long j5 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            int i5 = i + 5;
            jArr[i5] = jArr[i5] ^ (((jArr2[5] ^ j5) ^ (j4 >>> this.k364)) & this.mask);
            long j6 = ((j4 >>> this.k364ki) ^ ((jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64))) ^ (j5 << this.k3_ki);
            long j7 = jArr[i];
            int i6 = this.f1279k3;
            jArr[i] = j7 ^ ((jArr2[0] ^ j6) ^ (j6 << i6));
            int i7 = i + 1;
            long j8 = j << i6;
            jArr[i7] = (j8 ^ ((j6 >>> this.k364) ^ (jArr2[1] ^ j))) ^ jArr[i7];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM384_SPECIALIZED_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1280k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM384_SPECIALIZED_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1280k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
            this.k364ki = i4 + i2;
            this.k3_ki = i - i2;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            long j2 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j3 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j4 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j5 = (((jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64)) ^ (j2 >>> this.k364ki)) ^ (j3 << this.k3_ki);
            long j6 = (((jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64)) ^ (j3 >>> this.k364ki)) ^ (j4 << this.k3_ki);
            jArr[i] = jArr2[0] ^ j5;
            int i2 = this.f1280k3;
            jArr[i + 1] = (jArr2[1] ^ j6) ^ (j5 << i2);
            int i3 = this.k364;
            jArr[i + 2] = ((j5 >>> i3) ^ (jArr2[2] ^ j)) ^ (j6 << i2);
            jArr[i + 3] = ((jArr2[3] ^ j2) ^ (j6 >>> i3)) ^ (j << i2);
            jArr[i + 4] = ((j >>> i3) ^ (j3 ^ jArr2[4])) ^ (j2 << i2);
            jArr[i + 5] = ((j2 >>> i3) ^ (jArr2[5] ^ j4)) & this.mask;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            long j2 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j3 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j4 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j5 = (((jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64)) ^ (j2 >>> this.k364ki)) ^ (j3 << this.k3_ki);
            long j6 = (((jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64)) ^ (j3 >>> this.k364ki)) ^ (j4 << this.k3_ki);
            jArr[i] = jArr[i] ^ (jArr2[0] ^ j5);
            int i2 = i + 1;
            long j7 = jArr[i2];
            int i3 = this.f1280k3;
            jArr[i2] = j7 ^ ((jArr2[1] ^ j6) ^ (j5 << i3));
            int i4 = i + 2;
            long j8 = jArr[i4];
            int i5 = this.k364;
            jArr[i4] = (((jArr2[2] ^ j) ^ (j5 >>> i5)) ^ (j6 << i3)) ^ j8;
            int i6 = i + 3;
            jArr[i6] = jArr[i6] ^ (((j6 >>> i5) ^ (jArr2[3] ^ j2)) ^ (j << i3));
            int i7 = i + 4;
            jArr[i7] = (((j >>> i5) ^ (j3 ^ jArr2[4])) ^ (j2 << i3)) ^ jArr[i7];
            int i8 = i + 5;
            jArr[i8] = (((j2 >>> i5) ^ (jArr2[5] ^ j4)) & this.mask) ^ jArr[i8];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM384_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1281k3;
        private final int k364;
        private final int ki_k3;

        public REM384_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1281k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
            this.ki_k3 = i2 - i;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64);
            long j2 = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            long j3 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            long j4 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j5 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j6 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j7 = (j6 >>> this.ki_k3) ^ j;
            int i2 = this.f1281k3;
            jArr[i] = (jArr2[0] ^ j7) ^ (j7 << i2);
            int i3 = this.k364;
            jArr[i + 1] = ((jArr2[1] ^ j2) ^ (j >>> i3)) ^ (j2 << i2);
            jArr[i + 2] = ((jArr2[2] ^ j3) ^ (j2 >>> i3)) ^ (j3 << i2);
            jArr[i + 3] = ((jArr2[3] ^ j4) ^ (j3 >>> i3)) ^ (j4 << i2);
            jArr[i + 4] = ((jArr2[4] ^ j5) ^ (j4 >>> i3)) ^ (j5 << i2);
            jArr[i + 5] = ((j6 << i2) ^ ((jArr2[5] ^ j6) ^ (j5 >>> i3))) & this.mask;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[5] >>> this.f1276ki) ^ (jArr2[6] << this.ki64);
            long j2 = (jArr2[6] >>> this.f1276ki) ^ (jArr2[7] << this.ki64);
            long j3 = (jArr2[7] >>> this.f1276ki) ^ (jArr2[8] << this.ki64);
            long j4 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j5 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j6 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j7 = (j6 >>> this.ki_k3) ^ j;
            long j8 = jArr[i];
            int i2 = this.f1281k3;
            jArr[i] = j8 ^ ((jArr2[0] ^ j7) ^ (j7 << i2));
            int i3 = i + 1;
            long j9 = jArr[i3];
            int i4 = this.k364;
            jArr[i3] = j9 ^ (((jArr2[1] ^ j2) ^ (j >>> i4)) ^ (j2 << i2));
            int i5 = i + 2;
            jArr[i5] = jArr[i5] ^ (((jArr2[2] ^ j3) ^ (j2 >>> i4)) ^ (j3 << i2));
            int i6 = i + 3;
            jArr[i6] = jArr[i6] ^ (((jArr2[3] ^ j4) ^ (j3 >>> i4)) ^ (j4 << i2));
            int i7 = i + 4;
            jArr[i7] = jArr[i7] ^ (((jArr2[4] ^ j5) ^ (j4 >>> i4)) ^ (j5 << i2));
            int i8 = i + 5;
            jArr[i8] = (((j6 << i2) ^ ((jArr2[5] ^ j6) ^ (j5 >>> i4))) & this.mask) ^ jArr[i8];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM402_SPECIALIZED_TRINOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k3 */
        private final int f1282k3;
        private final int k364;

        public REM402_SPECIALIZED_TRINOMIAL_GF2X(int i, int i2, int i3, int i4, long j) {
            this.f1282k3 = i;
            this.f1276ki = i2;
            this.ki64 = i3;
            this.k364 = i4;
            this.mask = j;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j2 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j3 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            long j4 = jArr2[12] >>> this.f1276ki;
            long j5 = (((j >>> 39) ^ (j2 << 25)) ^ (jArr2[6] >>> this.f1276ki)) ^ (jArr2[7] << this.ki64);
            long j6 = (((j2 >>> 39) ^ (j3 << 25)) ^ (jArr2[7] >>> this.f1276ki)) ^ (jArr2[8] << this.ki64);
            long j7 = (((j3 >>> 39) ^ (j4 << 25)) ^ (jArr2[8] >>> this.f1276ki)) ^ (jArr2[9] << this.ki64);
            jArr[i] = jArr2[0] ^ j5;
            jArr[i + 1] = jArr2[1] ^ j6;
            int i2 = this.f1282k3;
            jArr[i + 2] = (jArr2[2] ^ j7) ^ (j5 << i2);
            int i3 = this.k364;
            jArr[i + 3] = ((jArr2[3] ^ j) ^ (j5 >>> i3)) ^ (j6 << i2);
            jArr[i + 4] = ((j2 ^ jArr2[4]) ^ (j6 >>> i3)) ^ (j7 << i2);
            jArr[i + 5] = ((jArr2[5] ^ j3) ^ (j7 >>> i3)) ^ (j << i2);
            jArr[i + 6] = ((j >>> i3) ^ (jArr2[6] ^ j4)) & this.mask;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j2 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j3 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            long j4 = jArr2[12] >>> this.f1276ki;
            long j5 = (((j >>> 39) ^ (j2 << 25)) ^ (jArr2[6] >>> this.f1276ki)) ^ (jArr2[7] << this.ki64);
            long j6 = (((j2 >>> 39) ^ (j3 << 25)) ^ (jArr2[7] >>> this.f1276ki)) ^ (jArr2[8] << this.ki64);
            long j7 = (((j3 >>> 39) ^ (j4 << 25)) ^ (jArr2[8] >>> this.f1276ki)) ^ (jArr2[9] << this.ki64);
            jArr[i] = jArr[i] ^ (jArr2[0] ^ j5);
            int i2 = i + 1;
            jArr[i2] = jArr[i2] ^ (jArr2[1] ^ j6);
            int i3 = i + 2;
            long j8 = jArr[i3];
            int i4 = this.f1282k3;
            jArr[i3] = j8 ^ ((jArr2[2] ^ j7) ^ (j5 << i4));
            int i5 = i + 3;
            long j9 = jArr[i5];
            int i6 = this.k364;
            jArr[i5] = j9 ^ (((jArr2[3] ^ j) ^ (j5 >>> i6)) ^ (j6 << i4));
            int i7 = i + 4;
            jArr[i7] = (((jArr2[4] ^ j2) ^ (j6 >>> i6)) ^ (j7 << i4)) ^ jArr[i7];
            int i8 = i + 5;
            jArr[i8] = jArr[i8] ^ (((j3 ^ jArr2[5]) ^ (j7 >>> i6)) ^ (j << i4));
            int i9 = i + 6;
            jArr[i9] = (((j >>> i6) ^ (jArr2[6] ^ j4)) & this.mask) ^ jArr[i9];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM544_PENTANOMIAL_GF2X extends Rem_GF2n {

        /* renamed from: k1 */
        private final int f1283k1;
        private final int k164;

        /* renamed from: k2 */
        private final int f1284k2;
        private final int k264;

        /* renamed from: k3 */
        private final int f1285k3;
        private final int k364;
        private final int ki_k1;
        private final int ki_k2;
        private final int ki_k3;

        public REM544_PENTANOMIAL_GF2X(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, long j) {
            this.f1283k1 = i;
            this.f1284k2 = i2;
            this.f1285k3 = i3;
            this.f1276ki = i4;
            this.ki64 = i5;
            this.k164 = i6;
            this.k264 = i7;
            this.k364 = i8;
            this.mask = j;
            this.ki_k3 = i4 - i3;
            this.ki_k2 = i4 - i2;
            this.ki_k1 = i4 - i;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = jArr2[16] >>> this.f1276ki;
            long j2 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j3 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            long j4 = (jArr2[1] ^ j3) ^ (j2 >>> this.k164);
            int i2 = this.f1283k1;
            long j5 = (j4 ^ (j3 << i2)) ^ (j2 >>> this.k264);
            int i3 = this.f1284k2;
            long j6 = (j5 ^ (j3 << i3)) ^ (j2 >>> this.k364);
            int i4 = this.f1285k3;
            jArr[i + 1] = j6 ^ (j3 << i4);
            long j7 = j2 ^ (((j >>> this.ki_k3) ^ (j >>> this.ki_k2)) ^ (j >>> this.ki_k1));
            jArr[i] = (j7 << i4) ^ (((jArr2[0] ^ j7) ^ (j7 << i2)) ^ (j7 << i3));
            long j8 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            jArr[i + 2] = ((j3 >>> this.k364) ^ (((((jArr2[2] ^ j8) ^ (j3 >>> this.k164)) ^ (j8 << this.f1283k1)) ^ (j3 >>> this.k264)) ^ (j8 << this.f1284k2))) ^ (j8 << this.f1285k3);
            long j9 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            jArr[i + 3] = ((j8 >>> this.k364) ^ (((((jArr2[3] ^ j9) ^ (j8 >>> this.k164)) ^ (j9 << this.f1283k1)) ^ (j8 >>> this.k264)) ^ (j9 << this.f1284k2))) ^ (j9 << this.f1285k3);
            long j10 = (jArr2[12] >>> this.f1276ki) ^ (jArr2[13] << this.ki64);
            jArr[i + 4] = ((j9 >>> this.k364) ^ (((((jArr2[4] ^ j10) ^ (j9 >>> this.k164)) ^ (j10 << this.f1283k1)) ^ (j9 >>> this.k264)) ^ (j10 << this.f1284k2))) ^ (j10 << this.f1285k3);
            long j11 = (jArr2[13] >>> this.f1276ki) ^ (jArr2[14] << this.ki64);
            jArr[i + 5] = ((j10 >>> this.k364) ^ (((((jArr2[5] ^ j11) ^ (j10 >>> this.k164)) ^ (j11 << this.f1283k1)) ^ (j10 >>> this.k264)) ^ (j11 << this.f1284k2))) ^ (j11 << this.f1285k3);
            long j12 = (jArr2[14] >>> this.f1276ki) ^ (jArr2[15] << this.ki64);
            jArr[i + 6] = ((j11 >>> this.k364) ^ (((((jArr2[6] ^ j12) ^ (j11 >>> this.k164)) ^ (j12 << this.f1283k1)) ^ (j11 >>> this.k264)) ^ (j12 << this.f1284k2))) ^ (j12 << this.f1285k3);
            long j13 = (jArr2[15] >>> this.f1276ki) ^ (jArr2[16] << this.ki64);
            int i5 = this.k164;
            long j14 = (jArr2[7] ^ j13) ^ (j12 >>> i5);
            int i6 = this.f1283k1;
            int i7 = this.k264;
            int i8 = this.f1284k2;
            int i9 = this.k364;
            long j15 = (j12 >>> i9) ^ (((j14 ^ (j13 << i6)) ^ (j12 >>> i7)) ^ (j13 << i8));
            int i10 = this.f1285k3;
            jArr[i + 7] = j15 ^ (j13 << i10);
            jArr[i + 8] = ((j << i10) ^ ((((((jArr2[8] ^ j) ^ (j13 >>> i5)) ^ (j << i6)) ^ (j13 >>> i7)) ^ (j << i8)) ^ (j13 >>> i9))) & this.mask;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = jArr2[16] >>> this.f1276ki;
            long j2 = (jArr2[8] >>> this.f1276ki) ^ (jArr2[9] << this.ki64);
            long j3 = (jArr2[9] >>> this.f1276ki) ^ (jArr2[10] << this.ki64);
            int i2 = i + 1;
            long j4 = jArr[i2];
            long j5 = (jArr2[1] ^ j3) ^ (j2 >>> this.k164);
            int i3 = this.f1283k1;
            int i4 = this.f1284k2;
            int i5 = this.f1285k3;
            jArr[i2] = j4 ^ (((((j5 ^ (j3 << i3)) ^ (j2 >>> this.k264)) ^ (j3 << i4)) ^ (j2 >>> this.k364)) ^ (j3 << i5));
            long j6 = j2 ^ (((j >>> this.ki_k3) ^ (j >>> this.ki_k2)) ^ (j >>> this.ki_k1));
            jArr[i] = ((j6 << i5) ^ (((jArr2[0] ^ j6) ^ (j6 << i3)) ^ (j6 << i4))) ^ jArr[i];
            long j7 = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            int i6 = i + 2;
            jArr[i6] = (((j3 >>> this.k364) ^ (((((jArr2[2] ^ j7) ^ (j3 >>> this.k164)) ^ (j7 << this.f1283k1)) ^ (j3 >>> this.k264)) ^ (j7 << this.f1284k2))) ^ (j7 << this.f1285k3)) ^ jArr[i6];
            long j8 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            int i7 = i + 3;
            jArr[i7] = (((j7 >>> this.k364) ^ (((((jArr2[3] ^ j8) ^ (j7 >>> this.k164)) ^ (j8 << this.f1283k1)) ^ (j7 >>> this.k264)) ^ (j8 << this.f1284k2))) ^ (j8 << this.f1285k3)) ^ jArr[i7];
            long j9 = (jArr2[12] >>> this.f1276ki) ^ (jArr2[13] << this.ki64);
            int i8 = i + 4;
            jArr[i8] = (((j8 >>> this.k364) ^ (((((jArr2[4] ^ j9) ^ (j8 >>> this.k164)) ^ (j9 << this.f1283k1)) ^ (j8 >>> this.k264)) ^ (j9 << this.f1284k2))) ^ (j9 << this.f1285k3)) ^ jArr[i8];
            long j10 = (jArr2[13] >>> this.f1276ki) ^ (jArr2[14] << this.ki64);
            int i9 = i + 5;
            jArr[i9] = (((j9 >>> this.k364) ^ (((((jArr2[5] ^ j10) ^ (j9 >>> this.k164)) ^ (j10 << this.f1283k1)) ^ (j9 >>> this.k264)) ^ (j10 << this.f1284k2))) ^ (j10 << this.f1285k3)) ^ jArr[i9];
            long j11 = (jArr2[14] >>> this.f1276ki) ^ (jArr2[15] << this.ki64);
            int i10 = i + 6;
            jArr[i10] = (((j10 >>> this.k364) ^ (((((jArr2[6] ^ j11) ^ (j10 >>> this.k164)) ^ (j11 << this.f1283k1)) ^ (j10 >>> this.k264)) ^ (j11 << this.f1284k2))) ^ (j11 << this.f1285k3)) ^ jArr[i10];
            long j12 = (jArr2[15] >>> this.f1276ki) ^ (jArr2[16] << this.ki64);
            int i11 = i + 7;
            long j13 = jArr[i11];
            int i12 = this.k164;
            long j14 = (jArr2[7] ^ j12) ^ (j11 >>> i12);
            int i13 = this.f1283k1;
            int i14 = this.k264;
            int i15 = this.f1284k2;
            int i16 = this.k364;
            long j15 = j11 >>> i16;
            long j16 = j15 ^ (((j14 ^ (j12 << i13)) ^ (j11 >>> i14)) ^ (j12 << i15));
            int i17 = this.f1285k3;
            jArr[i11] = (j16 ^ (j12 << i17)) ^ j13;
            int i18 = i + 8;
            long j17 = j << i17;
            jArr[i18] = ((j17 ^ ((j12 >>> i16) ^ (((((jArr2[8] ^ j) ^ (j12 >>> i12)) ^ (j << i13)) ^ (j12 >>> i14)) ^ (j << i15)))) & this.mask) ^ jArr[i18];
        }
    }

    /* loaded from: classes2.dex */
    public static class REM544_PENTANOMIAL_K3_IS_128_GF2X extends Rem_GF2n {

        /* renamed from: k1 */
        private final int f1286k1;
        private final int k164;

        /* renamed from: k2 */
        private final int f1287k2;
        private final int k264;

        public REM544_PENTANOMIAL_K3_IS_128_GF2X(int i, int i2, int i3, int i4, int i5, int i6, long j) {
            this.f1286k1 = i;
            this.f1287k2 = i2;
            this.f1276ki = i3;
            this.ki64 = i4;
            this.k164 = i5;
            this.k264 = i6;
            this.mask = j;
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j2 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            long j3 = (jArr2[12] >>> this.f1276ki) ^ (jArr2[13] << this.ki64);
            jArr[i + 4] = (((((jArr2[4] ^ j3) ^ j) ^ (j2 >>> this.k164)) ^ (j3 << this.f1286k1)) ^ (j2 >>> this.k264)) ^ (j3 << this.f1287k2);
            long j4 = (jArr2[13] >>> this.f1276ki) ^ (jArr2[14] << this.ki64);
            jArr[i + 5] = (((((jArr2[5] ^ j4) ^ j2) ^ (j3 >>> this.k164)) ^ (j4 << this.f1286k1)) ^ (j3 >>> this.k264)) ^ (j4 << this.f1287k2);
            long j5 = (jArr2[14] >>> this.f1276ki) ^ (jArr2[15] << this.ki64);
            jArr[i + 6] = ((((j3 ^ (jArr2[6] ^ j5)) ^ (j4 >>> this.k164)) ^ (j5 << this.f1286k1)) ^ (j4 >>> this.k264)) ^ (j5 << this.f1287k2);
            long j6 = (jArr2[15] >>> this.f1276ki) ^ (jArr2[16] << this.ki64);
            jArr[i + 7] = ((((j4 ^ (jArr2[7] ^ j6)) ^ (j5 >>> this.k164)) ^ (j6 << this.f1286k1)) ^ (j5 >>> this.k264)) ^ (j6 << this.f1287k2);
            long j7 = jArr2[16] >>> this.f1276ki;
            jArr[i + 8] = this.mask & ((((((jArr2[8] ^ j7) ^ j5) ^ (j6 >>> this.k164)) ^ (j7 << this.f1286k1)) ^ (j6 >>> this.k264)) ^ (j7 << this.f1287k2));
            long j8 = (((jArr2[8] ^ j5) >>> this.f1276ki) ^ ((jArr2[9] ^ j6) << this.ki64)) ^ (jArr2[16] >>> this.k264);
            long j9 = ((j6 ^ jArr2[9]) >>> this.f1276ki) ^ ((j7 ^ jArr2[10]) << this.ki64);
            int i2 = this.f1286k1;
            long j10 = (jArr2[0] ^ j8) ^ (j8 << i2);
            int i3 = this.f1287k2;
            jArr[i] = j10 ^ (j8 << i3);
            int i4 = this.k164;
            long j11 = ((jArr2[1] ^ j9) ^ (j8 >>> i4)) ^ (j9 << i2);
            int i5 = this.k264;
            jArr[i + 1] = (j11 ^ (j8 >>> i5)) ^ (j9 << i3);
            jArr[i + 2] = ((((j8 ^ (jArr2[2] ^ j)) ^ (j9 >>> i4)) ^ (j << i2)) ^ (j9 >>> i5)) ^ (j << i3);
            jArr[i + 3] = ((j >>> i5) ^ (((j9 ^ (jArr2[3] ^ j2)) ^ (j >>> i4)) ^ (j2 << i2))) ^ (j2 << i3);
        }

        @Override // org.bouncycastle.pqc.crypto.gemss.Rem_GF2n
        public void rem_gf2n_xor(long[] jArr, int i, long[] jArr2) {
            long j = (jArr2[10] >>> this.f1276ki) ^ (jArr2[11] << this.ki64);
            long j2 = (jArr2[11] >>> this.f1276ki) ^ (jArr2[12] << this.ki64);
            long j3 = (jArr2[12] >>> this.f1276ki) ^ (jArr2[13] << this.ki64);
            int i2 = i + 4;
            jArr[i2] = jArr[i2] ^ ((((((jArr2[4] ^ j3) ^ j) ^ (j2 >>> this.k164)) ^ (j3 << this.f1286k1)) ^ (j2 >>> this.k264)) ^ (j3 << this.f1287k2));
            long j4 = (jArr2[13] >>> this.f1276ki) ^ (jArr2[14] << this.ki64);
            int i3 = i + 5;
            jArr[i3] = jArr[i3] ^ ((((((jArr2[5] ^ j4) ^ j2) ^ (j3 >>> this.k164)) ^ (j4 << this.f1286k1)) ^ (j3 >>> this.k264)) ^ (j4 << this.f1287k2));
            long j5 = (jArr2[14] >>> this.f1276ki) ^ (jArr2[15] << this.ki64);
            int i4 = i + 6;
            jArr[i4] = ((((((jArr2[6] ^ j5) ^ j3) ^ (j4 >>> this.k164)) ^ (j5 << this.f1286k1)) ^ (j4 >>> this.k264)) ^ (j5 << this.f1287k2)) ^ jArr[i4];
            long j6 = (jArr2[15] >>> this.f1276ki) ^ (jArr2[16] << this.ki64);
            int i5 = i + 7;
            jArr[i5] = ((((((jArr2[7] ^ j6) ^ j4) ^ (j5 >>> this.k164)) ^ (j6 << this.f1286k1)) ^ (j5 >>> this.k264)) ^ (j6 << this.f1287k2)) ^ jArr[i5];
            long j7 = jArr2[16] >>> this.f1276ki;
            int i6 = i + 8;
            jArr[i6] = (((((((jArr2[8] ^ j7) ^ j5) ^ (j6 >>> this.k164)) ^ (j7 << this.f1286k1)) ^ (j6 >>> this.k264)) ^ (j7 << this.f1287k2)) & this.mask) ^ jArr[i6];
            long j8 = (((jArr2[8] ^ j5) >>> this.f1276ki) ^ ((jArr2[9] ^ j6) << this.ki64)) ^ (jArr2[16] >>> this.k264);
            long j9 = ((j6 ^ jArr2[9]) >>> this.f1276ki) ^ ((j7 ^ jArr2[10]) << this.ki64);
            long j10 = jArr[i];
            int i7 = this.f1286k1;
            long j11 = (jArr2[0] ^ j8) ^ (j8 << i7);
            int i8 = this.f1287k2;
            jArr[i] = j10 ^ (j11 ^ (j8 << i8));
            int i9 = i + 1;
            long j12 = jArr[i9];
            int i10 = this.k164;
            long j13 = ((jArr2[1] ^ j9) ^ (j8 >>> i10)) ^ (j9 << i7);
            int i11 = this.k264;
            jArr[i9] = j12 ^ ((j13 ^ (j8 >>> i11)) ^ (j9 << i8));
            int i12 = i + 2;
            jArr[i12] = (((((j8 ^ (jArr2[2] ^ j)) ^ (j9 >>> i10)) ^ (j << i7)) ^ (j9 >>> i11)) ^ (j << i8)) ^ jArr[i12];
            int i13 = i + 3;
            jArr[i13] = (((j >>> i11) ^ (((j9 ^ (jArr2[3] ^ j2)) ^ (j >>> i10)) ^ (j2 << i7))) ^ (j2 << i8)) ^ jArr[i13];
        }
    }

    Rem_GF2n() {
    }

    public abstract void rem_gf2n(long[] jArr, int i, long[] jArr2);

    public abstract void rem_gf2n_xor(long[] jArr, int i, long[] jArr2);
}