package org.bouncycastle.math.p016ec.rfc8032;

import androidx.core.location.LocationRequestCompat;
import kotlinx.coroutines.internal.LockFreeTaskQueueCore;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat448;
import org.bouncycastle.tls.CipherSuite;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Scalar448 */
/* loaded from: classes2.dex */
abstract class Scalar448 {
    private static final int L4_0 = 43969588;
    private static final int L4_1 = 30366549;
    private static final int L4_2 = 163752818;
    private static final int L4_3 = 258169998;
    private static final int L4_4 = 96434764;
    private static final int L4_5 = 227822194;
    private static final int L4_6 = 149865618;
    private static final int L4_7 = 550336261;
    private static final int L_0 = 78101261;
    private static final int L_1 = 141809365;
    private static final int L_2 = 175155932;
    private static final int L_3 = 64542499;
    private static final int L_4 = 158326419;
    private static final int L_5 = 191173276;
    private static final int L_6 = 104575268;
    private static final int L_7 = 137584065;
    private static final long M26L = 67108863;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int SCALAR_BYTES = 57;
    static final int SIZE = 14;
    private static final int TARGET_LENGTH = 447;

    /* renamed from: L */
    private static final int[] f1137L = {-1420278541, 595116690, -1916432555, 560775794, -1361693040, -1001465015, 2093622249, -1, -1, -1, -1, -1, -1, LockFreeTaskQueueCore.MAX_CAPACITY_MASK};
    private static final int[] LSq = {463601321, -1045562440, 1239460018, -1189350089, -412821483, 1160071467, -1564970643, 1256291574, -1170454588, -240530412, 2118977290, -1845154869, -1618855054, -1019204973, 1437344377, -1849925303, 1189267370, 280387897, -680846520, -500732508, -1100672524, -1, -1, -1, -1, -1, -1, 268435455};

    Scalar448() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean checkVar(byte[] bArr, int[] iArr) {
        if (bArr[56] != 0) {
            return false;
        }
        decode(bArr, iArr);
        return !Nat.gte(14, iArr, f1137L);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void decode(byte[] bArr, int[] iArr) {
        Codec.decode32(bArr, 0, iArr, 0, 14);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getOrderWnafVar(int i, byte[] bArr) {
        Wnaf.getSignedVar(f1137L, i, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void multiply225Var(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] iArr4 = new int[22];
        Nat.mul(iArr2, 0, 8, iArr, 0, 14, iArr4, 0);
        if (iArr2[7] < 0) {
            Nat.addTo(14, f1137L, 0, iArr4, 8);
            Nat.subFrom(14, iArr, 0, iArr4, 8);
        }
        byte[] bArr = new byte[88];
        Codec.encode32(iArr4, 0, 22, bArr, 0);
        decode(reduce704(bArr), iArr3);
    }

    static byte[] reduce704(byte[] bArr) {
        long decode24 = Codec.decode24(bArr, 60) << 4;
        long j = decode24 & 4294967295L;
        long decode32 = Codec.decode32(bArr, 70);
        long j2 = decode32 & 4294967295L;
        long decode322 = Codec.decode32(bArr, 84);
        long j3 = (decode322 & 4294967295L) >>> 28;
        long j4 = decode322 & M28L;
        long decode323 = (Codec.decode32(bArr, 49) & 4294967295L) + (j3 * 227822194);
        long decode242 = ((Codec.decode24(bArr, 53) << 4) & 4294967295L) + (j3 * 149865618);
        long decode324 = (Codec.decode32(bArr, 56) & 4294967295L) + (j3 * 550336261);
        long decode243 = ((Codec.decode24(bArr, 74) << 4) & 4294967295L) + (j2 >>> 28);
        long j5 = decode32 & M28L;
        long decode325 = (Codec.decode32(bArr, 77) & 4294967295L) + (decode243 >>> 28);
        long j6 = decode243 & M28L;
        long decode244 = ((Codec.decode24(bArr, 81) << 4) & 4294967295L) + (decode325 >>> 28);
        long j7 = decode325 & M28L;
        long j8 = j4 + (decode244 >>> 28);
        long j9 = decode244 & M28L;
        long decode326 = (Codec.decode32(bArr, 28) & 4294967295L) + (j8 * 43969588);
        long decode245 = ((Codec.decode24(bArr, 32) << 4) & 4294967295L) + (j3 * 43969588) + (j8 * 30366549);
        long decode327 = (Codec.decode32(bArr, 35) & 4294967295L) + (j3 * 30366549) + (j8 * 163752818);
        long decode246 = ((Codec.decode24(bArr, 39) << 4) & 4294967295L) + (j3 * 163752818) + (j8 * 258169998);
        long decode247 = ((Codec.decode24(bArr, 46) << 4) & 4294967295L) + (j3 * 96434764) + (j8 * 227822194);
        long j10 = decode323 + (j8 * 149865618) + (j9 * 550336261);
        long decode328 = (Codec.decode32(bArr, 21) & 4294967295L) + (j7 * 43969588);
        long decode329 = (Codec.decode32(bArr, 63) & 4294967295L) + (j >>> 28);
        long j11 = decode24 & M28L;
        long decode248 = ((Codec.decode24(bArr, 67) << 4) & 4294967295L) + (decode329 >>> 28);
        long j12 = decode329 & M28L;
        long j13 = j5 + (decode248 >>> 28);
        long j14 = decode248 & M28L;
        long j15 = j6 + (j13 >>> 28);
        long j16 = j13 & M28L;
        long decode3210 = (Codec.decode32(bArr, 42) & 4294967295L) + (j3 * 258169998) + (j8 * 96434764) + (j9 * 227822194) + (j7 * 149865618) + (j15 * 550336261);
        long j17 = decode242 + (j8 * 550336261) + (j10 >>> 28);
        long j18 = j10 & M28L;
        long j19 = decode324 + (j17 >>> 28);
        long j20 = j17 & M28L;
        long j21 = j11 + (j19 >>> 28);
        long j22 = j19 & M28L;
        long j23 = j12 + (j21 >>> 28);
        long j24 = j21 & M28L;
        long j25 = j17 & M26L;
        long j26 = (j22 * 4) + (j20 >>> 26) + 1;
        long decode3211 = (Codec.decode32(bArr, 0) & 4294967295L) + (78101261 * j26);
        long decode249 = ((Codec.decode24(bArr, 4) << 4) & 4294967295L) + (43969588 * j24) + (141809365 * j26) + (decode3211 >>> 28);
        long j27 = decode3211 & M28L;
        long decode3212 = (Codec.decode32(bArr, 7) & 4294967295L) + (j23 * 43969588) + (30366549 * j24) + (175155932 * j26) + (decode249 >>> 28);
        long j28 = decode249 & M28L;
        long decode2410 = ((Codec.decode24(bArr, 11) << 4) & 4294967295L) + (j14 * 43969588) + (j23 * 30366549) + (163752818 * j24) + (64542499 * j26) + (decode3212 >>> 28);
        long j29 = decode3212 & M28L;
        long decode3213 = (Codec.decode32(bArr, 14) & 4294967295L) + (j16 * 43969588) + (j14 * 30366549) + (j23 * 163752818) + (258169998 * j24) + (158326419 * j26) + (decode2410 >>> 28);
        long j30 = decode2410 & M28L;
        long decode2411 = ((Codec.decode24(bArr, 18) << 4) & 4294967295L) + (j15 * 43969588) + (j16 * 30366549) + (j14 * 163752818) + (j23 * 258169998) + (96434764 * j24) + (191173276 * j26) + (decode3213 >>> 28);
        long j31 = decode3213 & M28L;
        long j32 = decode328 + (j15 * 30366549) + (j16 * 163752818) + (j14 * 258169998) + (j23 * 96434764) + (227822194 * j24) + (104575268 * j26) + (decode2411 >>> 28);
        long j33 = decode2411 & M28L;
        long decode2412 = ((Codec.decode24(bArr, 25) << 4) & 4294967295L) + (j9 * 43969588) + (j7 * 30366549) + (j15 * 163752818) + (j16 * 258169998) + (j14 * 96434764) + (j23 * 227822194) + (149865618 * j24) + (j26 * 137584065) + (j32 >>> 28);
        long j34 = j32 & M28L;
        long j35 = decode326 + (j9 * 30366549) + (j7 * 163752818) + (j15 * 258169998) + (j16 * 96434764) + (j14 * 227822194) + (j23 * 149865618) + (j24 * 550336261) + (decode2412 >>> 28);
        long j36 = decode2412 & M28L;
        long j37 = decode245 + (j9 * 163752818) + (j7 * 258169998) + (j15 * 96434764) + (j16 * 227822194) + (j14 * 149865618) + (j23 * 550336261) + (j35 >>> 28);
        long j38 = j35 & M28L;
        long j39 = decode327 + (j9 * 258169998) + (j7 * 96434764) + (j15 * 227822194) + (j16 * 149865618) + (j14 * 550336261) + (j37 >>> 28);
        long j40 = j37 & M28L;
        long j41 = decode246 + (j9 * 96434764) + (j7 * 227822194) + (j15 * 149865618) + (j16 * 550336261) + (j39 >>> 28);
        long j42 = j39 & M28L;
        long j43 = decode3210 + (j41 >>> 28);
        long j44 = j41 & M28L;
        long j45 = decode247 + (j9 * 149865618) + (j7 * 550336261) + (j43 >>> 28);
        long j46 = j43 & M28L;
        long j47 = j18 + (j45 >>> 28);
        long j48 = j45 & M28L;
        long j49 = j25 + (j47 >>> 28);
        long j50 = j47 & M28L;
        long j51 = j49 & M26L;
        long j52 = (j49 >>> 26) - 1;
        long j53 = j27 - (j52 & 78101261);
        long j54 = (j28 - (j52 & 141809365)) + (j53 >> 28);
        long j55 = j53 & M28L;
        long j56 = (j29 - (j52 & 175155932)) + (j54 >> 28);
        long j57 = j54 & M28L;
        long j58 = (j30 - (j52 & 64542499)) + (j56 >> 28);
        long j59 = j56 & M28L;
        long j60 = (j31 - (j52 & 158326419)) + (j58 >> 28);
        long j61 = j58 & M28L;
        long j62 = (j33 - (j52 & 191173276)) + (j60 >> 28);
        long j63 = j60 & M28L;
        long j64 = (j34 - (j52 & 104575268)) + (j62 >> 28);
        long j65 = j62 & M28L;
        long j66 = (j36 - (j52 & 137584065)) + (j64 >> 28);
        long j67 = j64 & M28L;
        long j68 = j38 + (j66 >> 28);
        long j69 = j66 & M28L;
        long j70 = j40 + (j68 >> 28);
        long j71 = j68 & M28L;
        long j72 = j42 + (j70 >> 28);
        long j73 = j70 & M28L;
        long j74 = j44 + (j72 >> 28);
        long j75 = j72 & M28L;
        long j76 = j46 + (j74 >> 28);
        long j77 = j74 & M28L;
        long j78 = j48 + (j76 >> 28);
        long j79 = j76 & M28L;
        long j80 = j50 + (j78 >> 28);
        long j81 = j78 & M28L;
        long j82 = j80 & M28L;
        byte[] bArr2 = new byte[57];
        Codec.encode56(j55 | (j57 << 28), bArr2, 0);
        Codec.encode56(j59 | (j61 << 28), bArr2, 7);
        Codec.encode56(j63 | (j65 << 28), bArr2, 14);
        Codec.encode56(j67 | (j69 << 28), bArr2, 21);
        Codec.encode56(j71 | (j73 << 28), bArr2, 28);
        Codec.encode56((j77 << 28) | j75, bArr2, 35);
        Codec.encode56(j79 | (j81 << 28), bArr2, 42);
        Codec.encode56(j82 | ((j51 + (j80 >> 28)) << 28), bArr2, 49);
        return bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] reduce912(byte[] bArr) {
        long decode32 = Codec.decode32(bArr, 84);
        long j = decode32 & 4294967295L;
        long decode322 = Codec.decode32(bArr, 91);
        long j2 = decode322 & 4294967295L;
        long decode323 = Codec.decode32(bArr, 98);
        long j3 = decode323 & 4294967295L;
        long decode324 = Codec.decode32(bArr, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256);
        long j4 = decode324 & 4294967295L;
        long decode16 = Codec.decode16(bArr, 112) & 4294967295L;
        long decode24 = ((Codec.decode24(bArr, 109) << 4) & 4294967295L) + (j4 >>> 28);
        long j5 = decode324 & M28L;
        long decode325 = (Codec.decode32(bArr, 56) & 4294967295L) + (decode16 * 43969588) + (decode24 * 30366549);
        long decode242 = ((Codec.decode24(bArr, 60) << 4) & 4294967295L) + (decode16 * 30366549) + (decode24 * 163752818);
        long decode326 = (Codec.decode32(bArr, 63) & 4294967295L) + (decode16 * 163752818) + (decode24 * 258169998);
        long decode243 = ((Codec.decode24(bArr, 67) << 4) & 4294967295L) + (decode16 * 258169998) + (decode24 * 96434764);
        long decode327 = (Codec.decode32(bArr, 77) & 4294967295L) + (decode16 * 149865618) + (decode24 * 550336261);
        long decode328 = (Codec.decode32(bArr, 49) & 4294967295L) + (j5 * 43969588);
        long decode244 = ((Codec.decode24(bArr, LocationRequestCompat.QUALITY_BALANCED_POWER_ACCURACY) << 4) & 4294967295L) + (j3 >>> 28);
        long j6 = decode323 & M28L;
        long decode329 = (Codec.decode32(bArr, 70) & 4294967295L) + (decode16 * 96434764) + (decode24 * 227822194) + (j5 * 149865618) + (decode244 * 550336261);
        long decode3210 = (Codec.decode32(bArr, 42) & 4294967295L) + (j6 * 43969588);
        long decode245 = ((Codec.decode24(bArr, 95) << 4) & 4294967295L) + (j2 >>> 28);
        long j7 = decode322 & M28L;
        long j8 = decode326 + (j5 * 96434764) + (decode244 * 227822194) + (j6 * 149865618) + (decode245 * 550336261);
        long j9 = decode242 + (j5 * 258169998) + (decode244 * 96434764) + (j6 * 227822194) + (decode245 * 149865618) + (j7 * 550336261);
        long decode246 = ((Codec.decode24(bArr, 88) << 4) & 4294967295L) + (j >>> 28);
        long j10 = decode32 & M28L;
        long decode247 = ((Codec.decode24(bArr, 74) << 4) & 4294967295L) + (decode16 * 227822194) + (decode24 * 149865618) + (j5 * 550336261) + (decode329 >>> 28);
        long j11 = decode329 & M28L;
        long j12 = decode327 + (decode247 >>> 28);
        long j13 = decode247 & M28L;
        long decode248 = ((Codec.decode24(bArr, 81) << 4) & 4294967295L) + (decode16 * 550336261) + (j12 >>> 28);
        long j14 = j12 & M28L;
        long j15 = j10 + (decode248 >>> 28);
        long j16 = decode248 & M28L;
        long decode249 = ((Codec.decode24(bArr, 25) << 4) & 4294967295L) + (j16 * 43969588);
        long decode3211 = (Codec.decode32(bArr, 28) & 4294967295L) + (j15 * 43969588) + (j16 * 30366549);
        long decode2410 = ((Codec.decode24(bArr, 32) << 4) & 4294967295L) + (decode246 * 43969588) + (j15 * 30366549) + (j16 * 163752818);
        long decode3212 = (Codec.decode32(bArr, 35) & 4294967295L) + (j7 * 43969588) + (decode246 * 30366549) + (j15 * 163752818) + (j16 * 258169998);
        long decode2411 = ((Codec.decode24(bArr, 39) << 4) & 4294967295L) + (decode245 * 43969588) + (j7 * 30366549) + (decode246 * 163752818) + (j15 * 258169998) + (j16 * 96434764);
        long j17 = decode3210 + (decode245 * 30366549) + (j7 * 163752818) + (decode246 * 258169998) + (j15 * 96434764) + (j16 * 227822194);
        long j18 = decode328 + (decode244 * 30366549) + (j6 * 163752818) + (decode245 * 258169998) + (j7 * 96434764) + (decode246 * 227822194) + (j15 * 149865618) + (j16 * 550336261);
        long decode3213 = (Codec.decode32(bArr, 21) & 4294967295L) + (j14 * 43969588);
        long j19 = j8 + (j9 >>> 28);
        long j20 = j9 & M28L;
        long j21 = decode243 + (j5 * 227822194) + (decode244 * 149865618) + (j6 * 550336261) + (j19 >>> 28);
        long j22 = j19 & M28L;
        long j23 = j11 + (j21 >>> 28);
        long j24 = j21 & M28L;
        long j25 = j13 + (j23 >>> 28);
        long j26 = j23 & M28L;
        long j27 = decode2411 + (j14 * 227822194) + (j25 * 149865618) + (j26 * 550336261);
        long decode3214 = (Codec.decode32(bArr, 14) & 4294967295L) + (j26 * 43969588) + (j24 * 30366549);
        long decode2412 = ((Codec.decode24(bArr, 18) << 4) & 4294967295L) + (j25 * 43969588) + (j26 * 30366549) + (j24 * 163752818);
        long j28 = decode3213 + (j25 * 30366549) + (j26 * 163752818) + (j24 * 258169998);
        long j29 = decode249 + (j14 * 30366549) + (j25 * 163752818) + (j26 * 258169998) + (j24 * 96434764);
        long j30 = decode3211 + (j14 * 163752818) + (j25 * 258169998) + (j26 * 96434764) + (j24 * 227822194);
        long j31 = decode2410 + (j14 * 258169998) + (j25 * 96434764) + (j26 * 227822194) + (j24 * 149865618);
        long j32 = decode3212 + (j14 * 96434764) + (j25 * 227822194) + (j26 * 149865618) + (j24 * 550336261);
        long decode2413 = ((Codec.decode24(bArr, 53) << 4) & 4294967295L) + (decode24 * 43969588) + (j5 * 30366549) + (decode244 * 163752818) + (j6 * 258169998) + (decode245 * 96434764) + (j7 * 227822194) + (decode246 * 149865618) + (j15 * 550336261) + (j18 >>> 28);
        long j33 = j18 & M28L;
        long j34 = decode325 + (j5 * 163752818) + (decode244 * 258169998) + (j6 * 96434764) + (decode245 * 227822194) + (j7 * 149865618) + (decode246 * 550336261) + (decode2413 >>> 28);
        long j35 = decode2413 & M28L;
        long j36 = j20 + (j34 >>> 28);
        long j37 = j34 & M28L;
        long j38 = j22 + (j36 >>> 28);
        long j39 = j36 & M28L;
        long j40 = j28 + (j38 * 96434764);
        long j41 = j31 + (j38 * 550336261);
        long j42 = decode2413 & M26L;
        long j43 = (j37 * 4) + (j35 >>> 26) + 1;
        long decode3215 = (Codec.decode32(bArr, 0) & 4294967295L) + (78101261 * j43);
        long decode3216 = (Codec.decode32(bArr, 7) & 4294967295L) + (j38 * 43969588) + (30366549 * j39) + (175155932 * j43);
        long decode2414 = ((Codec.decode24(bArr, 11) << 4) & 4294967295L) + (j24 * 43969588) + (j38 * 30366549) + (163752818 * j39) + (64542499 * j43);
        long j44 = decode3214 + (j38 * 163752818) + (258169998 * j39) + (158326419 * j43);
        long j45 = decode2412 + (j38 * 258169998) + (96434764 * j39) + (191173276 * j43);
        long j46 = j29 + (j38 * 227822194) + (149865618 * j39) + (j43 * 137584065);
        long decode2415 = ((Codec.decode24(bArr, 4) << 4) & 4294967295L) + (43969588 * j39) + (141809365 * j43) + (decode3215 >>> 28);
        long j47 = decode3215 & M28L;
        long j48 = decode3216 + (decode2415 >>> 28);
        long j49 = decode2415 & M28L;
        long j50 = decode2414 + (j48 >>> 28);
        long j51 = j48 & M28L;
        long j52 = j44 + (j50 >>> 28);
        long j53 = j50 & M28L;
        long j54 = j45 + (j52 >>> 28);
        long j55 = j52 & M28L;
        long j56 = j40 + (227822194 * j39) + (104575268 * j43) + (j54 >>> 28);
        long j57 = j54 & M28L;
        long j58 = j46 + (j56 >>> 28);
        long j59 = j56 & M28L;
        long j60 = j30 + (j38 * 149865618) + (j39 * 550336261) + (j58 >>> 28);
        long j61 = j58 & M28L;
        long j62 = j41 + (j60 >>> 28);
        long j63 = j60 & M28L;
        long j64 = j32 + (j62 >>> 28);
        long j65 = j62 & M28L;
        long j66 = j27 + (j64 >>> 28);
        long j67 = j64 & M28L;
        long j68 = j17 + (j14 * 149865618) + (j25 * 550336261) + (j66 >>> 28);
        long j69 = j66 & M28L;
        long decode2416 = ((Codec.decode24(bArr, 46) << 4) & 4294967295L) + (decode244 * 43969588) + (j6 * 30366549) + (decode245 * 163752818) + (j7 * 258169998) + (decode246 * 96434764) + (j15 * 227822194) + (j16 * 149865618) + (j14 * 550336261) + (j68 >>> 28);
        long j70 = j68 & M28L;
        long j71 = j33 + (decode2416 >>> 28);
        long j72 = decode2416 & M28L;
        long j73 = j42 + (j71 >>> 28);
        long j74 = j71 & M28L;
        long j75 = j73 & M26L;
        long j76 = (j73 >>> 26) - 1;
        long j77 = j47 - (j76 & 78101261);
        long j78 = (j49 - (j76 & 141809365)) + (j77 >> 28);
        long j79 = j77 & M28L;
        long j80 = (j51 - (j76 & 175155932)) + (j78 >> 28);
        long j81 = j78 & M28L;
        long j82 = (j53 - (j76 & 64542499)) + (j80 >> 28);
        long j83 = j80 & M28L;
        long j84 = (j55 - (j76 & 158326419)) + (j82 >> 28);
        long j85 = j82 & M28L;
        long j86 = (j57 - (j76 & 191173276)) + (j84 >> 28);
        long j87 = j84 & M28L;
        long j88 = (j59 - (j76 & 104575268)) + (j86 >> 28);
        long j89 = j86 & M28L;
        long j90 = (j61 - (j76 & 137584065)) + (j88 >> 28);
        long j91 = j88 & M28L;
        long j92 = j63 + (j90 >> 28);
        long j93 = j90 & M28L;
        long j94 = j65 + (j92 >> 28);
        long j95 = j92 & M28L;
        long j96 = j67 + (j94 >> 28);
        long j97 = j94 & M28L;
        long j98 = j69 + (j96 >> 28);
        long j99 = j96 & M28L;
        long j100 = j70 + (j98 >> 28);
        long j101 = j98 & M28L;
        long j102 = j72 + (j100 >> 28);
        long j103 = j100 & M28L;
        long j104 = j74 + (j102 >> 28);
        long j105 = j102 & M28L;
        long j106 = j104 & M28L;
        byte[] bArr2 = new byte[57];
        Codec.encode56((j81 << 28) | j79, bArr2, 0);
        Codec.encode56((j85 << 28) | j83, bArr2, 7);
        Codec.encode56(j87 | (j89 << 28), bArr2, 14);
        Codec.encode56(j91 | (j93 << 28), bArr2, 21);
        Codec.encode56(j95 | (j97 << 28), bArr2, 28);
        Codec.encode56(j99 | (j101 << 28), bArr2, 35);
        Codec.encode56(j103 | (j105 << 28), bArr2, 42);
        Codec.encode56(((j75 + (j104 >> 28)) << 28) | j106, bArr2, 49);
        return bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean reduceBasisVar(int[] iArr, int[] iArr2, int[] iArr3) {
        int i;
        int i2;
        int[] iArr4;
        int[] iArr5 = new int[28];
        System.arraycopy(LSq, 0, iArr5, 0, 28);
        int[] iArr6 = new int[28];
        Nat448.square(iArr, iArr6);
        iArr6[0] = iArr6[0] + 1;
        int[] iArr7 = new int[28];
        int[] iArr8 = f1137L;
        Nat448.mul(iArr8, iArr, iArr7);
        int[] iArr9 = new int[28];
        int[] iArr10 = new int[8];
        System.arraycopy(iArr8, 0, iArr10, 0, 8);
        int[] iArr11 = new int[8];
        System.arraycopy(iArr, 0, iArr11, 0, 8);
        int[] iArr12 = new int[8];
        iArr12[0] = 1;
        int[] iArr13 = new int[8];
        int[] iArr14 = iArr10;
        int[] iArr15 = iArr11;
        int i3 = 27;
        int i4 = 1788;
        int bitLengthPositive = ScalarUtil.getBitLengthPositive(27, iArr6);
        while (bitLengthPositive > TARGET_LENGTH) {
            int i5 = i4 - 1;
            if (i5 < 0) {
                return false;
            }
            int bitLength = ScalarUtil.getBitLength(i3, iArr7) - bitLengthPositive;
            int i6 = bitLength & (~(bitLength >> 31));
            if (iArr7[i3] < 0) {
                i = bitLengthPositive;
                ScalarUtil.addShifted_NP(i3, i6, iArr5, iArr6, iArr7, iArr9);
                int[] iArr16 = iArr15;
                ScalarUtil.addShifted_UV(7, i6, iArr14, iArr13, iArr16, iArr12);
                iArr4 = iArr16;
                i2 = i3;
            } else {
                i = bitLengthPositive;
                ScalarUtil.subShifted_NP(i3, i6, iArr5, iArr6, iArr7, iArr9);
                i2 = i3;
                iArr4 = iArr15;
                ScalarUtil.subShifted_UV(7, i6, iArr14, iArr13, iArr4, iArr12);
            }
            if (ScalarUtil.lessThan(i2, iArr5, iArr6)) {
                int i7 = i >>> 5;
                i3 = i7;
                bitLengthPositive = ScalarUtil.getBitLengthPositive(i7, iArr5);
                iArr15 = iArr14;
                iArr14 = iArr4;
                int[] iArr17 = iArr13;
                iArr13 = iArr12;
                iArr12 = iArr17;
                int[] iArr18 = iArr6;
                iArr6 = iArr5;
                iArr5 = iArr18;
            } else {
                iArr15 = iArr4;
                i3 = i2;
                bitLengthPositive = i;
            }
            i4 = i5;
        }
        System.arraycopy(iArr15, 0, iArr2, 0, 8);
        System.arraycopy(iArr12, 0, iArr3, 0, 8);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void toSignedDigits(int i, int[] iArr, int[] iArr2) {
        iArr2[14] = (1 << (i - 448)) + Nat.cadd(14, 1 & (~iArr[0]), iArr, f1137L, iArr2);
        Nat.shiftDownBit(15, iArr2, 0);
    }
}