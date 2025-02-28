package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ThreefishEngine.class */
public class ThreefishEngine implements BlockCipher {
    public static final int BLOCKSIZE_256 = 256;
    public static final int BLOCKSIZE_512 = 512;
    public static final int BLOCKSIZE_1024 = 1024;
    private static final int TWEAK_SIZE_BYTES = 16;
    private static final int TWEAK_SIZE_WORDS = 2;
    private static final int ROUNDS_256 = 72;
    private static final int ROUNDS_512 = 72;
    private static final int ROUNDS_1024 = 80;
    private static final int MAX_ROUNDS = 80;
    private static final long C_240 = 2004413935125273122L;
    private static int[] MOD9 = new int[80];
    private static int[] MOD17 = new int[MOD9.length];
    private static int[] MOD5 = new int[MOD9.length];
    private static int[] MOD3 = new int[MOD9.length];
    private int blocksizeBytes;
    private int blocksizeWords;
    private long[] currentBlock;

    /* renamed from: t */
    private long[] f381t = new long[5];

    /* renamed from: kw */
    private long[] f382kw;
    private ThreefishCipher cipher;
    private boolean forEncryption;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ThreefishEngine$Threefish1024Cipher.class */
    private static final class Threefish1024Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 24;
        private static final int ROTATION_0_1 = 13;
        private static final int ROTATION_0_2 = 8;
        private static final int ROTATION_0_3 = 47;
        private static final int ROTATION_0_4 = 8;
        private static final int ROTATION_0_5 = 17;
        private static final int ROTATION_0_6 = 22;
        private static final int ROTATION_0_7 = 37;
        private static final int ROTATION_1_0 = 38;
        private static final int ROTATION_1_1 = 19;
        private static final int ROTATION_1_2 = 10;
        private static final int ROTATION_1_3 = 55;
        private static final int ROTATION_1_4 = 49;
        private static final int ROTATION_1_5 = 18;
        private static final int ROTATION_1_6 = 23;
        private static final int ROTATION_1_7 = 52;
        private static final int ROTATION_2_0 = 33;
        private static final int ROTATION_2_1 = 4;
        private static final int ROTATION_2_2 = 51;
        private static final int ROTATION_2_3 = 13;
        private static final int ROTATION_2_4 = 34;
        private static final int ROTATION_2_5 = 41;
        private static final int ROTATION_2_6 = 59;
        private static final int ROTATION_2_7 = 17;
        private static final int ROTATION_3_0 = 5;
        private static final int ROTATION_3_1 = 20;
        private static final int ROTATION_3_2 = 48;
        private static final int ROTATION_3_3 = 41;
        private static final int ROTATION_3_4 = 47;
        private static final int ROTATION_3_5 = 28;
        private static final int ROTATION_3_6 = 16;
        private static final int ROTATION_3_7 = 25;
        private static final int ROTATION_4_0 = 41;
        private static final int ROTATION_4_1 = 9;
        private static final int ROTATION_4_2 = 37;
        private static final int ROTATION_4_3 = 31;
        private static final int ROTATION_4_4 = 12;
        private static final int ROTATION_4_5 = 47;
        private static final int ROTATION_4_6 = 44;
        private static final int ROTATION_4_7 = 30;
        private static final int ROTATION_5_0 = 16;
        private static final int ROTATION_5_1 = 34;
        private static final int ROTATION_5_2 = 56;
        private static final int ROTATION_5_3 = 51;
        private static final int ROTATION_5_4 = 4;
        private static final int ROTATION_5_5 = 53;
        private static final int ROTATION_5_6 = 42;
        private static final int ROTATION_5_7 = 41;
        private static final int ROTATION_6_0 = 31;
        private static final int ROTATION_6_1 = 44;
        private static final int ROTATION_6_2 = 47;
        private static final int ROTATION_6_3 = 46;
        private static final int ROTATION_6_4 = 19;
        private static final int ROTATION_6_5 = 42;
        private static final int ROTATION_6_6 = 44;
        private static final int ROTATION_6_7 = 25;
        private static final int ROTATION_7_0 = 9;
        private static final int ROTATION_7_1 = 48;
        private static final int ROTATION_7_2 = 35;
        private static final int ROTATION_7_3 = 52;
        private static final int ROTATION_7_4 = 23;
        private static final int ROTATION_7_5 = 31;
        private static final int ROTATION_7_6 = 37;
        private static final int ROTATION_7_7 = 20;

        public Threefish1024Cipher(long[] jArr, long[] jArr2) {
            super(jArr, jArr2);
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        void encryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD17;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 33) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            long j5 = jArr[4];
            long j6 = jArr[5];
            long j7 = jArr[6];
            long j8 = jArr[7];
            long j9 = jArr[8];
            long j10 = jArr[9];
            long j11 = jArr[10];
            long j12 = jArr[11];
            long j13 = jArr[12];
            long j14 = jArr[13];
            long j15 = jArr[14];
            long j16 = jArr[15];
            long j17 = j + jArr3[0];
            long j18 = j2 + jArr3[1];
            long j19 = j3 + jArr3[2];
            long j20 = j4 + jArr3[3];
            long j21 = j5 + jArr3[4];
            long j22 = j6 + jArr3[5];
            long j23 = j7 + jArr3[6];
            long j24 = j8 + jArr3[7];
            long j25 = j9 + jArr3[8];
            long j26 = j10 + jArr3[9];
            long j27 = j11 + jArr3[10];
            long j28 = j12 + jArr3[11];
            long j29 = j13 + jArr3[12];
            long j30 = j14 + jArr3[13] + jArr4[0];
            long j31 = j15 + jArr3[14] + jArr4[1];
            long j32 = j16 + jArr3[15];
            for (int i = 1; i < 20; i += 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j33 = j18;
                long rotlXor = ThreefishEngine.rotlXor(j33, 24, j17 + j18);
                long j34 = j19 + j20;
                long rotlXor2 = ThreefishEngine.rotlXor(j20, 13, j34);
                long j35 = j21 + j22;
                long rotlXor3 = ThreefishEngine.rotlXor(j22, 8, j35);
                long j36 = j23 + j24;
                long rotlXor4 = ThreefishEngine.rotlXor(j24, 47, j36);
                long j37 = j25 + j26;
                long rotlXor5 = ThreefishEngine.rotlXor(j26, 8, j37);
                long j38 = j27 + j28;
                long rotlXor6 = ThreefishEngine.rotlXor(j28, 17, j38);
                long j39 = j29 + j30;
                long rotlXor7 = ThreefishEngine.rotlXor(j30, 22, j39);
                long j40 = j31 + j32;
                long rotlXor8 = ThreefishEngine.rotlXor(j32, 37, j40);
                long j41 = j33 + rotlXor5;
                long rotlXor9 = ThreefishEngine.rotlXor(rotlXor5, 38, j41);
                long j42 = j34 + rotlXor7;
                long rotlXor10 = ThreefishEngine.rotlXor(rotlXor7, 19, j42);
                long j43 = j36 + rotlXor6;
                long rotlXor11 = ThreefishEngine.rotlXor(rotlXor6, 10, j43);
                long j44 = j35 + rotlXor8;
                long rotlXor12 = ThreefishEngine.rotlXor(rotlXor8, 55, j44);
                long j45 = j38 + rotlXor4;
                long rotlXor13 = ThreefishEngine.rotlXor(rotlXor4, 49, j45);
                long j46 = j39 + rotlXor2;
                long rotlXor14 = ThreefishEngine.rotlXor(rotlXor2, 18, j46);
                long j47 = j40 + rotlXor3;
                long rotlXor15 = ThreefishEngine.rotlXor(rotlXor3, 23, j47);
                long j48 = j37 + rotlXor;
                long rotlXor16 = ThreefishEngine.rotlXor(rotlXor, 52, j48);
                long j49 = j41 + rotlXor13;
                long rotlXor17 = ThreefishEngine.rotlXor(rotlXor13, 33, j49);
                long j50 = j42 + rotlXor15;
                long rotlXor18 = ThreefishEngine.rotlXor(rotlXor15, 4, j50);
                long j51 = j44 + rotlXor14;
                long rotlXor19 = ThreefishEngine.rotlXor(rotlXor14, 51, j51);
                long j52 = j43 + rotlXor16;
                long rotlXor20 = ThreefishEngine.rotlXor(rotlXor16, 13, j52);
                long j53 = j46 + rotlXor12;
                long rotlXor21 = ThreefishEngine.rotlXor(rotlXor12, 34, j53);
                long j54 = j47 + rotlXor10;
                long rotlXor22 = ThreefishEngine.rotlXor(rotlXor10, 41, j54);
                long j55 = j48 + rotlXor11;
                long rotlXor23 = ThreefishEngine.rotlXor(rotlXor11, 59, j55);
                long j56 = j45 + rotlXor9;
                long rotlXor24 = ThreefishEngine.rotlXor(rotlXor9, 17, j56);
                long j57 = j49 + rotlXor21;
                long rotlXor25 = ThreefishEngine.rotlXor(rotlXor21, 5, j57);
                long j58 = j50 + rotlXor23;
                long rotlXor26 = ThreefishEngine.rotlXor(rotlXor23, 20, j58);
                long j59 = j52 + rotlXor22;
                long rotlXor27 = ThreefishEngine.rotlXor(rotlXor22, 48, j59);
                long j60 = j51 + rotlXor24;
                long rotlXor28 = ThreefishEngine.rotlXor(rotlXor24, 41, j60);
                long j61 = j54 + rotlXor20;
                long rotlXor29 = ThreefishEngine.rotlXor(rotlXor20, 47, j61);
                long j62 = j55 + rotlXor18;
                long rotlXor30 = ThreefishEngine.rotlXor(rotlXor18, 28, j62);
                long j63 = j56 + rotlXor19;
                long rotlXor31 = ThreefishEngine.rotlXor(rotlXor19, 16, j63);
                long j64 = j53 + rotlXor17;
                long rotlXor32 = ThreefishEngine.rotlXor(rotlXor17, 25, j64);
                long j65 = j57 + jArr3[i2];
                long j66 = rotlXor29 + jArr3[i2 + 1];
                long j67 = j58 + jArr3[i2 + 2];
                long j68 = rotlXor31 + jArr3[i2 + 3];
                long j69 = j60 + jArr3[i2 + 4];
                long j70 = rotlXor30 + jArr3[i2 + 5];
                long j71 = j59 + jArr3[i2 + 6];
                long j72 = rotlXor32 + jArr3[i2 + 7];
                long j73 = j62 + jArr3[i2 + 8];
                long j74 = rotlXor28 + jArr3[i2 + 9];
                long j75 = j63 + jArr3[i2 + 10];
                long j76 = rotlXor26 + jArr3[i2 + 11];
                long j77 = j64 + jArr3[i2 + 12];
                long j78 = rotlXor27 + jArr3[i2 + 13] + jArr4[i3];
                long j79 = j61 + jArr3[i2 + 14] + jArr4[i3 + 1];
                long j80 = rotlXor25 + jArr3[i2 + 15] + i;
                long j81 = j65 + j66;
                long rotlXor33 = ThreefishEngine.rotlXor(j66, 41, j81);
                long j82 = j67 + j68;
                long rotlXor34 = ThreefishEngine.rotlXor(j68, 9, j82);
                long j83 = j69 + j70;
                long rotlXor35 = ThreefishEngine.rotlXor(j70, 37, j83);
                long j84 = j71 + j72;
                long rotlXor36 = ThreefishEngine.rotlXor(j72, 31, j84);
                long j85 = j73 + j74;
                long rotlXor37 = ThreefishEngine.rotlXor(j74, 12, j85);
                long j86 = j75 + j76;
                long rotlXor38 = ThreefishEngine.rotlXor(j76, 47, j86);
                long j87 = j77 + j78;
                long rotlXor39 = ThreefishEngine.rotlXor(j78, 44, j87);
                long j88 = j79 + j80;
                long rotlXor40 = ThreefishEngine.rotlXor(j80, 30, j88);
                long j89 = j81 + rotlXor37;
                long rotlXor41 = ThreefishEngine.rotlXor(rotlXor37, 16, j89);
                long j90 = j82 + rotlXor39;
                long rotlXor42 = ThreefishEngine.rotlXor(rotlXor39, 34, j90);
                long j91 = j84 + rotlXor38;
                long rotlXor43 = ThreefishEngine.rotlXor(rotlXor38, 56, j91);
                long j92 = j83 + rotlXor40;
                long rotlXor44 = ThreefishEngine.rotlXor(rotlXor40, 51, j92);
                long j93 = j86 + rotlXor36;
                long rotlXor45 = ThreefishEngine.rotlXor(rotlXor36, 4, j93);
                long j94 = j87 + rotlXor34;
                long rotlXor46 = ThreefishEngine.rotlXor(rotlXor34, 53, j94);
                long j95 = j88 + rotlXor35;
                long rotlXor47 = ThreefishEngine.rotlXor(rotlXor35, 42, j95);
                long j96 = j85 + rotlXor33;
                long rotlXor48 = ThreefishEngine.rotlXor(rotlXor33, 41, j96);
                long j97 = j89 + rotlXor45;
                long rotlXor49 = ThreefishEngine.rotlXor(rotlXor45, 31, j97);
                long j98 = j90 + rotlXor47;
                long rotlXor50 = ThreefishEngine.rotlXor(rotlXor47, 44, j98);
                long j99 = j92 + rotlXor46;
                long rotlXor51 = ThreefishEngine.rotlXor(rotlXor46, 47, j99);
                long j100 = j91 + rotlXor48;
                long rotlXor52 = ThreefishEngine.rotlXor(rotlXor48, 46, j100);
                long j101 = j94 + rotlXor44;
                long rotlXor53 = ThreefishEngine.rotlXor(rotlXor44, 19, j101);
                long j102 = j95 + rotlXor42;
                long rotlXor54 = ThreefishEngine.rotlXor(rotlXor42, 42, j102);
                long j103 = j96 + rotlXor43;
                long rotlXor55 = ThreefishEngine.rotlXor(rotlXor43, 44, j103);
                long j104 = j93 + rotlXor41;
                long rotlXor56 = ThreefishEngine.rotlXor(rotlXor41, 25, j104);
                long j105 = j97 + rotlXor53;
                long rotlXor57 = ThreefishEngine.rotlXor(rotlXor53, 9, j105);
                long j106 = j98 + rotlXor55;
                long rotlXor58 = ThreefishEngine.rotlXor(rotlXor55, 48, j106);
                long j107 = j100 + rotlXor54;
                long rotlXor59 = ThreefishEngine.rotlXor(rotlXor54, 35, j107);
                long j108 = j99 + rotlXor56;
                long rotlXor60 = ThreefishEngine.rotlXor(rotlXor56, 52, j108);
                long j109 = j102 + rotlXor52;
                long rotlXor61 = ThreefishEngine.rotlXor(rotlXor52, 23, j109);
                long j110 = j103 + rotlXor50;
                long rotlXor62 = ThreefishEngine.rotlXor(rotlXor50, 31, j110);
                long j111 = j104 + rotlXor51;
                long rotlXor63 = ThreefishEngine.rotlXor(rotlXor51, 37, j111);
                long j112 = j101 + rotlXor49;
                long rotlXor64 = ThreefishEngine.rotlXor(rotlXor49, 20, j112);
                j17 = j105 + jArr3[i2 + 1];
                j18 = rotlXor61 + jArr3[i2 + 2];
                j19 = j106 + jArr3[i2 + 3];
                j20 = rotlXor63 + jArr3[i2 + 4];
                j21 = j108 + jArr3[i2 + 5];
                j22 = rotlXor62 + jArr3[i2 + 6];
                j23 = j107 + jArr3[i2 + 7];
                j24 = rotlXor64 + jArr3[i2 + 8];
                j25 = j110 + jArr3[i2 + 9];
                j26 = rotlXor60 + jArr3[i2 + 10];
                j27 = j111 + jArr3[i2 + 11];
                j28 = rotlXor58 + jArr3[i2 + 12];
                j29 = j112 + jArr3[i2 + 13];
                j30 = rotlXor59 + jArr3[i2 + 14] + jArr4[i3 + 1];
                j31 = j109 + jArr3[i2 + 15] + jArr4[i3 + 2];
                j32 = rotlXor57 + jArr3[i2 + 16] + i + 1;
            }
            jArr2[0] = j17;
            jArr2[1] = j18;
            jArr2[2] = j19;
            jArr2[3] = j20;
            jArr2[4] = j21;
            jArr2[5] = j22;
            jArr2[6] = j23;
            jArr2[7] = j24;
            jArr2[8] = j25;
            jArr2[9] = j26;
            jArr2[10] = j27;
            jArr2[11] = j28;
            jArr2[12] = j29;
            jArr2[13] = j30;
            jArr2[14] = j31;
            jArr2[15] = j32;
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        void decryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD17;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 33) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            long j5 = jArr[4];
            long j6 = jArr[5];
            long j7 = jArr[6];
            long j8 = jArr[7];
            long j9 = jArr[8];
            long j10 = jArr[9];
            long j11 = jArr[10];
            long j12 = jArr[11];
            long j13 = jArr[12];
            long j14 = jArr[13];
            long j15 = jArr[14];
            long j16 = jArr[15];
            for (int i = 19; i >= 1; i -= 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j17 = j - jArr3[i2 + 1];
                long j18 = j2 - jArr3[i2 + 2];
                long j19 = j3 - jArr3[i2 + 3];
                long j20 = j4 - jArr3[i2 + 4];
                long j21 = j5 - jArr3[i2 + 5];
                long j22 = j6 - jArr3[i2 + 6];
                long j23 = j7 - jArr3[i2 + 7];
                long j24 = j8 - jArr3[i2 + 8];
                long j25 = j9 - jArr3[i2 + 9];
                long j26 = j10 - jArr3[i2 + 10];
                long j27 = j11 - jArr3[i2 + 11];
                long j28 = j12 - jArr3[i2 + 12];
                long j29 = j13 - jArr3[i2 + 13];
                long j30 = j14 - (jArr3[i2 + 14] + jArr4[i3 + 1]);
                long j31 = j15 - (jArr3[i2 + 15] + jArr4[i3 + 2]);
                long xorRotr = ThreefishEngine.xorRotr(j16 - ((jArr3[i2 + 16] + i) + 1), 9, j17);
                long j32 = j17 - xorRotr;
                long xorRotr2 = ThreefishEngine.xorRotr(j28, 48, j19);
                long j33 = j19 - xorRotr2;
                long xorRotr3 = ThreefishEngine.xorRotr(j30, 35, j23);
                long j34 = j23 - xorRotr3;
                long xorRotr4 = ThreefishEngine.xorRotr(j26, 52, j21);
                long j35 = j21 - xorRotr4;
                long xorRotr5 = ThreefishEngine.xorRotr(j18, 23, j31);
                long j36 = j31 - xorRotr5;
                long xorRotr6 = ThreefishEngine.xorRotr(j22, 31, j25);
                long j37 = j25 - xorRotr6;
                long xorRotr7 = ThreefishEngine.xorRotr(j20, 37, j27);
                long j38 = j27 - xorRotr7;
                long xorRotr8 = ThreefishEngine.xorRotr(j24, 20, j29);
                long j39 = j29 - xorRotr8;
                long xorRotr9 = ThreefishEngine.xorRotr(xorRotr8, 31, j32);
                long j40 = j32 - xorRotr9;
                long xorRotr10 = ThreefishEngine.xorRotr(xorRotr6, 44, j33);
                long j41 = j33 - xorRotr10;
                long xorRotr11 = ThreefishEngine.xorRotr(xorRotr7, 47, j35);
                long j42 = j35 - xorRotr11;
                long xorRotr12 = ThreefishEngine.xorRotr(xorRotr5, 46, j34);
                long j43 = j34 - xorRotr12;
                long xorRotr13 = ThreefishEngine.xorRotr(xorRotr, 19, j39);
                long j44 = j39 - xorRotr13;
                long xorRotr14 = ThreefishEngine.xorRotr(xorRotr3, 42, j36);
                long j45 = j36 - xorRotr14;
                long xorRotr15 = ThreefishEngine.xorRotr(xorRotr2, 44, j37);
                long j46 = j37 - xorRotr15;
                long xorRotr16 = ThreefishEngine.xorRotr(xorRotr4, 25, j38);
                long j47 = j38 - xorRotr16;
                long xorRotr17 = ThreefishEngine.xorRotr(xorRotr16, 16, j40);
                long j48 = j40 - xorRotr17;
                long xorRotr18 = ThreefishEngine.xorRotr(xorRotr14, 34, j41);
                long j49 = j41 - xorRotr18;
                long xorRotr19 = ThreefishEngine.xorRotr(xorRotr15, 56, j43);
                long j50 = j43 - xorRotr19;
                long xorRotr20 = ThreefishEngine.xorRotr(xorRotr13, 51, j42);
                long j51 = j42 - xorRotr20;
                long xorRotr21 = ThreefishEngine.xorRotr(xorRotr9, 4, j47);
                long j52 = j47 - xorRotr21;
                long xorRotr22 = ThreefishEngine.xorRotr(xorRotr11, 53, j44);
                long j53 = j44 - xorRotr22;
                long xorRotr23 = ThreefishEngine.xorRotr(xorRotr10, 42, j45);
                long j54 = j45 - xorRotr23;
                long xorRotr24 = ThreefishEngine.xorRotr(xorRotr12, 41, j46);
                long j55 = j46 - xorRotr24;
                long xorRotr25 = ThreefishEngine.xorRotr(xorRotr24, 41, j48);
                long j56 = j48 - xorRotr25;
                long xorRotr26 = ThreefishEngine.xorRotr(xorRotr22, 9, j49);
                long j57 = j49 - xorRotr26;
                long xorRotr27 = ThreefishEngine.xorRotr(xorRotr23, 37, j51);
                long j58 = j51 - xorRotr27;
                long xorRotr28 = ThreefishEngine.xorRotr(xorRotr21, 31, j50);
                long j59 = j50 - xorRotr28;
                long xorRotr29 = ThreefishEngine.xorRotr(xorRotr17, 12, j55);
                long j60 = j55 - xorRotr29;
                long xorRotr30 = ThreefishEngine.xorRotr(xorRotr19, 47, j52);
                long j61 = j52 - xorRotr30;
                long xorRotr31 = ThreefishEngine.xorRotr(xorRotr18, 44, j53);
                long j62 = j53 - xorRotr31;
                long xorRotr32 = ThreefishEngine.xorRotr(xorRotr20, 30, j54);
                long j63 = j54 - xorRotr32;
                long j64 = j56 - jArr3[i2];
                long j65 = xorRotr25 - jArr3[i2 + 1];
                long j66 = j57 - jArr3[i2 + 2];
                long j67 = xorRotr26 - jArr3[i2 + 3];
                long j68 = j58 - jArr3[i2 + 4];
                long j69 = xorRotr27 - jArr3[i2 + 5];
                long j70 = j59 - jArr3[i2 + 6];
                long j71 = xorRotr28 - jArr3[i2 + 7];
                long j72 = j60 - jArr3[i2 + 8];
                long j73 = xorRotr29 - jArr3[i2 + 9];
                long j74 = j61 - jArr3[i2 + 10];
                long j75 = xorRotr30 - jArr3[i2 + 11];
                long j76 = j62 - jArr3[i2 + 12];
                long j77 = xorRotr31 - (jArr3[i2 + 13] + jArr4[i3]);
                long j78 = j63 - (jArr3[i2 + 14] + jArr4[i3 + 1]);
                long xorRotr33 = ThreefishEngine.xorRotr(xorRotr32 - (jArr3[i2 + 15] + i), 5, j64);
                long j79 = j64 - xorRotr33;
                long xorRotr34 = ThreefishEngine.xorRotr(j75, 20, j66);
                long j80 = j66 - xorRotr34;
                long xorRotr35 = ThreefishEngine.xorRotr(j77, 48, j70);
                long j81 = j70 - xorRotr35;
                long xorRotr36 = ThreefishEngine.xorRotr(j73, 41, j68);
                long j82 = j68 - xorRotr36;
                long xorRotr37 = ThreefishEngine.xorRotr(j65, 47, j78);
                long j83 = j78 - xorRotr37;
                long xorRotr38 = ThreefishEngine.xorRotr(j69, 28, j72);
                long j84 = j72 - xorRotr38;
                long xorRotr39 = ThreefishEngine.xorRotr(j67, 16, j74);
                long j85 = j74 - xorRotr39;
                long xorRotr40 = ThreefishEngine.xorRotr(j71, 25, j76);
                long j86 = j76 - xorRotr40;
                long xorRotr41 = ThreefishEngine.xorRotr(xorRotr40, 33, j79);
                long j87 = j79 - xorRotr41;
                long xorRotr42 = ThreefishEngine.xorRotr(xorRotr38, 4, j80);
                long j88 = j80 - xorRotr42;
                long xorRotr43 = ThreefishEngine.xorRotr(xorRotr39, 51, j82);
                long j89 = j82 - xorRotr43;
                long xorRotr44 = ThreefishEngine.xorRotr(xorRotr37, 13, j81);
                long j90 = j81 - xorRotr44;
                long xorRotr45 = ThreefishEngine.xorRotr(xorRotr33, 34, j86);
                long j91 = j86 - xorRotr45;
                long xorRotr46 = ThreefishEngine.xorRotr(xorRotr35, 41, j83);
                long j92 = j83 - xorRotr46;
                long xorRotr47 = ThreefishEngine.xorRotr(xorRotr34, 59, j84);
                long j93 = j84 - xorRotr47;
                long xorRotr48 = ThreefishEngine.xorRotr(xorRotr36, 17, j85);
                long j94 = j85 - xorRotr48;
                long xorRotr49 = ThreefishEngine.xorRotr(xorRotr48, 38, j87);
                long j95 = j87 - xorRotr49;
                long xorRotr50 = ThreefishEngine.xorRotr(xorRotr46, 19, j88);
                long j96 = j88 - xorRotr50;
                long xorRotr51 = ThreefishEngine.xorRotr(xorRotr47, 10, j90);
                long j97 = j90 - xorRotr51;
                long xorRotr52 = ThreefishEngine.xorRotr(xorRotr45, 55, j89);
                long j98 = j89 - xorRotr52;
                long xorRotr53 = ThreefishEngine.xorRotr(xorRotr41, 49, j94);
                long j99 = j94 - xorRotr53;
                long xorRotr54 = ThreefishEngine.xorRotr(xorRotr43, 18, j91);
                long j100 = j91 - xorRotr54;
                long xorRotr55 = ThreefishEngine.xorRotr(xorRotr42, 23, j92);
                long j101 = j92 - xorRotr55;
                long xorRotr56 = ThreefishEngine.xorRotr(xorRotr44, 52, j93);
                long j102 = j93 - xorRotr56;
                j2 = ThreefishEngine.xorRotr(xorRotr56, 24, j95);
                j = j95 - j2;
                j4 = ThreefishEngine.xorRotr(xorRotr54, 13, j96);
                j3 = j96 - j4;
                j6 = ThreefishEngine.xorRotr(xorRotr55, 8, j98);
                j5 = j98 - j6;
                j8 = ThreefishEngine.xorRotr(xorRotr53, 47, j97);
                j7 = j97 - j8;
                j10 = ThreefishEngine.xorRotr(xorRotr49, 8, j102);
                j9 = j102 - j10;
                j12 = ThreefishEngine.xorRotr(xorRotr51, 17, j99);
                j11 = j99 - j12;
                j14 = ThreefishEngine.xorRotr(xorRotr50, 22, j100);
                j13 = j100 - j14;
                j16 = ThreefishEngine.xorRotr(xorRotr52, 37, j101);
                j15 = j101 - j16;
            }
            long j103 = j - jArr3[0];
            long j104 = j2 - jArr3[1];
            long j105 = j3 - jArr3[2];
            long j106 = j4 - jArr3[3];
            long j107 = j5 - jArr3[4];
            long j108 = j6 - jArr3[5];
            long j109 = j7 - jArr3[6];
            long j110 = j8 - jArr3[7];
            long j111 = j9 - jArr3[8];
            long j112 = j10 - jArr3[9];
            long j113 = j11 - jArr3[10];
            long j114 = j12 - jArr3[11];
            long j115 = j13 - jArr3[12];
            long j116 = j14 - (jArr3[13] + jArr4[0]);
            long j117 = j15 - (jArr3[14] + jArr4[1]);
            jArr2[0] = j103;
            jArr2[1] = j104;
            jArr2[2] = j105;
            jArr2[3] = j106;
            jArr2[4] = j107;
            jArr2[5] = j108;
            jArr2[6] = j109;
            jArr2[7] = j110;
            jArr2[8] = j111;
            jArr2[9] = j112;
            jArr2[10] = j113;
            jArr2[11] = j114;
            jArr2[12] = j115;
            jArr2[13] = j116;
            jArr2[14] = j117;
            jArr2[15] = j16 - jArr3[15];
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ThreefishEngine$Threefish256Cipher.class */
    private static final class Threefish256Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 14;
        private static final int ROTATION_0_1 = 16;
        private static final int ROTATION_1_0 = 52;
        private static final int ROTATION_1_1 = 57;
        private static final int ROTATION_2_0 = 23;
        private static final int ROTATION_2_1 = 40;
        private static final int ROTATION_3_0 = 5;
        private static final int ROTATION_3_1 = 37;
        private static final int ROTATION_4_0 = 25;
        private static final int ROTATION_4_1 = 33;
        private static final int ROTATION_5_0 = 46;
        private static final int ROTATION_5_1 = 12;
        private static final int ROTATION_6_0 = 58;
        private static final int ROTATION_6_1 = 22;
        private static final int ROTATION_7_0 = 32;
        private static final int ROTATION_7_1 = 32;

        public Threefish256Cipher(long[] jArr, long[] jArr2) {
            super(jArr, jArr2);
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        void encryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD5;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 9) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            long j5 = j + jArr3[0];
            long j6 = j2 + jArr3[1] + jArr4[0];
            long j7 = j3 + jArr3[2] + jArr4[1];
            long j8 = j4 + jArr3[3];
            for (int i = 1; i < 18; i += 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j9 = j6;
                long rotlXor = ThreefishEngine.rotlXor(j9, 14, j5 + j6);
                long j10 = j7 + j8;
                long rotlXor2 = ThreefishEngine.rotlXor(j8, 16, j10);
                long j11 = j9 + rotlXor2;
                long rotlXor3 = ThreefishEngine.rotlXor(rotlXor2, 52, j11);
                long j12 = j10 + rotlXor;
                long rotlXor4 = ThreefishEngine.rotlXor(rotlXor, 57, j12);
                long j13 = j11 + rotlXor4;
                long rotlXor5 = ThreefishEngine.rotlXor(rotlXor4, 23, j13);
                long j14 = j12 + rotlXor3;
                long rotlXor6 = ThreefishEngine.rotlXor(rotlXor3, 40, j14);
                long j15 = j13 + rotlXor6;
                long rotlXor7 = ThreefishEngine.rotlXor(rotlXor6, 5, j15);
                long j16 = j14 + rotlXor5;
                long rotlXor8 = ThreefishEngine.rotlXor(rotlXor5, 37, j16);
                long j17 = j15 + jArr3[i2];
                long j18 = rotlXor8 + jArr3[i2 + 1] + jArr4[i3];
                long j19 = j16 + jArr3[i2 + 2] + jArr4[i3 + 1];
                long j20 = rotlXor7 + jArr3[i2 + 3] + i;
                long j21 = j17 + j18;
                long rotlXor9 = ThreefishEngine.rotlXor(j18, 25, j21);
                long j22 = j19 + j20;
                long rotlXor10 = ThreefishEngine.rotlXor(j20, 33, j22);
                long j23 = j21 + rotlXor10;
                long rotlXor11 = ThreefishEngine.rotlXor(rotlXor10, 46, j23);
                long j24 = j22 + rotlXor9;
                long rotlXor12 = ThreefishEngine.rotlXor(rotlXor9, 12, j24);
                long j25 = j23 + rotlXor12;
                long rotlXor13 = ThreefishEngine.rotlXor(rotlXor12, 58, j25);
                long j26 = j24 + rotlXor11;
                long rotlXor14 = ThreefishEngine.rotlXor(rotlXor11, 22, j26);
                long j27 = j25 + rotlXor14;
                long rotlXor15 = ThreefishEngine.rotlXor(rotlXor14, 32, j27);
                long j28 = j26 + rotlXor13;
                long rotlXor16 = ThreefishEngine.rotlXor(rotlXor13, 32, j28);
                j5 = j27 + jArr3[i2 + 1];
                j6 = rotlXor16 + jArr3[i2 + 2] + jArr4[i3 + 1];
                j7 = j28 + jArr3[i2 + 3] + jArr4[i3 + 2];
                j8 = rotlXor15 + jArr3[i2 + 4] + i + 1;
            }
            jArr2[0] = j5;
            jArr2[1] = j6;
            jArr2[2] = j7;
            jArr2[3] = j8;
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        void decryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD5;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 9) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            for (int i = 17; i >= 1; i -= 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j5 = j - jArr3[i2 + 1];
                long j6 = j2 - (jArr3[i2 + 2] + jArr4[i3 + 1]);
                long j7 = j3 - (jArr3[i2 + 3] + jArr4[i3 + 2]);
                long xorRotr = ThreefishEngine.xorRotr(j4 - ((jArr3[i2 + 4] + i) + 1), 32, j5);
                long j8 = j5 - xorRotr;
                long xorRotr2 = ThreefishEngine.xorRotr(j6, 32, j7);
                long j9 = j7 - xorRotr2;
                long xorRotr3 = ThreefishEngine.xorRotr(xorRotr2, 58, j8);
                long j10 = j8 - xorRotr3;
                long xorRotr4 = ThreefishEngine.xorRotr(xorRotr, 22, j9);
                long j11 = j9 - xorRotr4;
                long xorRotr5 = ThreefishEngine.xorRotr(xorRotr4, 46, j10);
                long j12 = j10 - xorRotr5;
                long xorRotr6 = ThreefishEngine.xorRotr(xorRotr3, 12, j11);
                long j13 = j11 - xorRotr6;
                long xorRotr7 = ThreefishEngine.xorRotr(xorRotr6, 25, j12);
                long j14 = j12 - xorRotr7;
                long xorRotr8 = ThreefishEngine.xorRotr(xorRotr5, 33, j13);
                long j15 = j13 - xorRotr8;
                long j16 = j14 - jArr3[i2];
                long j17 = xorRotr7 - (jArr3[i2 + 1] + jArr4[i3]);
                long j18 = j15 - (jArr3[i2 + 2] + jArr4[i3 + 1]);
                long xorRotr9 = ThreefishEngine.xorRotr(xorRotr8 - (jArr3[i2 + 3] + i), 5, j16);
                long j19 = j16 - xorRotr9;
                long xorRotr10 = ThreefishEngine.xorRotr(j17, 37, j18);
                long j20 = j18 - xorRotr10;
                long xorRotr11 = ThreefishEngine.xorRotr(xorRotr10, 23, j19);
                long j21 = j19 - xorRotr11;
                long xorRotr12 = ThreefishEngine.xorRotr(xorRotr9, 40, j20);
                long j22 = j20 - xorRotr12;
                long xorRotr13 = ThreefishEngine.xorRotr(xorRotr12, 52, j21);
                long j23 = j21 - xorRotr13;
                long xorRotr14 = ThreefishEngine.xorRotr(xorRotr11, 57, j22);
                long j24 = j22 - xorRotr14;
                j2 = ThreefishEngine.xorRotr(xorRotr14, 14, j23);
                j = j23 - j2;
                j4 = ThreefishEngine.xorRotr(xorRotr13, 16, j24);
                j3 = j24 - j4;
            }
            long j25 = j - jArr3[0];
            long j26 = j2 - (jArr3[1] + jArr4[0]);
            long j27 = j3 - (jArr3[2] + jArr4[1]);
            jArr2[0] = j25;
            jArr2[1] = j26;
            jArr2[2] = j27;
            jArr2[3] = j4 - jArr3[3];
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ThreefishEngine$Threefish512Cipher.class */
    private static final class Threefish512Cipher extends ThreefishCipher {
        private static final int ROTATION_0_0 = 46;
        private static final int ROTATION_0_1 = 36;
        private static final int ROTATION_0_2 = 19;
        private static final int ROTATION_0_3 = 37;
        private static final int ROTATION_1_0 = 33;
        private static final int ROTATION_1_1 = 27;
        private static final int ROTATION_1_2 = 14;
        private static final int ROTATION_1_3 = 42;
        private static final int ROTATION_2_0 = 17;
        private static final int ROTATION_2_1 = 49;
        private static final int ROTATION_2_2 = 36;
        private static final int ROTATION_2_3 = 39;
        private static final int ROTATION_3_0 = 44;
        private static final int ROTATION_3_1 = 9;
        private static final int ROTATION_3_2 = 54;
        private static final int ROTATION_3_3 = 56;
        private static final int ROTATION_4_0 = 39;
        private static final int ROTATION_4_1 = 30;
        private static final int ROTATION_4_2 = 34;
        private static final int ROTATION_4_3 = 24;
        private static final int ROTATION_5_0 = 13;
        private static final int ROTATION_5_1 = 50;
        private static final int ROTATION_5_2 = 10;
        private static final int ROTATION_5_3 = 17;
        private static final int ROTATION_6_0 = 25;
        private static final int ROTATION_6_1 = 29;
        private static final int ROTATION_6_2 = 39;
        private static final int ROTATION_6_3 = 43;
        private static final int ROTATION_7_0 = 8;
        private static final int ROTATION_7_1 = 35;
        private static final int ROTATION_7_2 = 56;
        private static final int ROTATION_7_3 = 22;

        protected Threefish512Cipher(long[] jArr, long[] jArr2) {
            super(jArr, jArr2);
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        public void encryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD9;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 17) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            long j5 = jArr[4];
            long j6 = jArr[5];
            long j7 = jArr[6];
            long j8 = jArr[7];
            long j9 = j + jArr3[0];
            long j10 = j2 + jArr3[1];
            long j11 = j3 + jArr3[2];
            long j12 = j4 + jArr3[3];
            long j13 = j5 + jArr3[4];
            long j14 = j6 + jArr3[5] + jArr4[0];
            long j15 = j7 + jArr3[6] + jArr4[1];
            long j16 = j8 + jArr3[7];
            for (int i = 1; i < 18; i += 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j17 = j10;
                long rotlXor = ThreefishEngine.rotlXor(j17, 46, j9 + j10);
                long j18 = j11 + j12;
                long rotlXor2 = ThreefishEngine.rotlXor(j12, 36, j18);
                long j19 = j13 + j14;
                long rotlXor3 = ThreefishEngine.rotlXor(j14, 19, j19);
                long j20 = j15 + j16;
                long rotlXor4 = ThreefishEngine.rotlXor(j16, 37, j20);
                long j21 = j18 + rotlXor;
                long rotlXor5 = ThreefishEngine.rotlXor(rotlXor, 33, j21);
                long j22 = j19 + rotlXor4;
                long rotlXor6 = ThreefishEngine.rotlXor(rotlXor4, 27, j22);
                long j23 = j20 + rotlXor3;
                long rotlXor7 = ThreefishEngine.rotlXor(rotlXor3, 14, j23);
                long j24 = j17 + rotlXor2;
                long rotlXor8 = ThreefishEngine.rotlXor(rotlXor2, 42, j24);
                long j25 = j22 + rotlXor5;
                long rotlXor9 = ThreefishEngine.rotlXor(rotlXor5, 17, j25);
                long j26 = j23 + rotlXor8;
                long rotlXor10 = ThreefishEngine.rotlXor(rotlXor8, 49, j26);
                long j27 = j24 + rotlXor7;
                long rotlXor11 = ThreefishEngine.rotlXor(rotlXor7, 36, j27);
                long j28 = j21 + rotlXor6;
                long rotlXor12 = ThreefishEngine.rotlXor(rotlXor6, 39, j28);
                long j29 = j26 + rotlXor9;
                long rotlXor13 = ThreefishEngine.rotlXor(rotlXor9, 44, j29);
                long j30 = j27 + rotlXor12;
                long rotlXor14 = ThreefishEngine.rotlXor(rotlXor12, 9, j30);
                long j31 = j28 + rotlXor11;
                long rotlXor15 = ThreefishEngine.rotlXor(rotlXor11, 54, j31);
                long j32 = j25 + rotlXor10;
                long rotlXor16 = ThreefishEngine.rotlXor(rotlXor10, 56, j32);
                long j33 = j30 + jArr3[i2];
                long j34 = rotlXor13 + jArr3[i2 + 1];
                long j35 = j31 + jArr3[i2 + 2];
                long j36 = rotlXor16 + jArr3[i2 + 3];
                long j37 = j32 + jArr3[i2 + 4];
                long j38 = rotlXor15 + jArr3[i2 + 5] + jArr4[i3];
                long j39 = j29 + jArr3[i2 + 6] + jArr4[i3 + 1];
                long j40 = rotlXor14 + jArr3[i2 + 7] + i;
                long j41 = j33 + j34;
                long rotlXor17 = ThreefishEngine.rotlXor(j34, 39, j41);
                long j42 = j35 + j36;
                long rotlXor18 = ThreefishEngine.rotlXor(j36, 30, j42);
                long j43 = j37 + j38;
                long rotlXor19 = ThreefishEngine.rotlXor(j38, 34, j43);
                long j44 = j39 + j40;
                long rotlXor20 = ThreefishEngine.rotlXor(j40, 24, j44);
                long j45 = j42 + rotlXor17;
                long rotlXor21 = ThreefishEngine.rotlXor(rotlXor17, 13, j45);
                long j46 = j43 + rotlXor20;
                long rotlXor22 = ThreefishEngine.rotlXor(rotlXor20, 50, j46);
                long j47 = j44 + rotlXor19;
                long rotlXor23 = ThreefishEngine.rotlXor(rotlXor19, 10, j47);
                long j48 = j41 + rotlXor18;
                long rotlXor24 = ThreefishEngine.rotlXor(rotlXor18, 17, j48);
                long j49 = j46 + rotlXor21;
                long rotlXor25 = ThreefishEngine.rotlXor(rotlXor21, 25, j49);
                long j50 = j47 + rotlXor24;
                long rotlXor26 = ThreefishEngine.rotlXor(rotlXor24, 29, j50);
                long j51 = j48 + rotlXor23;
                long rotlXor27 = ThreefishEngine.rotlXor(rotlXor23, 39, j51);
                long j52 = j45 + rotlXor22;
                long rotlXor28 = ThreefishEngine.rotlXor(rotlXor22, 43, j52);
                long j53 = j50 + rotlXor25;
                long rotlXor29 = ThreefishEngine.rotlXor(rotlXor25, 8, j53);
                long j54 = j51 + rotlXor28;
                long rotlXor30 = ThreefishEngine.rotlXor(rotlXor28, 35, j54);
                long j55 = j52 + rotlXor27;
                long rotlXor31 = ThreefishEngine.rotlXor(rotlXor27, 56, j55);
                long j56 = j49 + rotlXor26;
                long rotlXor32 = ThreefishEngine.rotlXor(rotlXor26, 22, j56);
                j9 = j54 + jArr3[i2 + 1];
                j10 = rotlXor29 + jArr3[i2 + 2];
                j11 = j55 + jArr3[i2 + 3];
                j12 = rotlXor32 + jArr3[i2 + 4];
                j13 = j56 + jArr3[i2 + 5];
                j14 = rotlXor31 + jArr3[i2 + 6] + jArr4[i3 + 1];
                j15 = j53 + jArr3[i2 + 7] + jArr4[i3 + 2];
                j16 = rotlXor30 + jArr3[i2 + 8] + i + 1;
            }
            jArr2[0] = j9;
            jArr2[1] = j10;
            jArr2[2] = j11;
            jArr2[3] = j12;
            jArr2[4] = j13;
            jArr2[5] = j14;
            jArr2[6] = j15;
            jArr2[7] = j16;
        }

        @Override // org.bouncycastle.crypto.engines.ThreefishEngine.ThreefishCipher
        public void decryptBlock(long[] jArr, long[] jArr2) {
            long[] jArr3 = this.f384kw;
            long[] jArr4 = this.f383t;
            int[] iArr = ThreefishEngine.MOD9;
            int[] iArr2 = ThreefishEngine.MOD3;
            if (jArr3.length != 17) {
                throw new IllegalArgumentException();
            }
            if (jArr4.length != 5) {
                throw new IllegalArgumentException();
            }
            long j = jArr[0];
            long j2 = jArr[1];
            long j3 = jArr[2];
            long j4 = jArr[3];
            long j5 = jArr[4];
            long j6 = jArr[5];
            long j7 = jArr[6];
            long j8 = jArr[7];
            for (int i = 17; i >= 1; i -= 2) {
                int i2 = iArr[i];
                int i3 = iArr2[i];
                long j9 = j - jArr3[i2 + 1];
                long j10 = j2 - jArr3[i2 + 2];
                long j11 = j3 - jArr3[i2 + 3];
                long j12 = j4 - jArr3[i2 + 4];
                long j13 = j5 - jArr3[i2 + 5];
                long j14 = j6 - (jArr3[i2 + 6] + jArr4[i3 + 1]);
                long j15 = j7 - (jArr3[i2 + 7] + jArr4[i3 + 2]);
                long j16 = j8 - ((jArr3[i2 + 8] + i) + 1);
                long xorRotr = ThreefishEngine.xorRotr(j10, 8, j15);
                long j17 = j15 - xorRotr;
                long xorRotr2 = ThreefishEngine.xorRotr(j16, 35, j9);
                long j18 = j9 - xorRotr2;
                long xorRotr3 = ThreefishEngine.xorRotr(j14, 56, j11);
                long j19 = j11 - xorRotr3;
                long xorRotr4 = ThreefishEngine.xorRotr(j12, 22, j13);
                long j20 = j13 - xorRotr4;
                long xorRotr5 = ThreefishEngine.xorRotr(xorRotr, 25, j20);
                long j21 = j20 - xorRotr5;
                long xorRotr6 = ThreefishEngine.xorRotr(xorRotr4, 29, j17);
                long j22 = j17 - xorRotr6;
                long xorRotr7 = ThreefishEngine.xorRotr(xorRotr3, 39, j18);
                long j23 = j18 - xorRotr7;
                long xorRotr8 = ThreefishEngine.xorRotr(xorRotr2, 43, j19);
                long j24 = j19 - xorRotr8;
                long xorRotr9 = ThreefishEngine.xorRotr(xorRotr5, 13, j24);
                long j25 = j24 - xorRotr9;
                long xorRotr10 = ThreefishEngine.xorRotr(xorRotr8, 50, j21);
                long j26 = j21 - xorRotr10;
                long xorRotr11 = ThreefishEngine.xorRotr(xorRotr7, 10, j22);
                long j27 = j22 - xorRotr11;
                long xorRotr12 = ThreefishEngine.xorRotr(xorRotr6, 17, j23);
                long j28 = j23 - xorRotr12;
                long xorRotr13 = ThreefishEngine.xorRotr(xorRotr9, 39, j28);
                long j29 = j28 - xorRotr13;
                long xorRotr14 = ThreefishEngine.xorRotr(xorRotr12, 30, j25);
                long j30 = j25 - xorRotr14;
                long xorRotr15 = ThreefishEngine.xorRotr(xorRotr11, 34, j26);
                long j31 = j26 - xorRotr15;
                long xorRotr16 = ThreefishEngine.xorRotr(xorRotr10, 24, j27);
                long j32 = j27 - xorRotr16;
                long j33 = j29 - jArr3[i2];
                long j34 = xorRotr13 - jArr3[i2 + 1];
                long j35 = j30 - jArr3[i2 + 2];
                long j36 = xorRotr14 - jArr3[i2 + 3];
                long j37 = j31 - jArr3[i2 + 4];
                long j38 = xorRotr15 - (jArr3[i2 + 5] + jArr4[i3]);
                long j39 = j32 - (jArr3[i2 + 6] + jArr4[i3 + 1]);
                long j40 = xorRotr16 - (jArr3[i2 + 7] + i);
                long xorRotr17 = ThreefishEngine.xorRotr(j34, 44, j39);
                long j41 = j39 - xorRotr17;
                long xorRotr18 = ThreefishEngine.xorRotr(j40, 9, j33);
                long j42 = j33 - xorRotr18;
                long xorRotr19 = ThreefishEngine.xorRotr(j38, 54, j35);
                long j43 = j35 - xorRotr19;
                long xorRotr20 = ThreefishEngine.xorRotr(j36, 56, j37);
                long j44 = j37 - xorRotr20;
                long xorRotr21 = ThreefishEngine.xorRotr(xorRotr17, 17, j44);
                long j45 = j44 - xorRotr21;
                long xorRotr22 = ThreefishEngine.xorRotr(xorRotr20, 49, j41);
                long j46 = j41 - xorRotr22;
                long xorRotr23 = ThreefishEngine.xorRotr(xorRotr19, 36, j42);
                long j47 = j42 - xorRotr23;
                long xorRotr24 = ThreefishEngine.xorRotr(xorRotr18, 39, j43);
                long j48 = j43 - xorRotr24;
                long xorRotr25 = ThreefishEngine.xorRotr(xorRotr21, 33, j48);
                long j49 = j48 - xorRotr25;
                long xorRotr26 = ThreefishEngine.xorRotr(xorRotr24, 27, j45);
                long j50 = j45 - xorRotr26;
                long xorRotr27 = ThreefishEngine.xorRotr(xorRotr23, 14, j46);
                long j51 = j46 - xorRotr27;
                long xorRotr28 = ThreefishEngine.xorRotr(xorRotr22, 42, j47);
                long j52 = j47 - xorRotr28;
                j2 = ThreefishEngine.xorRotr(xorRotr25, 46, j52);
                j = j52 - j2;
                j4 = ThreefishEngine.xorRotr(xorRotr28, 36, j49);
                j3 = j49 - j4;
                j6 = ThreefishEngine.xorRotr(xorRotr27, 19, j50);
                j5 = j50 - j6;
                j8 = ThreefishEngine.xorRotr(xorRotr26, 37, j51);
                j7 = j51 - j8;
            }
            long j53 = j - jArr3[0];
            long j54 = j2 - jArr3[1];
            long j55 = j3 - jArr3[2];
            long j56 = j4 - jArr3[3];
            long j57 = j5 - jArr3[4];
            long j58 = j6 - (jArr3[5] + jArr4[0]);
            long j59 = j7 - (jArr3[6] + jArr4[1]);
            jArr2[0] = j53;
            jArr2[1] = j54;
            jArr2[2] = j55;
            jArr2[3] = j56;
            jArr2[4] = j57;
            jArr2[5] = j58;
            jArr2[6] = j59;
            jArr2[7] = j8 - jArr3[7];
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ThreefishEngine$ThreefishCipher.class */
    public static abstract class ThreefishCipher {

        /* renamed from: t */
        protected final long[] f383t;

        /* renamed from: kw */
        protected final long[] f384kw;

        protected ThreefishCipher(long[] jArr, long[] jArr2) {
            this.f384kw = jArr;
            this.f383t = jArr2;
        }

        abstract void encryptBlock(long[] jArr, long[] jArr2);

        abstract void decryptBlock(long[] jArr, long[] jArr2);
    }

    public ThreefishEngine(int i) {
        this.blocksizeBytes = i / 8;
        this.blocksizeWords = this.blocksizeBytes / 8;
        this.currentBlock = new long[this.blocksizeWords];
        this.f382kw = new long[(2 * this.blocksizeWords) + 1];
        switch (i) {
            case 256:
                this.cipher = new Threefish256Cipher(this.f382kw, this.f381t);
                return;
            case 512:
                this.cipher = new Threefish512Cipher(this.f382kw, this.f381t);
                return;
            case 1024:
                this.cipher = new Threefish1024Cipher(this.f382kw, this.f381t);
                return;
            default:
                throw new IllegalArgumentException("Invalid blocksize - Threefish is defined with block size of 256, 512, or 1024 bits");
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] key;
        byte[] bArr;
        if (cipherParameters instanceof TweakableBlockCipherParameters) {
            TweakableBlockCipherParameters tweakableBlockCipherParameters = (TweakableBlockCipherParameters) cipherParameters;
            key = tweakableBlockCipherParameters.getKey().getKey();
            bArr = tweakableBlockCipherParameters.getTweak();
        } else if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to Threefish init - " + cipherParameters.getClass().getName());
        } else {
            key = ((KeyParameter) cipherParameters).getKey();
            bArr = null;
        }
        long[] jArr = null;
        long[] jArr2 = null;
        if (key != null) {
            if (key.length != this.blocksizeBytes) {
                throw new IllegalArgumentException("Threefish key must be same size as block (" + this.blocksizeBytes + " bytes)");
            }
            jArr = new long[this.blocksizeWords];
            for (int i = 0; i < jArr.length; i++) {
                jArr[i] = bytesToWord(key, i * 8);
            }
        }
        if (bArr != null) {
            if (bArr.length != 16) {
                throw new IllegalArgumentException("Threefish tweak must be 16 bytes");
            }
            jArr2 = new long[]{bytesToWord(bArr, 0), bytesToWord(bArr, 8)};
        }
        init(z, jArr, jArr2);
    }

    public void init(boolean z, long[] jArr, long[] jArr2) {
        this.forEncryption = z;
        if (jArr != null) {
            setKey(jArr);
        }
        if (jArr2 != null) {
            setTweak(jArr2);
        }
    }

    private void setKey(long[] jArr) {
        if (jArr.length != this.blocksizeWords) {
            throw new IllegalArgumentException("Threefish key must be same size as block (" + this.blocksizeWords + " words)");
        }
        long j = 2004413935125273122L;
        for (int i = 0; i < this.blocksizeWords; i++) {
            this.f382kw[i] = jArr[i];
            j ^= this.f382kw[i];
        }
        this.f382kw[this.blocksizeWords] = j;
        System.arraycopy(this.f382kw, 0, this.f382kw, this.blocksizeWords + 1, this.blocksizeWords);
    }

    private void setTweak(long[] jArr) {
        if (jArr.length != 2) {
            throw new IllegalArgumentException("Tweak must be 2 words.");
        }
        this.f381t[0] = jArr[0];
        this.f381t[1] = jArr[1];
        this.f381t[2] = this.f381t[0] ^ this.f381t[1];
        this.f381t[3] = this.f381t[0];
        this.f381t[4] = this.f381t[1];
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Threefish-" + (this.blocksizeBytes * 8);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.blocksizeBytes;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blocksizeBytes > bArr.length) {
            throw new DataLengthException("Input buffer too short");
        }
        if (i2 + this.blocksizeBytes > bArr2.length) {
            throw new OutputLengthException("Output buffer too short");
        }
        for (int i3 = 0; i3 < this.blocksizeBytes; i3 += 8) {
            this.currentBlock[i3 >> 3] = bytesToWord(bArr, i + i3);
        }
        processBlock(this.currentBlock, this.currentBlock);
        for (int i4 = 0; i4 < this.blocksizeBytes; i4 += 8) {
            wordToBytes(this.currentBlock[i4 >> 3], bArr2, i2 + i4);
        }
        return this.blocksizeBytes;
    }

    public int processBlock(long[] jArr, long[] jArr2) throws DataLengthException, IllegalStateException {
        if (this.f382kw[this.blocksizeWords] == 0) {
            throw new IllegalStateException("Threefish engine not initialised");
        }
        if (jArr.length != this.blocksizeWords) {
            throw new DataLengthException("Input buffer too short");
        }
        if (jArr2.length != this.blocksizeWords) {
            throw new OutputLengthException("Output buffer too short");
        }
        if (this.forEncryption) {
            this.cipher.encryptBlock(jArr, jArr2);
        } else {
            this.cipher.decryptBlock(jArr, jArr2);
        }
        return this.blocksizeWords;
    }

    public static long bytesToWord(byte[] bArr, int i) {
        if (i + 8 > bArr.length) {
            throw new IllegalArgumentException();
        }
        int i2 = i + 1;
        int i3 = i2 + 1;
        int i4 = i3 + 1;
        int i5 = i4 + 1;
        int i6 = i5 + 1;
        int i7 = i6 + 1;
        int i8 = i7 + 1;
        int i9 = i8 + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16) | ((bArr[i4] & 255) << 24) | ((bArr[i5] & 255) << 32) | ((bArr[i6] & 255) << 40) | ((bArr[i7] & 255) << 48) | ((bArr[i8] & 255) << 56);
    }

    public static void wordToBytes(long j, byte[] bArr, int i) {
        if (i + 8 > bArr.length) {
            throw new IllegalArgumentException();
        }
        int i2 = i + 1;
        bArr[i] = (byte) j;
        int i3 = i2 + 1;
        bArr[i2] = (byte) (j >> 8);
        int i4 = i3 + 1;
        bArr[i3] = (byte) (j >> 16);
        int i5 = i4 + 1;
        bArr[i4] = (byte) (j >> 24);
        int i6 = i5 + 1;
        bArr[i5] = (byte) (j >> 32);
        int i7 = i6 + 1;
        bArr[i6] = (byte) (j >> 40);
        int i8 = i7 + 1;
        bArr[i7] = (byte) (j >> 48);
        int i9 = i8 + 1;
        bArr[i8] = (byte) (j >> 56);
    }

    static long rotlXor(long j, int i, long j2) {
        return ((j << i) | (j >>> (-i))) ^ j2;
    }

    static long xorRotr(long j, int i, long j2) {
        long j3 = j ^ j2;
        return (j3 >>> i) | (j3 << (-i));
    }

    static {
        for (int i = 0; i < MOD9.length; i++) {
            MOD17[i] = i % 17;
            MOD9[i] = i % 9;
            MOD5[i] = i % 5;
            MOD3[i] = i % 3;
        }
    }
}