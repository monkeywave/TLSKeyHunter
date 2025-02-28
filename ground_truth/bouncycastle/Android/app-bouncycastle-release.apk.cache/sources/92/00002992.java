package org.bouncycastle.pqc.crypto.falcon;

/* loaded from: classes2.dex */
class SHAKE256 {

    /* renamed from: RC */
    private long[] f1248RC = {1, 32898, -9223372036854742902L, -9223372034707259392L, 32907, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138, 136, 2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778, -9223372034707292150L, -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L};

    /* renamed from: A */
    long[] f1247A = new long[25];
    byte[] dbuf = new byte[200];
    long dptr = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    public void i_shake256_flip() {
        int i = (int) this.dptr;
        long[] jArr = this.f1247A;
        int i2 = i >> 3;
        jArr[i2] = jArr[i2] ^ (31 << ((i & 7) << 3));
        jArr[16] = jArr[16] ^ Long.MIN_VALUE;
        this.dptr = 136L;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void inner_shake256_extract(byte[] bArr, int i, int i2) {
        int i3 = (int) this.dptr;
        while (i2 > 0) {
            if (i3 == 136) {
                process_block(this.f1247A);
                i3 = 0;
            }
            int i4 = 136 - i3;
            if (i4 > i2) {
                i4 = i2;
            }
            i2 -= i4;
            while (true) {
                int i5 = i4 - 1;
                if (i4 > 0) {
                    bArr[i] = (byte) (this.f1247A[i3 >> 3] >>> ((i3 & 7) << 3));
                    i3++;
                    i++;
                    i4 = i5;
                }
            }
        }
        this.dptr = i3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void inner_shake256_init() {
        this.dptr = 0L;
        int i = 0;
        while (true) {
            long[] jArr = this.f1247A;
            if (i >= jArr.length) {
                return;
            }
            jArr[i] = 0;
            i++;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void inner_shake256_inject(byte[] bArr, int i, int i2) {
        long j = this.dptr;
        int i3 = i;
        int i4 = i2;
        while (i4 > 0) {
            long j2 = 136 - j;
            long j3 = i4;
            if (j2 > j3) {
                j2 = j3;
            }
            long j4 = 0;
            while (j4 < j2) {
                long j5 = j4 + j;
                long[] jArr = this.f1247A;
                int i5 = (int) (j5 >> 3);
                jArr[i5] = jArr[i5] ^ ((bArr[((int) j4) + i3] & 255) << ((int) ((j5 & 7) << 3)));
                j4++;
                j3 = j3;
            }
            j += j2;
            i3 = (int) (i3 + j2);
            i4 = (int) (j3 - j2);
            if (j == 136) {
                process_block(this.f1247A);
                j = 0;
            }
        }
        this.dptr = j;
    }

    void process_block(long[] jArr) {
        char c = 1;
        jArr[1] = ~jArr[1];
        char c2 = 2;
        jArr[2] = ~jArr[2];
        char c3 = '\b';
        jArr[8] = ~jArr[8];
        char c4 = '\f';
        jArr[12] = ~jArr[12];
        char c5 = 17;
        jArr[17] = ~jArr[17];
        char c6 = 20;
        jArr[20] = ~jArr[20];
        char c7 = 0;
        int i = 0;
        while (i < 24) {
            long j = jArr[c];
            long j2 = jArr[6];
            long j3 = jArr[11];
            long j4 = jArr[16];
            long j5 = jArr[21];
            long j6 = (j ^ j2) ^ (j5 ^ (j3 ^ j4));
            long j7 = jArr[4];
            long j8 = jArr[9];
            long j9 = jArr[14];
            long j10 = jArr[19];
            long j11 = jArr[24];
            long j12 = (((j6 << c) | (j6 >>> 63)) ^ j11) ^ ((j7 ^ j8) ^ (j9 ^ j10));
            long j13 = jArr[c2];
            long j14 = jArr[7];
            long j15 = jArr[c4];
            long j16 = jArr[c5];
            long j17 = jArr[22];
            long j18 = (j13 ^ j14) ^ (j17 ^ (j15 ^ j16));
            long j19 = jArr[c7];
            long j20 = jArr[5];
            long j21 = jArr[10];
            long j22 = jArr[15];
            long j23 = jArr[c6];
            long j24 = (((j18 << c) | (j18 >>> 63)) ^ j23) ^ ((j19 ^ j20) ^ (j21 ^ j22));
            long j25 = jArr[3];
            long j26 = jArr[c3];
            long j27 = jArr[13];
            long j28 = jArr[18];
            long j29 = jArr[23];
            long j30 = (j25 ^ j26) ^ (j29 ^ (j27 ^ j28));
            long j31 = (((j30 << c) | (j30 >>> 63)) ^ j5) ^ ((j ^ j2) ^ (j3 ^ j4));
            long j32 = (j7 ^ j8) ^ (j11 ^ (j9 ^ j10));
            long j33 = (((j32 << c) | (j32 >>> 63)) ^ j17) ^ ((j13 ^ j14) ^ (j15 ^ j16));
            long j34 = (j19 ^ j20) ^ (j23 ^ (j21 ^ j22));
            long j35 = (((j34 << c) | (j34 >>> 63)) ^ j29) ^ ((j25 ^ j26) ^ (j27 ^ j28));
            long j36 = j19 ^ j12;
            jArr[c7] = j36;
            long j37 = j20 ^ j12;
            jArr[5] = j37;
            long j38 = j21 ^ j12;
            jArr[10] = j38;
            long j39 = j22 ^ j12;
            jArr[15] = j39;
            long j40 = j23 ^ j12;
            jArr[c6] = j40;
            long j41 = j ^ j24;
            jArr[c] = j41;
            long j42 = j2 ^ j24;
            jArr[6] = j42;
            long j43 = j3 ^ j24;
            jArr[11] = j43;
            long j44 = j4 ^ j24;
            jArr[16] = j44;
            long j45 = j5 ^ j24;
            jArr[21] = j45;
            long j46 = j13 ^ j31;
            jArr[c2] = j46;
            long j47 = j14 ^ j31;
            jArr[7] = j47;
            long j48 = j15 ^ j31;
            jArr[c4] = j48;
            long j49 = j16 ^ j31;
            jArr[c5] = j49;
            long j50 = j17 ^ j31;
            jArr[22] = j50;
            long j51 = j25 ^ j33;
            jArr[3] = j51;
            long j52 = j26 ^ j33;
            jArr[c3] = j52;
            long j53 = j27 ^ j33;
            jArr[13] = j53;
            long j54 = j28 ^ j33;
            jArr[18] = j54;
            long j55 = j29 ^ j33;
            jArr[23] = j55;
            long j56 = j7 ^ j35;
            jArr[4] = j56;
            long j57 = j8 ^ j35;
            jArr[9] = j57;
            long j58 = j9 ^ j35;
            jArr[14] = j58;
            long j59 = j10 ^ j35;
            jArr[19] = j59;
            long j60 = j11 ^ j35;
            jArr[24] = j60;
            long j61 = (j37 << 36) | (j37 >>> 28);
            jArr[5] = j61;
            long j62 = (j38 << 3) | (j38 >>> 61);
            jArr[10] = j62;
            long j63 = (j39 << 41) | (j39 >>> 23);
            jArr[15] = j63;
            long j64 = (j40 << 18) | (j40 >>> 46);
            jArr[c6] = j64;
            long j65 = (j41 << c) | (j41 >>> 63);
            jArr[c] = j65;
            long j66 = (j42 << 44) | (j42 >>> c6);
            jArr[6] = j66;
            long j67 = (j43 << 10) | (j43 >>> 54);
            jArr[11] = j67;
            long j68 = (j44 << 45) | (j44 >>> 19);
            jArr[16] = j68;
            long j69 = (j45 << c2) | (j45 >>> 62);
            jArr[21] = j69;
            long j70 = (j46 << 62) | (j46 >>> c2);
            jArr[c2] = j70;
            long j71 = (j47 << 6) | (j47 >>> 58);
            jArr[7] = j71;
            long j72 = (j48 << 43) | (j48 >>> 21);
            jArr[c4] = j72;
            int i2 = i;
            long j73 = (j49 << 15) | (j49 >>> 49);
            jArr[c5] = j73;
            long j74 = (j50 << 61) | (j50 >>> 3);
            jArr[22] = j74;
            long j75 = (j51 << 28) | (j51 >>> 36);
            jArr[3] = j75;
            long j76 = (j52 << 55) | (j52 >>> 9);
            jArr[c3] = j76;
            long j77 = (j53 << 25) | (j53 >>> 39);
            jArr[13] = j77;
            long j78 = (j54 << 21) | (j54 >>> 43);
            jArr[18] = j78;
            long j79 = (j55 << 56) | (j55 >>> c3);
            jArr[23] = j79;
            long j80 = (j56 << 27) | (j56 >>> 37);
            jArr[4] = j80;
            long j81 = (j57 << c6) | (j57 >>> 44);
            jArr[9] = j81;
            long j82 = (j58 << 39) | (j58 >>> 25);
            jArr[14] = j82;
            long j83 = (j59 << c3) | (j59 >>> 56);
            jArr[19] = j83;
            long j84 = (j60 << 14) | (j60 >>> 50);
            jArr[24] = j84;
            long j85 = j36 ^ (j66 | j72);
            long j86 = j66 ^ ((~j72) | j78);
            long j87 = j72 ^ (j78 & j84);
            long j88 = j78 ^ (j84 | j36);
            long j89 = j84 ^ (j36 & j66);
            jArr[0] = j85;
            jArr[6] = j86;
            jArr[12] = j87;
            jArr[18] = j88;
            jArr[24] = j89;
            long j90 = j75 ^ (j81 | j62);
            long j91 = j81 ^ (j62 & j68);
            long j92 = j62 ^ (j68 | (~j74));
            long j93 = j68 ^ (j74 | j75);
            long j94 = j74 ^ (j75 & j81);
            jArr[3] = j90;
            jArr[9] = j91;
            jArr[10] = j92;
            jArr[16] = j93;
            jArr[22] = j94;
            long j95 = ~j83;
            long j96 = j65 ^ (j71 | j77);
            long j97 = j71 ^ (j77 & j83);
            long j98 = j77 ^ (j95 & j64);
            long j99 = j95 ^ (j64 | j65);
            long j100 = j64 ^ (j65 & j71);
            jArr[1] = j96;
            jArr[7] = j97;
            jArr[13] = j98;
            jArr[19] = j99;
            jArr[20] = j100;
            long j101 = ~j73;
            long j102 = j80 ^ (j61 & j67);
            long j103 = j61 ^ (j67 | j73);
            long j104 = j67 ^ (j101 | j79);
            long j105 = j101 ^ (j79 & j80);
            long j106 = j79 ^ (j80 | j61);
            jArr[4] = j102;
            jArr[5] = j103;
            jArr[11] = j104;
            jArr[17] = j105;
            jArr[23] = j106;
            long j107 = ~j76;
            long j108 = j70 ^ (j107 & j82);
            long j109 = j107 ^ (j82 | j63);
            long j110 = j82 ^ (j63 & j69);
            long j111 = j63 ^ (j69 | j70);
            long j112 = j69 ^ (j70 & j76);
            jArr[2] = j108;
            jArr[8] = j109;
            jArr[14] = j110;
            jArr[15] = j111;
            jArr[21] = j112;
            long[] jArr2 = this.f1248RC;
            long j113 = j85 ^ jArr2[i2];
            jArr[0] = j113;
            long j114 = (j86 ^ j91) ^ (j109 ^ (j97 ^ j103));
            long j115 = (((j114 << 1) | (j114 >>> 63)) ^ j112) ^ ((j89 ^ j94) ^ (j100 ^ j106));
            long j116 = (j87 ^ j92) ^ (j110 ^ (j98 ^ j104));
            long j117 = (((j116 << 1) | (j116 >>> 63)) ^ j108) ^ ((j113 ^ j90) ^ (j96 ^ j102));
            long j118 = (j88 ^ j93) ^ (j111 ^ (j99 ^ j105));
            long j119 = (((j118 << 1) | (j118 >>> 63)) ^ j109) ^ ((j86 ^ j91) ^ (j97 ^ j103));
            long j120 = (j89 ^ j94) ^ (j112 ^ (j100 ^ j106));
            long j121 = (((j120 << 1) | (j120 >>> 63)) ^ j110) ^ ((j87 ^ j92) ^ (j98 ^ j104));
            long j122 = (j113 ^ j90) ^ (j108 ^ (j96 ^ j102));
            long j123 = (((j122 << 1) | (j122 >>> 63)) ^ j111) ^ ((j88 ^ j93) ^ (j99 ^ j105));
            long j124 = j113 ^ j115;
            jArr[0] = j124;
            long j125 = j90 ^ j115;
            jArr[3] = j125;
            long j126 = j96 ^ j115;
            jArr[1] = j126;
            long j127 = j102 ^ j115;
            jArr[4] = j127;
            long j128 = j108 ^ j115;
            jArr[2] = j128;
            long j129 = j86 ^ j117;
            jArr[6] = j129;
            long j130 = j91 ^ j117;
            jArr[9] = j130;
            long j131 = j97 ^ j117;
            jArr[7] = j131;
            long j132 = j103 ^ j117;
            jArr[5] = j132;
            long j133 = j109 ^ j117;
            jArr[8] = j133;
            long j134 = j87 ^ j119;
            jArr[12] = j134;
            long j135 = j92 ^ j119;
            jArr[10] = j135;
            long j136 = j98 ^ j119;
            jArr[13] = j136;
            long j137 = j104 ^ j119;
            jArr[11] = j137;
            long j138 = j110 ^ j119;
            jArr[14] = j138;
            long j139 = j88 ^ j121;
            jArr[18] = j139;
            long j140 = j93 ^ j121;
            jArr[16] = j140;
            long j141 = j99 ^ j121;
            jArr[19] = j141;
            long j142 = j105 ^ j121;
            jArr[17] = j142;
            long j143 = j111 ^ j121;
            jArr[15] = j143;
            long j144 = j89 ^ j123;
            jArr[24] = j144;
            long j145 = j94 ^ j123;
            jArr[22] = j145;
            long j146 = j100 ^ j123;
            jArr[20] = j146;
            long j147 = j106 ^ j123;
            jArr[23] = j147;
            long j148 = j112 ^ j123;
            jArr[21] = j148;
            long j149 = (j125 << 36) | (j125 >>> 28);
            jArr[3] = j149;
            long j150 = (j126 << 3) | (j126 >>> 61);
            jArr[1] = j150;
            long j151 = (j127 << 41) | (j127 >>> 23);
            jArr[4] = j151;
            long j152 = (j128 << 18) | (j128 >>> 46);
            jArr[2] = j152;
            long j153 = (j129 << 1) | (j129 >>> 63);
            jArr[6] = j153;
            long j154 = (j130 << 44) | (j130 >>> 20);
            jArr[9] = j154;
            long j155 = (j131 << 10) | (j131 >>> 54);
            jArr[7] = j155;
            long j156 = (j132 << 45) | (j132 >>> 19);
            jArr[5] = j156;
            long j157 = (j133 << 2) | (j133 >>> 62);
            jArr[8] = j157;
            long j158 = (j134 << 62) | (j134 >>> 2);
            jArr[12] = j158;
            long j159 = (j135 << 6) | (j135 >>> 58);
            jArr[10] = j159;
            long j160 = (j136 << 43) | (j136 >>> 21);
            jArr[13] = j160;
            long j161 = (j137 << 15) | (j137 >>> 49);
            jArr[11] = j161;
            long j162 = (j138 << 61) | (j138 >>> 3);
            jArr[14] = j162;
            long j163 = (j139 << 28) | (j139 >>> 36);
            jArr[18] = j163;
            long j164 = (j140 << 55) | (j140 >>> 9);
            jArr[16] = j164;
            long j165 = (j141 << 25) | (j141 >>> 39);
            jArr[19] = j165;
            long j166 = (j142 << 21) | (j142 >>> 43);
            jArr[17] = j166;
            long j167 = (j143 << 56) | (j143 >>> 8);
            jArr[15] = j167;
            long j168 = (j144 << 27) | (j144 >>> 37);
            jArr[24] = j168;
            long j169 = (j145 << 20) | (j145 >>> 44);
            jArr[22] = j169;
            long j170 = (j146 << 39) | (j146 >>> 25);
            jArr[20] = j170;
            long j171 = (j147 << 8) | (j147 >>> 56);
            jArr[23] = j171;
            long j172 = (j148 << 14) | (j148 >>> 50);
            jArr[21] = j172;
            long j173 = j124 ^ (j154 | j160);
            long j174 = j154 ^ ((~j160) | j166);
            long j175 = j160 ^ (j166 & j172);
            long j176 = j166 ^ (j172 | j124);
            long j177 = j172 ^ (j124 & j154);
            jArr[0] = j173;
            jArr[9] = j174;
            jArr[13] = j175;
            jArr[17] = j176;
            jArr[21] = j177;
            long j178 = j163 ^ (j169 | j150);
            long j179 = j169 ^ (j150 & j156);
            long j180 = j150 ^ (j156 | (~j162));
            long j181 = j156 ^ (j162 | j163);
            long j182 = j162 ^ (j163 & j169);
            jArr[18] = j178;
            jArr[22] = j179;
            jArr[1] = j180;
            jArr[5] = j181;
            jArr[14] = j182;
            long j183 = ~j171;
            long j184 = j153 ^ (j159 | j165);
            long j185 = (j165 & j171) ^ j159;
            long j186 = j165 ^ (j183 & j152);
            long j187 = j183 ^ (j152 | j153);
            long j188 = j152 ^ (j153 & j159);
            jArr[6] = j184;
            jArr[10] = j185;
            jArr[19] = j186;
            jArr[23] = j187;
            jArr[2] = j188;
            long j189 = ~j161;
            long j190 = j168 ^ (j149 & j155);
            long j191 = j149 ^ (j155 | j161);
            long j192 = j155 ^ (j189 | j167);
            long j193 = j189 ^ (j167 & j168);
            long j194 = j167 ^ (j168 | j149);
            jArr[24] = j190;
            jArr[3] = j191;
            jArr[7] = j192;
            jArr[11] = j193;
            jArr[15] = j194;
            long j195 = ~j164;
            long j196 = j158 ^ (j195 & j170);
            long j197 = j195 ^ (j170 | j151);
            long j198 = j170 ^ (j151 & j157);
            long j199 = j151 ^ (j157 | j158);
            long j200 = j157 ^ (j158 & j164);
            jArr[12] = j196;
            jArr[16] = j197;
            jArr[20] = j198;
            jArr[4] = j199;
            jArr[8] = j200;
            jArr[0] = j173 ^ jArr2[i2 + 1];
            jArr[5] = j178;
            jArr[18] = j193;
            jArr[11] = j185;
            jArr[10] = j184;
            jArr[6] = j179;
            jArr[22] = j198;
            jArr[20] = j196;
            jArr[12] = j186;
            jArr[19] = j194;
            jArr[15] = j190;
            jArr[24] = j200;
            jArr[8] = j181;
            jArr[1] = j174;
            jArr[9] = j182;
            jArr[14] = j188;
            jArr[2] = j175;
            jArr[13] = j187;
            jArr[23] = j199;
            jArr[4] = j177;
            jArr[21] = j197;
            jArr[16] = j191;
            jArr[3] = j176;
            jArr[17] = j192;
            jArr[7] = j180;
            i = i2 + 2;
            c7 = 0;
            c = 1;
            c2 = 2;
            c3 = '\b';
            c4 = '\f';
            c5 = 17;
            c6 = 20;
        }
        jArr[c] = ~jArr[c];
        jArr[2] = ~jArr[2];
        jArr[8] = ~jArr[8];
        jArr[12] = ~jArr[12];
        jArr[17] = ~jArr[17];
        jArr[20] = ~jArr[20];
    }
}