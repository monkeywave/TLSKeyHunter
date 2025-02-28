package org.bouncycastle.pqc.crypto.sphincsplus;

import androidx.core.view.MotionEventCompat;
import com.google.android.material.internal.ViewUtils;
import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class HarakaSBase {
    protected long[][] haraka512_rc = {new long[]{2652350495371256459L, -4767360454786055294L, -2778808723033108313L, -6138960262205972599L, 4944264682582508575L, 5312892415214084856L, 390034814247088728L, 2584105839607850161L}, new long[]{-2829930801980875922L, 9137660425067592590L, 7974068014816832049L, -4665944065725157058L, 2602240152241800734L, -1525694355931290902L, 8634660511727056099L, 1757945485816280992L}, new long[]{1181946526362588450L, -2765192619992380293L, 3395396416743122529L, -5116273100549372423L, -1285454309797503998L, -3363297609815171261L, -8360835858392998991L, -2371352336613968487L}, new long[]{-2500853454776756032L, 8465221333286591414L, 8817016078209461823L, 9067727467981428858L, 4244107674518258433L, -4347326460570889538L, 1711371409274742987L, 6486926172609168623L}, new long[]{1689001080716996467L, -491496126278250673L, 1273395568185090836L, 5805238412293617850L, -3441289770925384855L, 4592753210857527691L, 7062886034259989751L, -7974393977033172556L}, new long[]{-797818098819718290L, -41460260651793472L, 476036171179798187L, 7391697506481003962L, -855662275170689475L, -3489340839585811635L, -4891525734487956488L, 9110006695579921767L}, new long[]{-886938081943560790L, 4212830408327159617L, -3546674487567282635L, -1955379422127038289L, 3174578079917510314L, 5156046680874954380L, -318545805834821831L, -6176414008149462342L}, new long[]{2529785914229181047L, 2966313764524854080L, 6363694428402697361L, 8292109690175819701L, -8497546332135459587L, -3211108476154815616L, -5526938793786642321L, -4975969843627057770L}, new long[]{3357847021085574721L, -4764837212565187058L, -626391829400648692L, 2124133995575340009L, 7425858999829294301L, -3432032868905637771L, 1119301198758921294L, 1907812968586478892L}, new long[]{-8986524826712832802L, 3356175496741300052L, -5764600317639896362L, 4002747967109689317L, -8718925159733497197L, -1938063772587374661L, -8003749789895945835L, 7302960353763723932L}};
    protected int[][] haraka256_rc = (int[][]) Array.newInstance(Integer.TYPE, 10, 8);
    protected final byte[] buffer = new byte[64];
    protected int off = 0;

    private void Swapn(long[] jArr, int i, int i2, int i3) {
        long j;
        long j2;
        if (i == 1) {
            j = 6148914691236517205L;
            j2 = -6148914691236517206L;
        } else if (i == 2) {
            j = 3689348814741910323L;
            j2 = -3689348814741910324L;
        } else if (i != 4) {
            return;
        } else {
            j = 1085102592571150095L;
            j2 = -1085102592571150096L;
        }
        long j3 = jArr[i2];
        long j4 = jArr[i3];
        jArr[i2] = ((j & j4) << i) | (j3 & j);
        jArr[i3] = ((j3 & j2) >>> i) | (j4 & j2);
    }

    private void Swapn32(int[] iArr, int i, int i2, int i3) {
        int i4;
        int i5;
        if (i == 1) {
            i4 = 1431655765;
            i5 = -1431655766;
        } else if (i == 2) {
            i4 = 858993459;
            i5 = -858993460;
        } else if (i != 4) {
            i4 = 0;
            i5 = 0;
        } else {
            i4 = 252645135;
            i5 = -252645136;
        }
        int i6 = iArr[i2];
        int i7 = iArr[i3];
        iArr[i2] = ((i4 & i7) << i) | (i6 & i4);
        iArr[i3] = ((i6 & i5) >>> i) | (i7 & i5);
    }

    private void addRoundKey(long[] jArr, long[] jArr2) {
        jArr[0] = jArr[0] ^ jArr2[0];
        jArr[1] = jArr[1] ^ jArr2[1];
        jArr[2] = jArr[2] ^ jArr2[2];
        jArr[3] = jArr[3] ^ jArr2[3];
        jArr[4] = jArr[4] ^ jArr2[4];
        jArr[5] = jArr[5] ^ jArr2[5];
        jArr[6] = jArr[6] ^ jArr2[6];
        jArr[7] = jArr[7] ^ jArr2[7];
    }

    private void addRoundKey32(int[] iArr, int[] iArr2) {
        iArr[0] = iArr[0] ^ iArr2[0];
        iArr[1] = iArr[1] ^ iArr2[1];
        iArr[2] = iArr[2] ^ iArr2[2];
        iArr[3] = iArr[3] ^ iArr2[3];
        iArr[4] = iArr[4] ^ iArr2[4];
        iArr[5] = iArr[5] ^ iArr2[5];
        iArr[6] = iArr[6] ^ iArr2[6];
        iArr[7] = iArr2[7] ^ iArr[7];
    }

    private void brAesCt64BitsliceSbox(long[] jArr) {
        long j = jArr[7];
        long j2 = jArr[6];
        long j3 = jArr[5];
        long j4 = jArr[4];
        long j5 = jArr[3];
        long j6 = jArr[2];
        long j7 = jArr[1];
        long j8 = jArr[0];
        long j9 = j4 ^ j6;
        long j10 = j ^ j7;
        long j11 = j ^ j4;
        long j12 = j ^ j6;
        long j13 = j3 ^ j2;
        long j14 = j13 ^ j8;
        long j15 = j14 ^ j4;
        long j16 = j10 ^ j9;
        long j17 = j14 ^ j;
        long j18 = j14 ^ j7;
        long j19 = j18 ^ j12;
        long j20 = j5 ^ j16;
        long j21 = j20 ^ j6;
        long j22 = j2 ^ j20;
        long j23 = j21 ^ j8;
        long j24 = j21 ^ j13;
        long j25 = j22 ^ j11;
        long j26 = j8 ^ j25;
        long j27 = j24 ^ j25;
        long j28 = j13 ^ j25;
        long j29 = j16 & j21;
        long j30 = (j19 & j23) ^ j29;
        long j31 = j10 & j28;
        long j32 = (j18 & j14) ^ j31;
        long j33 = j11 & j25;
        long j34 = (j9 & j27) ^ j33;
        long j35 = (j12 & j24) ^ j33;
        long j36 = (j30 ^ j34) ^ j22;
        long j37 = (((j15 & j8) ^ j29) ^ j35) ^ (j24 ^ j12);
        long j38 = (j32 ^ j34) ^ (j10 ^ j28);
        long j39 = (((j17 & j26) ^ j31) ^ j35) ^ (j ^ j28);
        long j40 = j36 ^ j37;
        long j41 = j36 & j38;
        long j42 = j39 ^ j41;
        long j43 = (j40 & j42) ^ j37;
        long j44 = ((j37 ^ j41) & (j38 ^ j39)) ^ j39;
        long j45 = j39 & (j42 ^ j44);
        long j46 = j45 ^ (j38 ^ j44);
        long j47 = j40 ^ (j43 & (j42 ^ j45));
        long j48 = j47 ^ j46;
        long j49 = j43 ^ j44;
        long j50 = j43 ^ j47;
        long j51 = j44 ^ j46;
        long j52 = j49 ^ j48;
        long j53 = j44 & j8;
        long j54 = j50 & j28;
        long j55 = j47 & j14;
        long j56 = j43 & j26;
        long j57 = j52 & j27;
        long j58 = j46 & j19;
        long j59 = j44 & j15;
        long j60 = j50 & j10;
        long j61 = j47 & j18;
        long j62 = j49 & j11;
        long j63 = j52 & j9;
        long j64 = j48 & j12;
        long j65 = j62 ^ j63;
        long j66 = j56 ^ j61;
        long j67 = (j51 & j16) ^ j58;
        long j68 = (j51 & j21) ^ j54;
        long j69 = j63 ^ j64;
        long j70 = (j53 ^ j60) ^ j68;
        long j71 = j55 ^ j65;
        long j72 = j54 ^ ((j49 & j25) ^ j57);
        long j73 = j65 ^ j70;
        long j74 = (j43 & j17) ^ j70;
        long j75 = (j57 ^ (j48 & j24)) ^ j71;
        long j76 = j67 ^ j71;
        long j77 = j55 ^ j72;
        long j78 = j74 ^ j75;
        long j79 = (j46 & j23) ^ j76;
        long j80 = j68 ^ j79;
        jArr[7] = j72 ^ j76;
        jArr[6] = j77 ^ (~j80);
        jArr[5] = j69 ^ (~(j77 ^ j78));
        jArr[4] = j80;
        jArr[3] = (j53 ^ j56) ^ j79;
        jArr[2] = (j58 ^ j59) ^ j78;
        jArr[1] = (~j75) ^ (j60 ^ j66);
        jArr[0] = j66 ^ (~j73);
    }

    private void brAesCt64InterleaveIn(long[] jArr, int i, int[] iArr, int i2) {
        long j = iArr[i2] & BodyPartID.bodyIdMax;
        long j2 = iArr[i2 + 1] & BodyPartID.bodyIdMax;
        long j3 = iArr[i2 + 2] & BodyPartID.bodyIdMax;
        long j4 = iArr[i2 + 3] & BodyPartID.bodyIdMax;
        long j5 = (j | (j << 16)) & 281470681808895L;
        long j6 = (j2 | (j2 << 16)) & 281470681808895L;
        long j7 = (j3 | (j3 << 16)) & 281470681808895L;
        long j8 = (j4 | (j4 << 16)) & 281470681808895L;
        jArr[i] = ((j5 | (j5 << 8)) & 71777214294589695L) | (((j7 | (j7 << 8)) & 71777214294589695L) << 8);
        long j9 = ((j8 | (j8 << 8)) & 71777214294589695L) << 8;
        jArr[i + 4] = j9 | ((j6 | (j6 << 8)) & 71777214294589695L);
    }

    private void brAesCt64InterleaveOut(int[] iArr, long[] jArr, int i) {
        long j = jArr[i];
        long j2 = j & 71777214294589695L;
        long j3 = jArr[i + 4];
        long j4 = j3 & 71777214294589695L;
        long j5 = (j >>> 8) & 71777214294589695L;
        long j6 = 71777214294589695L & (j3 >>> 8);
        long j7 = (j2 | (j2 >>> 8)) & 281470681808895L;
        long j8 = ((j4 >>> 8) | j4) & 281470681808895L;
        long j9 = (j5 | (j5 >>> 8)) & 281470681808895L;
        long j10 = (j6 | (j6 >>> 8)) & 281470681808895L;
        int i2 = i << 2;
        iArr[i2] = (int) (j7 | (j7 >>> 16));
        iArr[i2 + 1] = (int) (j8 | (j8 >>> 16));
        iArr[i2 + 2] = (int) (j9 | (j9 >>> 16));
        iArr[i2 + 3] = (int) ((j10 >>> 16) | j10);
    }

    private void brAesCt64Ortho(long[] jArr) {
        Swapn(jArr, 1, 0, 1);
        Swapn(jArr, 1, 2, 3);
        Swapn(jArr, 1, 4, 5);
        Swapn(jArr, 1, 6, 7);
        Swapn(jArr, 2, 0, 2);
        Swapn(jArr, 2, 1, 3);
        Swapn(jArr, 2, 4, 6);
        Swapn(jArr, 2, 5, 7);
        Swapn(jArr, 4, 0, 4);
        Swapn(jArr, 4, 1, 5);
        Swapn(jArr, 4, 2, 6);
        Swapn(jArr, 4, 3, 7);
    }

    private static void brAesCtBitsliceSbox(int[] iArr) {
        int i = iArr[7];
        int i2 = iArr[6];
        int i3 = iArr[5];
        int i4 = iArr[4];
        int i5 = iArr[3];
        int i6 = iArr[2];
        int i7 = iArr[1];
        int i8 = iArr[0];
        int i9 = i4 ^ i6;
        int i10 = i ^ i7;
        int i11 = i ^ i4;
        int i12 = i ^ i6;
        int i13 = i3 ^ i2;
        int i14 = i13 ^ i8;
        int i15 = i14 ^ i4;
        int i16 = i10 ^ i9;
        int i17 = i14 ^ i;
        int i18 = i14 ^ i7;
        int i19 = i18 ^ i12;
        int i20 = i5 ^ i16;
        int i21 = i6 ^ i20;
        int i22 = i2 ^ i20;
        int i23 = i21 ^ i8;
        int i24 = i21 ^ i13;
        int i25 = i22 ^ i11;
        int i26 = i8 ^ i25;
        int i27 = i24 ^ i25;
        int i28 = i13 ^ i25;
        int i29 = i16 & i21;
        int i30 = (i19 & i23) ^ i29;
        int i31 = i10 & i28;
        int i32 = (i18 & i14) ^ i31;
        int i33 = i11 & i25;
        int i34 = (i9 & i27) ^ i33;
        int i35 = (i12 & i24) ^ i33;
        int i36 = (i30 ^ i34) ^ i22;
        int i37 = (((i15 & i8) ^ i29) ^ i35) ^ (i24 ^ i12);
        int i38 = (i32 ^ i34) ^ (i10 ^ i28);
        int i39 = (((i17 & i26) ^ i31) ^ i35) ^ (i ^ i28);
        int i40 = i36 ^ i37;
        int i41 = i36 & i38;
        int i42 = i39 ^ i41;
        int i43 = (i40 & i42) ^ i37;
        int i44 = ((i37 ^ i41) & (i38 ^ i39)) ^ i39;
        int i45 = i39 & (i42 ^ i44);
        int i46 = i45 ^ (i38 ^ i44);
        int i47 = i40 ^ (i43 & (i42 ^ i45));
        int i48 = i47 ^ i46;
        int i49 = i43 ^ i44;
        int i50 = i43 ^ i47;
        int i51 = i44 ^ i46;
        int i52 = i49 ^ i48;
        int i53 = i8 & i44;
        int i54 = i50 & i28;
        int i55 = i47 & i14;
        int i56 = i43 & i26;
        int i57 = i52 & i27;
        int i58 = i46 & i19;
        int i59 = i44 & i15;
        int i60 = i50 & i10;
        int i61 = i47 & i18;
        int i62 = i49 & i11;
        int i63 = i52 & i9;
        int i64 = i48 & i12;
        int i65 = i62 ^ i63;
        int i66 = i56 ^ i61;
        int i67 = (i51 & i16) ^ i58;
        int i68 = (i51 & i21) ^ i54;
        int i69 = i63 ^ i64;
        int i70 = (i53 ^ i60) ^ i68;
        int i71 = i55 ^ i65;
        int i72 = i54 ^ ((i49 & i25) ^ i57);
        int i73 = i65 ^ i70;
        int i74 = (i43 & i17) ^ i70;
        int i75 = (i57 ^ (i48 & i24)) ^ i71;
        int i76 = i67 ^ i71;
        int i77 = i55 ^ i72;
        int i78 = i74 ^ i75;
        int i79 = (i46 & i23) ^ i76;
        int i80 = (i60 ^ i66) ^ (~i75);
        int i81 = i66 ^ (~i73);
        int i82 = i68 ^ i79;
        iArr[7] = i72 ^ i76;
        iArr[6] = i77 ^ (~i82);
        iArr[5] = i69 ^ (~(i77 ^ i78));
        iArr[4] = i82;
        iArr[3] = i79 ^ (i53 ^ i56);
        iArr[2] = (i58 ^ i59) ^ i78;
        iArr[1] = i80;
        iArr[0] = i81;
    }

    private void brAesCtOrtho(int[] iArr) {
        Swapn32(iArr, 1, 0, 1);
        Swapn32(iArr, 1, 2, 3);
        Swapn32(iArr, 1, 4, 5);
        Swapn32(iArr, 1, 6, 7);
        Swapn32(iArr, 2, 0, 2);
        Swapn32(iArr, 2, 1, 3);
        Swapn32(iArr, 2, 4, 6);
        Swapn32(iArr, 2, 5, 7);
        Swapn32(iArr, 4, 0, 4);
        Swapn32(iArr, 4, 1, 5);
        Swapn32(iArr, 4, 2, 6);
        Swapn32(iArr, 4, 3, 7);
    }

    private int brDec32Le(byte[] bArr, int i) {
        return (bArr[i + 3] << 24) | (bArr[i] & UByte.MAX_VALUE) | ((bArr[i + 1] << 8) & MotionEventCompat.ACTION_POINTER_INDEX_MASK) | ((bArr[i + 2] << 16) & 16711680);
    }

    private void brEnc32Le(byte[] bArr, int i, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            bArr[i2 + i3] = (byte) (i >> (i3 << 3));
        }
    }

    private void brRangeDec32Le(byte[] bArr, int[] iArr, int i) {
        for (int i2 = 0; i2 < iArr.length; i2++) {
            int i3 = (i2 << 2) + i;
            iArr[i2] = (bArr[i3 + 3] << 24) | (bArr[i3] & 255) | ((bArr[i3 + 1] << 8) & MotionEventCompat.ACTION_POINTER_INDEX_MASK) | ((bArr[i3 + 2] << 16) & 16711680);
        }
    }

    private void mixColumns(long[] jArr) {
        long j = jArr[0];
        long j2 = jArr[1];
        long j3 = jArr[2];
        long j4 = jArr[3];
        long j5 = jArr[4];
        long j6 = jArr[5];
        long j7 = jArr[6];
        long j8 = jArr[7];
        long j9 = (j >>> 16) | (j << 48);
        long j10 = (j2 >>> 16) | (j2 << 48);
        long j11 = (j3 >>> 16) | (j3 << 48);
        long j12 = (j4 >>> 16) | (j4 << 48);
        long j13 = (j5 >>> 16) | (j5 << 48);
        long j14 = (j6 >>> 16) | (j6 << 48);
        long j15 = (j7 >>> 16) | (j7 << 48);
        long j16 = (j8 >>> 16) | (j8 << 48);
        long j17 = j8 ^ j16;
        long j18 = j ^ j9;
        jArr[0] = (j17 ^ j9) ^ rotr32(j18);
        long j19 = j2 ^ j10;
        jArr[1] = (((j18 ^ j8) ^ j16) ^ j10) ^ rotr32(j19);
        long j20 = j3 ^ j11;
        jArr[2] = (j19 ^ j11) ^ rotr32(j20);
        long j21 = j4 ^ j12;
        jArr[3] = (((j20 ^ j8) ^ j16) ^ j12) ^ rotr32(j21);
        long j22 = j5 ^ j13;
        jArr[4] = (((j21 ^ j8) ^ j16) ^ j13) ^ rotr32(j22);
        long j23 = j22 ^ j14;
        long j24 = j6 ^ j14;
        jArr[5] = j23 ^ rotr32(j24);
        long j25 = j24 ^ j15;
        long j26 = j7 ^ j15;
        jArr[6] = j25 ^ rotr32(j26);
        jArr[7] = (j26 ^ j16) ^ rotr32(j17);
    }

    private void mixColumns32(int[] iArr) {
        int i = iArr[0];
        int i2 = iArr[1];
        int i3 = iArr[2];
        int i4 = iArr[3];
        int i5 = iArr[4];
        int i6 = iArr[5];
        int i7 = iArr[6];
        int i8 = iArr[7];
        int i9 = (i >>> 8) | (i << 24);
        int i10 = (i2 >>> 8) | (i2 << 24);
        int i11 = (i3 >>> 8) | (i3 << 24);
        int i12 = (i4 >>> 8) | (i4 << 24);
        int i13 = (i5 >>> 8) | (i5 << 24);
        int i14 = (i6 >>> 8) | (i6 << 24);
        int i15 = (i7 >>> 8) | (i7 << 24);
        int i16 = (i8 >>> 8) | (i8 << 24);
        int i17 = i8 ^ i16;
        int i18 = i ^ i9;
        iArr[0] = (i17 ^ i9) ^ rotr16(i18);
        int i19 = i2 ^ i10;
        iArr[1] = (((i18 ^ i8) ^ i16) ^ i10) ^ rotr16(i19);
        int i20 = i19 ^ i11;
        int i21 = i3 ^ i11;
        iArr[2] = i20 ^ rotr16(i21);
        int i22 = i4 ^ i12;
        iArr[3] = (((i21 ^ i8) ^ i16) ^ i12) ^ rotr16(i22);
        int i23 = i5 ^ i13;
        iArr[4] = (((i22 ^ i8) ^ i16) ^ i13) ^ rotr16(i23);
        int i24 = i23 ^ i14;
        int i25 = i6 ^ i14;
        iArr[5] = i24 ^ rotr16(i25);
        int i26 = i25 ^ i15;
        int i27 = i7 ^ i15;
        iArr[6] = i26 ^ rotr16(i27);
        iArr[7] = (i27 ^ i16) ^ rotr16(i17);
    }

    private int rotr16(int i) {
        return (i >>> 16) | (i << 16);
    }

    private long rotr32(long j) {
        return (j >>> 32) | (j << 32);
    }

    private void shiftRows(long[] jArr) {
        for (int i = 0; i < jArr.length; i++) {
            long j = jArr[i];
            jArr[i] = ((j & 1152640029630136320L) << 4) | (65535 & j) | ((4293918720L & j) >>> 4) | ((983040 & j) << 12) | ((280375465082880L & j) >>> 8) | ((1095216660480L & j) << 8) | (((-1152921504606846976L) & j) >>> 12);
        }
    }

    private void shiftRows32(int[] iArr) {
        for (int i = 0; i < 8; i++) {
            int i2 = iArr[i];
            iArr[i] = ((i2 & 1056964608) << 2) | (i2 & 255) | ((64512 & i2) >>> 2) | ((i2 & ViewUtils.EDGE_TO_EDGE_FLAGS) << 6) | ((15728640 & i2) >>> 4) | ((983040 & i2) << 4) | (((-1073741824) & i2) >>> 6);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void xor(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4) {
        for (int i5 = 0; i5 < i4; i5++) {
            bArr3[i3 + i5] = (byte) (bArr[i + i5] ^ bArr2[i2 + i5]);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void haraka256Perm(byte[] bArr) {
        int[] iArr = new int[8];
        interleaveConstant32(iArr, this.buffer, 0);
        for (int i = 0; i < 5; i++) {
            for (int i2 = 0; i2 < 2; i2++) {
                brAesCtBitsliceSbox(iArr);
                shiftRows32(iArr);
                mixColumns32(iArr);
                addRoundKey32(iArr, this.haraka256_rc[(i << 1) + i2]);
            }
            for (int i3 = 0; i3 < 8; i3++) {
                int i4 = iArr[i3];
                iArr[i3] = ((i4 & 1077952576) >>> 1) | ((-2122219135) & i4) | ((33686018 & i4) << 1) | ((67372036 & i4) << 2) | ((134744072 & i4) << 3) | ((269488144 & i4) >>> 3) | ((538976288 & i4) >>> 2);
            }
        }
        brAesCtOrtho(iArr);
        for (int i5 = 0; i5 < 4; i5++) {
            int i6 = i5 << 1;
            int i7 = i5 << 2;
            brEnc32Le(bArr, iArr[i6], i7);
            brEnc32Le(bArr, iArr[i6 + 1], i7 + 16);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void haraka512Perm(byte[] bArr) {
        int[] iArr = new int[16];
        long[] jArr = new long[8];
        brRangeDec32Le(this.buffer, iArr, 0);
        for (int i = 0; i < 4; i++) {
            brAesCt64InterleaveIn(jArr, i, iArr, i << 2);
        }
        brAesCt64Ortho(jArr);
        for (int i2 = 0; i2 < 5; i2++) {
            for (int i3 = 0; i3 < 2; i3++) {
                brAesCt64BitsliceSbox(jArr);
                shiftRows(jArr);
                mixColumns(jArr);
                addRoundKey(jArr, this.haraka512_rc[(i2 << 1) + i3]);
            }
            for (int i4 = 0; i4 < 8; i4++) {
                long j = jArr[i4];
                jArr[i4] = ((j & (-8934996522953571328L)) >>> 3) | ((281479271743489L & j) << 5) | ((562958543486978L & j) << 12) | ((1125917086973956L & j) >>> 1) | ((2251834173947912L & j) << 6) | ((9007336695791648L & j) << 9) | ((18014673391583296L & j) >>> 4) | ((36029346783166592L & j) << 3) | ((2377936887688995072L & j) >>> 5) | ((148621055480562192L & j) << 2) | ((576469548530665472L & j) << 4) | ((1152939097061330944L & j) >>> 12) | ((4611756388245323776L & j) >>> 10);
            }
        }
        brAesCt64Ortho(jArr);
        for (int i5 = 0; i5 < 4; i5++) {
            brAesCt64InterleaveOut(iArr, jArr, i5);
        }
        for (int i6 = 0; i6 < 16; i6++) {
            for (int i7 = 0; i7 < 4; i7++) {
                bArr[(i6 << 2) + i7] = (byte) ((iArr[i6] >>> (i7 << 3)) & 255);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void interleaveConstant(long[] jArr, byte[] bArr, int i) {
        int[] iArr = new int[16];
        brRangeDec32Le(bArr, iArr, i);
        for (int i2 = 0; i2 < 4; i2++) {
            brAesCt64InterleaveIn(jArr, i2, iArr, i2 << 2);
        }
        brAesCt64Ortho(jArr);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void interleaveConstant32(int[] iArr, byte[] bArr, int i) {
        for (int i2 = 0; i2 < 4; i2++) {
            int i3 = i2 << 1;
            int i4 = (i2 << 2) + i;
            iArr[i3] = brDec32Le(bArr, i4);
            iArr[i3 + 1] = brDec32Le(bArr, i4 + 16);
        }
        brAesCtOrtho(iArr);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void reset() {
        this.off = 0;
        Arrays.clear(this.buffer);
    }
}