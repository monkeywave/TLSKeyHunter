package org.bouncycastle.crypto.digests;

import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public abstract class LongDigest implements ExtendedDigest, Memoable, EncodableDigest {
    private static final int BYTE_LENGTH = 128;

    /* renamed from: K */
    static final long[] f436K = {4794697086780616226L, 8158064640168781261L, -5349999486874862801L, -1606136188198331460L, 4131703408338449720L, 6480981068601479193L, -7908458776815382629L, -6116909921290321640L, -2880145864133508542L, 1334009975649890238L, 2608012711638119052L, 6128411473006802146L, 8268148722764581231L, -9160688886553864527L, -7215885187991268811L, -4495734319001033068L, -1973867731355612462L, -1171420211273849373L, 1135362057144423861L, 2597628984639134821L, 3308224258029322869L, 5365058923640841347L, 6679025012923562964L, 8573033837759648693L, -7476448914759557205L, -6327057829258317296L, -5763719355590565569L, -4658551843659510044L, -4116276920077217854L, -3051310485924567259L, 489312712824947311L, 1452737877330783856L, 2861767655752347644L, 3322285676063803686L, 5560940570517711597L, 5996557281743188959L, 7280758554555802590L, 8532644243296465576L, -9096487096722542874L, -7894198246740708037L, -6719396339535248540L, -6333637450476146687L, -4446306890439682159L, -4076793802049405392L, -3345356375505022440L, -2983346525034927856L, -860691631967231958L, 1182934255886127544L, 1847814050463011016L, 2177327727835720531L, 2830643537854262169L, 3796741975233480872L, 4115178125766777443L, 5681478168544905931L, 6601373596472566643L, 7507060721942968483L, 8399075790359081724L, 8693463985226723168L, -8878714635349349518L, -8302665154208450068L, -8016688836872298968L, -6606660893046293015L, -4685533653050689259L, -4147400797238176981L, -3880063495543823972L, -3348786107499101689L, -1523767162380948706L, -757361751448694408L, 500013540394364858L, 748580250866718886L, 1242879168328830382L, 1977374033974150939L, 2944078676154940804L, 3659926193048069267L, 4368137639120453308L, 4836135668995329356L, 5532061633213252278L, 6448918945643986474L, 6902733635092675308L, 7801388544844847127L};

    /* renamed from: H1 */
    protected long f437H1;

    /* renamed from: H2 */
    protected long f438H2;

    /* renamed from: H3 */
    protected long f439H3;

    /* renamed from: H4 */
    protected long f440H4;

    /* renamed from: H5 */
    protected long f441H5;

    /* renamed from: H6 */
    protected long f442H6;

    /* renamed from: H7 */
    protected long f443H7;

    /* renamed from: H8 */
    protected long f444H8;

    /* renamed from: W */
    private long[] f445W;
    private long byteCount1;
    private long byteCount2;
    protected final CryptoServicePurpose purpose;
    private int wOff;
    private byte[] xBuf;
    private int xBufOff;

    /* JADX INFO: Access modifiers changed from: protected */
    public LongDigest() {
        this(CryptoServicePurpose.ANY);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public LongDigest(CryptoServicePurpose cryptoServicePurpose) {
        this.xBuf = new byte[8];
        this.f445W = new long[80];
        this.purpose = cryptoServicePurpose;
        this.xBufOff = 0;
        reset();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public LongDigest(LongDigest longDigest) {
        this.xBuf = new byte[8];
        this.f445W = new long[80];
        this.purpose = longDigest.purpose;
        copyIn(longDigest);
    }

    /* renamed from: Ch */
    private long m131Ch(long j, long j2, long j3) {
        return ((~j) & j3) ^ (j2 & j);
    }

    private long Maj(long j, long j2, long j3) {
        return ((j & j3) ^ (j & j2)) ^ (j2 & j3);
    }

    private long Sigma0(long j) {
        return (j >>> 7) ^ (((j << 63) | (j >>> 1)) ^ ((j << 56) | (j >>> 8)));
    }

    private long Sigma1(long j) {
        return (j >>> 6) ^ (((j << 45) | (j >>> 19)) ^ ((j << 3) | (j >>> 61)));
    }

    private long Sum0(long j) {
        return ((j >>> 39) | (j << 25)) ^ (((j << 36) | (j >>> 28)) ^ ((j << 30) | (j >>> 34)));
    }

    private long Sum1(long j) {
        return ((j >>> 41) | (j << 23)) ^ (((j << 50) | (j >>> 14)) ^ ((j << 46) | (j >>> 18)));
    }

    private void adjustByteCounts() {
        long j = this.byteCount1;
        if (j > 2305843009213693951L) {
            this.byteCount2 += j >>> 61;
            this.byteCount1 = j & 2305843009213693951L;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void copyIn(LongDigest longDigest) {
        byte[] bArr = longDigest.xBuf;
        System.arraycopy(bArr, 0, this.xBuf, 0, bArr.length);
        this.xBufOff = longDigest.xBufOff;
        this.byteCount1 = longDigest.byteCount1;
        this.byteCount2 = longDigest.byteCount2;
        this.f437H1 = longDigest.f437H1;
        this.f438H2 = longDigest.f438H2;
        this.f439H3 = longDigest.f439H3;
        this.f440H4 = longDigest.f440H4;
        this.f441H5 = longDigest.f441H5;
        this.f442H6 = longDigest.f442H6;
        this.f443H7 = longDigest.f443H7;
        this.f444H8 = longDigest.f444H8;
        long[] jArr = longDigest.f445W;
        System.arraycopy(jArr, 0, this.f445W, 0, jArr.length);
        this.wOff = longDigest.wOff;
    }

    protected abstract CryptoServiceProperties cryptoServiceProperties();

    public void finish() {
        adjustByteCounts();
        long j = this.byteCount1 << 3;
        long j2 = this.byteCount2;
        byte b = ByteCompanionObject.MIN_VALUE;
        while (true) {
            update(b);
            if (this.xBufOff == 0) {
                processLength(j, j2);
                processBlock();
                return;
            }
            b = 0;
        }
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 128;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getEncodedStateSize() {
        return (this.wOff * 8) + 96;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void populateState(byte[] bArr) {
        System.arraycopy(this.xBuf, 0, bArr, 0, this.xBufOff);
        Pack.intToBigEndian(this.xBufOff, bArr, 8);
        Pack.longToBigEndian(this.byteCount1, bArr, 12);
        Pack.longToBigEndian(this.byteCount2, bArr, 20);
        Pack.longToBigEndian(this.f437H1, bArr, 28);
        Pack.longToBigEndian(this.f438H2, bArr, 36);
        Pack.longToBigEndian(this.f439H3, bArr, 44);
        Pack.longToBigEndian(this.f440H4, bArr, 52);
        Pack.longToBigEndian(this.f441H5, bArr, 60);
        Pack.longToBigEndian(this.f442H6, bArr, 68);
        Pack.longToBigEndian(this.f443H7, bArr, 76);
        Pack.longToBigEndian(this.f444H8, bArr, 84);
        Pack.intToBigEndian(this.wOff, bArr, 92);
        for (int i = 0; i < this.wOff; i++) {
            Pack.longToBigEndian(this.f445W[i], bArr, (i * 8) + 96);
        }
    }

    protected void processBlock() {
        adjustByteCounts();
        for (int i = 16; i <= 79; i++) {
            long[] jArr = this.f445W;
            long Sigma1 = Sigma1(jArr[i - 2]);
            long[] jArr2 = this.f445W;
            jArr[i] = Sigma1 + jArr2[i - 7] + Sigma0(jArr2[i - 15]) + this.f445W[i - 16];
        }
        long j = this.f437H1;
        long j2 = this.f438H2;
        long j3 = this.f439H3;
        long j4 = this.f440H4;
        long j5 = this.f441H5;
        long j6 = this.f442H6;
        long j7 = this.f443H7;
        long j8 = j6;
        long j9 = j4;
        int i2 = 0;
        long j10 = j2;
        long j11 = j3;
        long j12 = j5;
        int i3 = 0;
        long j13 = this.f444H8;
        long j14 = j;
        long j15 = j7;
        while (i3 < 10) {
            long j16 = j12;
            long[] jArr3 = f436K;
            int i4 = i2 + 1;
            long Sum1 = j13 + Sum1(j12) + m131Ch(j12, j8, j15) + jArr3[i2] + this.f445W[i2];
            long j17 = j9 + Sum1;
            long Sum0 = Sum1 + Sum0(j14) + Maj(j14, j10, j11);
            int i5 = i2 + 2;
            long Sum12 = j15 + Sum1(j17) + m131Ch(j17, j16, j8) + jArr3[i4] + this.f445W[i4];
            long j18 = j11 + Sum12;
            long Sum02 = Sum12 + Sum0(Sum0) + Maj(Sum0, j14, j10);
            int i6 = i2 + 3;
            long Sum13 = j8 + Sum1(j18) + m131Ch(j18, j17, j16) + jArr3[i5] + this.f445W[i5];
            long j19 = j10 + Sum13;
            long Sum03 = Sum13 + Sum0(Sum02) + Maj(Sum02, Sum0, j14);
            int i7 = i2 + 4;
            long Sum14 = j16 + Sum1(j19) + m131Ch(j19, j18, j17) + jArr3[i6] + this.f445W[i6];
            long j20 = j14 + Sum14;
            long Sum04 = Sum14 + Sum0(Sum03) + Maj(Sum03, Sum02, Sum0);
            int i8 = i2 + 5;
            long Sum15 = j17 + Sum1(j20) + m131Ch(j20, j19, j18) + jArr3[i7] + this.f445W[i7];
            long j21 = Sum0 + Sum15;
            long Sum05 = Sum15 + Sum0(Sum04) + Maj(Sum04, Sum03, Sum02);
            int i9 = i2 + 6;
            long Sum16 = j18 + Sum1(j21) + m131Ch(j21, j20, j19) + jArr3[i8] + this.f445W[i8];
            long j22 = Sum02 + Sum16;
            long Sum06 = Sum16 + Sum0(Sum05) + Maj(Sum05, Sum04, Sum03);
            j15 = j22;
            int i10 = i2 + 7;
            long Sum17 = j19 + Sum1(j22) + m131Ch(j22, j21, j20) + jArr3[i9] + this.f445W[i9];
            long j23 = Sum03 + Sum17;
            j8 = j23;
            j10 = Sum17 + Sum0(Sum06) + Maj(Sum06, Sum05, Sum04);
            i2 += 8;
            long Sum18 = j20 + Sum1(j23) + m131Ch(j23, j15, j21) + jArr3[i10] + this.f445W[i10];
            long Sum07 = Sum18 + Sum0(j10) + Maj(j10, Sum06, Sum05);
            i3++;
            j12 = Sum04 + Sum18;
            j11 = Sum06;
            j13 = j21;
            j9 = Sum05;
            j14 = Sum07;
        }
        this.f437H1 += j14;
        this.f438H2 += j10;
        this.f439H3 += j11;
        this.f440H4 += j9;
        this.f441H5 += j12;
        this.f442H6 += j8;
        this.f443H7 += j15;
        this.f444H8 += j13;
        this.wOff = 0;
        for (int i11 = 0; i11 < 16; i11++) {
            this.f445W[i11] = 0;
        }
    }

    protected void processLength(long j, long j2) {
        if (this.wOff > 14) {
            processBlock();
        }
        long[] jArr = this.f445W;
        jArr[14] = j2;
        jArr[15] = j;
    }

    protected void processWord(byte[] bArr, int i) {
        this.f445W[this.wOff] = Pack.bigEndianToLong(bArr, i);
        int i2 = this.wOff + 1;
        this.wOff = i2;
        if (i2 == 16) {
            processBlock();
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.byteCount1 = 0L;
        this.byteCount2 = 0L;
        int i = 0;
        this.xBufOff = 0;
        int i2 = 0;
        while (true) {
            byte[] bArr = this.xBuf;
            if (i2 >= bArr.length) {
                break;
            }
            bArr[i2] = 0;
            i2++;
        }
        this.wOff = 0;
        while (true) {
            long[] jArr = this.f445W;
            if (i == jArr.length) {
                return;
            }
            jArr[i] = 0;
            i++;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void restoreState(byte[] bArr) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, 8);
        this.xBufOff = bigEndianToInt;
        System.arraycopy(bArr, 0, this.xBuf, 0, bigEndianToInt);
        this.byteCount1 = Pack.bigEndianToLong(bArr, 12);
        this.byteCount2 = Pack.bigEndianToLong(bArr, 20);
        this.f437H1 = Pack.bigEndianToLong(bArr, 28);
        this.f438H2 = Pack.bigEndianToLong(bArr, 36);
        this.f439H3 = Pack.bigEndianToLong(bArr, 44);
        this.f440H4 = Pack.bigEndianToLong(bArr, 52);
        this.f441H5 = Pack.bigEndianToLong(bArr, 60);
        this.f442H6 = Pack.bigEndianToLong(bArr, 68);
        this.f443H7 = Pack.bigEndianToLong(bArr, 76);
        this.f444H8 = Pack.bigEndianToLong(bArr, 84);
        this.wOff = Pack.bigEndianToInt(bArr, 92);
        for (int i = 0; i < this.wOff; i++) {
            this.f445W[i] = Pack.bigEndianToLong(bArr, (i * 8) + 96);
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        int i2 = i + 1;
        this.xBufOff = i2;
        bArr[i] = b;
        if (i2 == bArr.length) {
            processWord(bArr, 0);
            this.xBufOff = 0;
        }
        this.byteCount1++;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        while (this.xBufOff != 0 && i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
        while (i2 >= this.xBuf.length) {
            processWord(bArr, i);
            byte[] bArr2 = this.xBuf;
            i += bArr2.length;
            i2 -= bArr2.length;
            this.byteCount1 += bArr2.length;
        }
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }
}