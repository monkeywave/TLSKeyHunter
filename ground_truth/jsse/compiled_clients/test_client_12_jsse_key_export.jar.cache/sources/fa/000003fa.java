package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/LongDigest.class */
public abstract class LongDigest implements ExtendedDigest, Memoable, EncodableDigest {
    private static final int BYTE_LENGTH = 128;
    private byte[] xBuf;
    private int xBufOff;
    private long byteCount1;
    private long byteCount2;

    /* renamed from: H1 */
    protected long f167H1;

    /* renamed from: H2 */
    protected long f168H2;

    /* renamed from: H3 */
    protected long f169H3;

    /* renamed from: H4 */
    protected long f170H4;

    /* renamed from: H5 */
    protected long f171H5;

    /* renamed from: H6 */
    protected long f172H6;

    /* renamed from: H7 */
    protected long f173H7;

    /* renamed from: H8 */
    protected long f174H8;

    /* renamed from: W */
    private long[] f175W;
    private int wOff;

    /* renamed from: K */
    static final long[] f176K = {4794697086780616226L, 8158064640168781261L, -5349999486874862801L, -1606136188198331460L, 4131703408338449720L, 6480981068601479193L, -7908458776815382629L, -6116909921290321640L, -2880145864133508542L, 1334009975649890238L, 2608012711638119052L, 6128411473006802146L, 8268148722764581231L, -9160688886553864527L, -7215885187991268811L, -4495734319001033068L, -1973867731355612462L, -1171420211273849373L, 1135362057144423861L, 2597628984639134821L, 3308224258029322869L, 5365058923640841347L, 6679025012923562964L, 8573033837759648693L, -7476448914759557205L, -6327057829258317296L, -5763719355590565569L, -4658551843659510044L, -4116276920077217854L, -3051310485924567259L, 489312712824947311L, 1452737877330783856L, 2861767655752347644L, 3322285676063803686L, 5560940570517711597L, 5996557281743188959L, 7280758554555802590L, 8532644243296465576L, -9096487096722542874L, -7894198246740708037L, -6719396339535248540L, -6333637450476146687L, -4446306890439682159L, -4076793802049405392L, -3345356375505022440L, -2983346525034927856L, -860691631967231958L, 1182934255886127544L, 1847814050463011016L, 2177327727835720531L, 2830643537854262169L, 3796741975233480872L, 4115178125766777443L, 5681478168544905931L, 6601373596472566643L, 7507060721942968483L, 8399075790359081724L, 8693463985226723168L, -8878714635349349518L, -8302665154208450068L, -8016688836872298968L, -6606660893046293015L, -4685533653050689259L, -4147400797238176981L, -3880063495543823972L, -3348786107499101689L, -1523767162380948706L, -757361751448694408L, 500013540394364858L, 748580250866718886L, 1242879168328830382L, 1977374033974150939L, 2944078676154940804L, 3659926193048069267L, 4368137639120453308L, 4836135668995329356L, 5532061633213252278L, 6448918945643986474L, 6902733635092675308L, 7801388544844847127L};

    /* JADX INFO: Access modifiers changed from: protected */
    public LongDigest() {
        this.xBuf = new byte[8];
        this.f175W = new long[80];
        this.xBufOff = 0;
        reset();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public LongDigest(LongDigest longDigest) {
        this.xBuf = new byte[8];
        this.f175W = new long[80];
        copyIn(longDigest);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void copyIn(LongDigest longDigest) {
        System.arraycopy(longDigest.xBuf, 0, this.xBuf, 0, longDigest.xBuf.length);
        this.xBufOff = longDigest.xBufOff;
        this.byteCount1 = longDigest.byteCount1;
        this.byteCount2 = longDigest.byteCount2;
        this.f167H1 = longDigest.f167H1;
        this.f168H2 = longDigest.f168H2;
        this.f169H3 = longDigest.f169H3;
        this.f170H4 = longDigest.f170H4;
        this.f171H5 = longDigest.f171H5;
        this.f172H6 = longDigest.f172H6;
        this.f173H7 = longDigest.f173H7;
        this.f174H8 = longDigest.f174H8;
        System.arraycopy(longDigest.f175W, 0, this.f175W, 0, longDigest.f175W.length);
        this.wOff = longDigest.wOff;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void populateState(byte[] bArr) {
        System.arraycopy(this.xBuf, 0, bArr, 0, this.xBufOff);
        Pack.intToBigEndian(this.xBufOff, bArr, 8);
        Pack.longToBigEndian(this.byteCount1, bArr, 12);
        Pack.longToBigEndian(this.byteCount2, bArr, 20);
        Pack.longToBigEndian(this.f167H1, bArr, 28);
        Pack.longToBigEndian(this.f168H2, bArr, 36);
        Pack.longToBigEndian(this.f169H3, bArr, 44);
        Pack.longToBigEndian(this.f170H4, bArr, 52);
        Pack.longToBigEndian(this.f171H5, bArr, 60);
        Pack.longToBigEndian(this.f172H6, bArr, 68);
        Pack.longToBigEndian(this.f173H7, bArr, 76);
        Pack.longToBigEndian(this.f174H8, bArr, 84);
        Pack.intToBigEndian(this.wOff, bArr, 92);
        for (int i = 0; i < this.wOff; i++) {
            Pack.longToBigEndian(this.f175W[i], bArr, 96 + (i * 8));
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void restoreState(byte[] bArr) {
        this.xBufOff = Pack.bigEndianToInt(bArr, 8);
        System.arraycopy(bArr, 0, this.xBuf, 0, this.xBufOff);
        this.byteCount1 = Pack.bigEndianToLong(bArr, 12);
        this.byteCount2 = Pack.bigEndianToLong(bArr, 20);
        this.f167H1 = Pack.bigEndianToLong(bArr, 28);
        this.f168H2 = Pack.bigEndianToLong(bArr, 36);
        this.f169H3 = Pack.bigEndianToLong(bArr, 44);
        this.f170H4 = Pack.bigEndianToLong(bArr, 52);
        this.f171H5 = Pack.bigEndianToLong(bArr, 60);
        this.f172H6 = Pack.bigEndianToLong(bArr, 68);
        this.f173H7 = Pack.bigEndianToLong(bArr, 76);
        this.f174H8 = Pack.bigEndianToLong(bArr, 84);
        this.wOff = Pack.bigEndianToInt(bArr, 92);
        for (int i = 0; i < this.wOff; i++) {
            this.f175W[i] = Pack.bigEndianToLong(bArr, 96 + (i * 8));
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getEncodedStateSize() {
        return 96 + (this.wOff * 8);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        byte[] bArr = this.xBuf;
        int i = this.xBufOff;
        this.xBufOff = i + 1;
        bArr[i] = b;
        if (this.xBufOff == this.xBuf.length) {
            processWord(this.xBuf, 0);
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
        while (i2 > this.xBuf.length) {
            processWord(bArr, i);
            i += this.xBuf.length;
            i2 -= this.xBuf.length;
            this.byteCount1 += this.xBuf.length;
        }
        while (i2 > 0) {
            update(bArr[i]);
            i++;
            i2--;
        }
    }

    public void finish() {
        adjustByteCounts();
        long j = this.byteCount1 << 3;
        long j2 = this.byteCount2;
        update(Byte.MIN_VALUE);
        while (this.xBufOff != 0) {
            update((byte) 0);
        }
        processLength(j, j2);
        processBlock();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.byteCount1 = 0L;
        this.byteCount2 = 0L;
        this.xBufOff = 0;
        for (int i = 0; i < this.xBuf.length; i++) {
            this.xBuf[i] = 0;
        }
        this.wOff = 0;
        for (int i2 = 0; i2 != this.f175W.length; i2++) {
            this.f175W[i2] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 128;
    }

    protected void processWord(byte[] bArr, int i) {
        this.f175W[this.wOff] = Pack.bigEndianToLong(bArr, i);
        int i2 = this.wOff + 1;
        this.wOff = i2;
        if (i2 == 16) {
            processBlock();
        }
    }

    private void adjustByteCounts() {
        if (this.byteCount1 > 2305843009213693951L) {
            this.byteCount2 += this.byteCount1 >>> 61;
            this.byteCount1 &= 2305843009213693951L;
        }
    }

    protected void processLength(long j, long j2) {
        if (this.wOff > 14) {
            processBlock();
        }
        this.f175W[14] = j2;
        this.f175W[15] = j;
    }

    protected void processBlock() {
        adjustByteCounts();
        for (int i = 16; i <= 79; i++) {
            this.f175W[i] = Sigma1(this.f175W[i - 2]) + this.f175W[i - 7] + Sigma0(this.f175W[i - 15]) + this.f175W[i - 16];
        }
        long j = this.f167H1;
        long j2 = this.f168H2;
        long j3 = this.f169H3;
        long j4 = this.f170H4;
        long j5 = this.f171H5;
        long j6 = this.f172H6;
        long j7 = this.f173H7;
        long j8 = this.f174H8;
        int i2 = 0;
        for (int i3 = 0; i3 < 10; i3++) {
            int i4 = i2;
            int i5 = i2 + 1;
            long Sum1 = j8 + Sum1(j5) + m111Ch(j5, j6, j7) + f176K[i2] + this.f175W[i4];
            long j9 = j4 + Sum1;
            long Sum0 = Sum1 + Sum0(j) + Maj(j, j2, j3);
            int i6 = i5 + 1;
            long Sum12 = j7 + Sum1(j9) + m111Ch(j9, j5, j6) + f176K[i5] + this.f175W[i5];
            long j10 = j3 + Sum12;
            long Sum02 = Sum12 + Sum0(Sum0) + Maj(Sum0, j, j2);
            int i7 = i6 + 1;
            long Sum13 = j6 + Sum1(j10) + m111Ch(j10, j9, j5) + f176K[i6] + this.f175W[i6];
            long j11 = j2 + Sum13;
            long Sum03 = Sum13 + Sum0(Sum02) + Maj(Sum02, Sum0, j);
            int i8 = i7 + 1;
            long Sum14 = j5 + Sum1(j11) + m111Ch(j11, j10, j9) + f176K[i7] + this.f175W[i7];
            long j12 = j + Sum14;
            long Sum04 = Sum14 + Sum0(Sum03) + Maj(Sum03, Sum02, Sum0);
            int i9 = i8 + 1;
            long Sum15 = j9 + Sum1(j12) + m111Ch(j12, j11, j10) + f176K[i8] + this.f175W[i8];
            j8 = Sum0 + Sum15;
            j4 = Sum15 + Sum0(Sum04) + Maj(Sum04, Sum03, Sum02);
            int i10 = i9 + 1;
            long Sum16 = j10 + Sum1(j8) + m111Ch(j8, j12, j11) + f176K[i9] + this.f175W[i9];
            j7 = Sum02 + Sum16;
            j3 = Sum16 + Sum0(j4) + Maj(j4, Sum04, Sum03);
            int i11 = i10 + 1;
            long Sum17 = j11 + Sum1(j7) + m111Ch(j7, j8, j12) + f176K[i10] + this.f175W[i10];
            j6 = Sum03 + Sum17;
            j2 = Sum17 + Sum0(j3) + Maj(j3, j4, Sum04);
            i2 = i11 + 1;
            long Sum18 = j12 + Sum1(j6) + m111Ch(j6, j7, j8) + f176K[i11] + this.f175W[i11];
            j5 = Sum04 + Sum18;
            j = Sum18 + Sum0(j2) + Maj(j2, j3, j4);
        }
        this.f167H1 += j;
        this.f168H2 += j2;
        this.f169H3 += j3;
        this.f170H4 += j4;
        this.f171H5 += j5;
        this.f172H6 += j6;
        this.f173H7 += j7;
        this.f174H8 += j8;
        this.wOff = 0;
        for (int i12 = 0; i12 < 16; i12++) {
            this.f175W[i12] = 0;
        }
    }

    /* renamed from: Ch */
    private long m111Ch(long j, long j2, long j3) {
        return (j & j2) ^ ((j ^ (-1)) & j3);
    }

    private long Maj(long j, long j2, long j3) {
        return ((j & j2) ^ (j & j3)) ^ (j2 & j3);
    }

    private long Sum0(long j) {
        return (((j << 36) | (j >>> 28)) ^ ((j << 30) | (j >>> 34))) ^ ((j << 25) | (j >>> 39));
    }

    private long Sum1(long j) {
        return (((j << 50) | (j >>> 14)) ^ ((j << 46) | (j >>> 18))) ^ ((j << 23) | (j >>> 41));
    }

    private long Sigma0(long j) {
        return (((j << 63) | (j >>> 1)) ^ ((j << 56) | (j >>> 8))) ^ (j >>> 7);
    }

    private long Sigma1(long j) {
        return (((j << 45) | (j >>> 19)) ^ ((j << 3) | (j >>> 61))) ^ (j >>> 6);
    }
}