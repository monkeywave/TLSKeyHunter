package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class ISAPDigest implements Digest {
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /* renamed from: t0 */
    private long f426t0;

    /* renamed from: t1 */
    private long f427t1;

    /* renamed from: t2 */
    private long f428t2;

    /* renamed from: t3 */
    private long f429t3;

    /* renamed from: t4 */
    private long f430t4;

    /* renamed from: x0 */
    private long f431x0;

    /* renamed from: x1 */
    private long f432x1;

    /* renamed from: x2 */
    private long f433x2;

    /* renamed from: x3 */
    private long f434x3;

    /* renamed from: x4 */
    private long f435x4;

    private void P12() {
        ROUND(240L);
        ROUND(225L);
        ROUND(210L);
        ROUND(195L);
        ROUND(180L);
        ROUND(165L);
        ROUND(150L);
        ROUND(135L);
        ROUND(120L);
        ROUND(105L);
        ROUND(90L);
        ROUND(75L);
    }

    private long ROTR(long j, long j2) {
        return (j << ((int) (64 - j2))) | (j >>> ((int) j2));
    }

    private void ROUND(long j) {
        long j2 = this.f431x0;
        long j3 = this.f432x1;
        long j4 = this.f433x2;
        long j5 = this.f434x3;
        long j6 = this.f435x4;
        long j7 = ((((j2 ^ j3) ^ j4) ^ j5) ^ j) ^ ((((j2 ^ j4) ^ j6) ^ j) & j3);
        this.f426t0 = j7;
        this.f427t1 = ((((j2 ^ j4) ^ j5) ^ j6) ^ j) ^ (((j3 ^ j4) ^ j) & (j3 ^ j5));
        this.f428t2 = (((j3 ^ j4) ^ j6) ^ j) ^ (j5 & j6);
        this.f429t3 = ((j4 ^ (j2 ^ j3)) ^ j) ^ ((~j2) & (j5 ^ j6));
        this.f430t4 = ((j2 ^ j6) & j3) ^ ((j3 ^ j5) ^ j6);
        this.f431x0 = (ROTR(j7, 19L) ^ j7) ^ ROTR(this.f426t0, 28L);
        long j8 = this.f427t1;
        this.f432x1 = (j8 ^ ROTR(j8, 39L)) ^ ROTR(this.f427t1, 61L);
        long j9 = this.f428t2;
        this.f433x2 = ~((j9 ^ ROTR(j9, 1L)) ^ ROTR(this.f428t2, 6L));
        long j10 = this.f429t3;
        this.f434x3 = (j10 ^ ROTR(j10, 10L)) ^ ROTR(this.f429t3, 17L);
        long j11 = this.f430t4;
        this.f435x4 = (j11 ^ ROTR(j11, 7L)) ^ ROTR(this.f430t4, 41L);
    }

    protected long U64BIG(long j) {
        return (ROTR(j, 56L) & 1095216660735L) | (ROTR(j, 8L) & (-72057589759737856L)) | (ROTR(j, 24L) & 71776119077928960L) | (ROTR(j, 40L) & 280375465148160L);
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        if (i + 32 > bArr.length) {
            throw new OutputLengthException("output buffer is too short");
        }
        this.f430t4 = 0L;
        this.f429t3 = 0L;
        this.f428t2 = 0L;
        this.f427t1 = 0L;
        this.f426t0 = 0L;
        this.f431x0 = -1255492011513352131L;
        this.f432x1 = -8380609354527731710L;
        this.f433x2 = -5437372128236807582L;
        this.f434x3 = 4834782570098516968L;
        this.f435x4 = 3787428097924915520L;
        byte[] byteArray = this.buffer.toByteArray();
        int length = byteArray.length;
        int i2 = length >> 3;
        long[] jArr = new long[i2];
        int i3 = 0;
        Pack.littleEndianToLong(byteArray, 0, jArr, 0, i2);
        int i4 = 0;
        while (length >= 8) {
            this.f431x0 ^= U64BIG(jArr[i4]);
            P12();
            length -= 8;
            i4++;
        }
        long j = this.f431x0;
        int i5 = (7 - length) << 3;
        long j2 = 128;
        while (true) {
            this.f431x0 = j ^ (j2 << i5);
            if (length <= 0) {
                break;
            }
            j = this.f431x0;
            length--;
            j2 = byteArray[(i4 << 3) + length] & 255;
            i5 = (7 - length) << 3;
        }
        P12();
        long[] jArr2 = new long[4];
        while (true) {
            long U64BIG = U64BIG(this.f431x0);
            if (i3 >= 3) {
                jArr2[i3] = U64BIG;
                Pack.longToLittleEndian(jArr2, bArr, i);
                this.buffer.reset();
                return 32;
            }
            jArr2[i3] = U64BIG;
            P12();
            i3++;
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "ISAP Hash";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.buffer.reset();
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.buffer.write(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        this.buffer.write(bArr, i, i2);
    }
}