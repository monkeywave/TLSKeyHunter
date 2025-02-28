package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;

/* loaded from: classes2.dex */
public class AsconDigest implements ExtendedDigest {
    private final int ASCON_PB_ROUNDS;
    private final String algorithmName;
    AsconParameters asconParameters;

    /* renamed from: x0 */
    private long f375x0;

    /* renamed from: x1 */
    private long f376x1;

    /* renamed from: x2 */
    private long f377x2;

    /* renamed from: x3 */
    private long f378x3;

    /* renamed from: x4 */
    private long f379x4;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int CRYPTO_BYTES = 32;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: org.bouncycastle.crypto.digests.AsconDigest$1 */
    /* loaded from: classes2.dex */
    public static /* synthetic */ class C11511 {

        /* renamed from: $SwitchMap$org$bouncycastle$crypto$digests$AsconDigest$AsconParameters */
        static final /* synthetic */ int[] f380x8d084c42;

        static {
            int[] iArr = new int[AsconParameters.values().length];
            f380x8d084c42 = iArr;
            try {
                iArr[AsconParameters.AsconHash.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f380x8d084c42[AsconParameters.AsconHashA.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public enum AsconParameters {
        AsconHash,
        AsconHashA
    }

    public AsconDigest(AsconParameters asconParameters) {
        String str;
        this.asconParameters = asconParameters;
        int i = C11511.f380x8d084c42[asconParameters.ordinal()];
        if (i == 1) {
            this.ASCON_PB_ROUNDS = 12;
            str = "Ascon-Hash";
        } else if (i != 2) {
            throw new IllegalArgumentException("Invalid parameter settings for Ascon Hash");
        } else {
            this.ASCON_PB_ROUNDS = 8;
            str = "Ascon-HashA";
        }
        this.algorithmName = str;
        reset();
    }

    private long LOADBYTES(byte[] bArr, int i, int i2) {
        long j = 0;
        for (int i3 = 0; i3 < i2; i3++) {
            j |= (bArr[i3 + i] & 255) << ((7 - i3) << 3);
        }
        return j;
    }

    /* renamed from: P */
    private void m143P(int i) {
        if (i == 12) {
            ROUND(240L);
            ROUND(225L);
            ROUND(210L);
            ROUND(195L);
        }
        if (i >= 8) {
            ROUND(180L);
            ROUND(165L);
        }
        ROUND(150L);
        ROUND(135L);
        ROUND(120L);
        ROUND(105L);
        ROUND(90L);
        ROUND(75L);
    }

    private long PAD(int i) {
        return 128 << (56 - (i << 3));
    }

    private long ROR(long j, int i) {
        return (j << (64 - i)) | (j >>> i);
    }

    private void ROUND(long j) {
        long j2 = this.f375x0;
        long j3 = this.f376x1;
        long j4 = this.f377x2;
        long j5 = this.f378x3;
        long j6 = this.f379x4;
        long j7 = ((((j2 ^ j3) ^ j4) ^ j5) ^ j) ^ ((((j2 ^ j4) ^ j6) ^ j) & j3);
        long j8 = ((((j2 ^ j4) ^ j5) ^ j6) ^ j) ^ (((j3 ^ j4) ^ j) & (j3 ^ j5));
        long j9 = (((j3 ^ j4) ^ j6) ^ j) ^ (j5 & j6);
        long j10 = ((j4 ^ (j2 ^ j3)) ^ j) ^ ((~j2) & (j5 ^ j6));
        long j11 = ((j2 ^ j6) & j3) ^ ((j5 ^ j3) ^ j6);
        this.f375x0 = (ROR(j7, 19) ^ j7) ^ ROR(j7, 28);
        this.f376x1 = ROR(j8, 61) ^ (ROR(j8, 39) ^ j8);
        this.f377x2 = ~(ROR(j9, 6) ^ (ROR(j9, 1) ^ j9));
        this.f378x3 = (ROR(j10, 10) ^ j10) ^ ROR(j10, 17);
        this.f379x4 = ROR(j11, 41) ^ (ROR(j11, 7) ^ j11);
    }

    private void STOREBYTES(byte[] bArr, int i, long j, int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            bArr[i3 + i] = (byte) (j >>> ((7 - i3) << 3));
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        long j;
        if (i + 32 > bArr.length) {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] byteArray = this.buffer.toByteArray();
        int size = this.buffer.size();
        int i2 = 0;
        while (true) {
            j = this.f375x0;
            if (size < 8) {
                break;
            }
            this.f375x0 = j ^ LOADBYTES(byteArray, i2, 8);
            m143P(this.ASCON_PB_ROUNDS);
            i2 += 8;
            size -= 8;
        }
        long LOADBYTES = j ^ LOADBYTES(byteArray, i2, size);
        this.f375x0 = LOADBYTES;
        this.f375x0 = PAD(size) ^ LOADBYTES;
        m143P(12);
        int i3 = 32;
        while (true) {
            long j2 = this.f375x0;
            if (i3 <= 8) {
                STOREBYTES(bArr, i, j2, i3);
                reset();
                return 32;
            }
            STOREBYTES(bArr, i, j2, 8);
            m143P(this.ASCON_PB_ROUNDS);
            i += 8;
            i3 -= 8;
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        long j;
        this.buffer.reset();
        int i = C11511.f380x8d084c42[this.asconParameters.ordinal()];
        if (i == 1) {
            this.f375x0 = -1255492011513352131L;
            this.f376x1 = -8380609354527731710L;
            this.f377x2 = -5437372128236807582L;
            this.f378x3 = 4834782570098516968L;
            j = 3787428097924915520L;
        } else if (i != 2) {
            return;
        } else {
            this.f375x0 = 92044056785660070L;
            this.f376x1 = 8326807761760157607L;
            this.f377x2 = 3371194088139667532L;
            this.f378x3 = -2956994353054992515L;
            j = -6828509670848688761L;
        }
        this.f379x4 = j;
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