package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SipHash implements Mac {

    /* renamed from: c */
    protected final int f753c;

    /* renamed from: d */
    protected final int f754d;

    /* renamed from: k0 */
    protected long f755k0;

    /* renamed from: k1 */
    protected long f756k1;

    /* renamed from: m */
    protected long f757m;

    /* renamed from: v0 */
    protected long f758v0;

    /* renamed from: v1 */
    protected long f759v1;

    /* renamed from: v2 */
    protected long f760v2;

    /* renamed from: v3 */
    protected long f761v3;
    protected int wordCount;
    protected int wordPos;

    public SipHash() {
        this.f757m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
        this.f753c = 2;
        this.f754d = 4;
    }

    public SipHash(int i, int i2) {
        this.f757m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
        this.f753c = i;
        this.f754d = i2;
    }

    protected static long rotateLeft(long j, int i) {
        return (j >>> (-i)) | (j << i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void applySipRounds(int i) {
        long j = this.f758v0;
        long j2 = this.f759v1;
        long j3 = this.f760v2;
        long j4 = this.f761v3;
        for (int i2 = 0; i2 < i; i2++) {
            long j5 = j + j2;
            long j6 = j3 + j4;
            long rotateLeft = rotateLeft(j2, 13) ^ j5;
            long rotateLeft2 = rotateLeft(j4, 16) ^ j6;
            long j7 = j6 + rotateLeft;
            j = rotateLeft(j5, 32) + rotateLeft2;
            j2 = rotateLeft(rotateLeft, 17) ^ j7;
            j4 = rotateLeft(rotateLeft2, 21) ^ j;
            j3 = rotateLeft(j7, 32);
        }
        this.f758v0 = j;
        this.f759v1 = j2;
        this.f760v2 = j3;
        this.f761v3 = j4;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        Pack.longToLittleEndian(doFinal(), bArr, i);
        return 8;
    }

    public long doFinal() throws DataLengthException, IllegalStateException {
        int i;
        this.f757m = ((this.f757m >>> ((7 - this.wordPos) << 3)) >>> 8) | ((((this.wordCount << 3) + i) & 255) << 56);
        processMessageWord();
        this.f760v2 ^= 255;
        applySipRounds(this.f754d);
        long j = ((this.f758v0 ^ this.f759v1) ^ this.f760v2) ^ this.f761v3;
        reset();
        return j;
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "SipHash-" + this.f753c + "-" + this.f754d;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("'params' must be an instance of KeyParameter");
        }
        byte[] key = ((KeyParameter) cipherParameters).getKey();
        if (key.length != 16) {
            throw new IllegalArgumentException("'params' must be a 128-bit key");
        }
        this.f755k0 = Pack.littleEndianToLong(key, 0);
        this.f756k1 = Pack.littleEndianToLong(key, 8);
        reset();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void processMessageWord() {
        this.wordCount++;
        this.f761v3 ^= this.f757m;
        applySipRounds(this.f753c);
        this.f758v0 ^= this.f757m;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        long j = this.f755k0;
        this.f758v0 = 8317987319222330741L ^ j;
        long j2 = this.f756k1;
        this.f759v1 = 7237128888997146477L ^ j2;
        this.f760v2 = j ^ 7816392313619706465L;
        this.f761v3 = 8387220255154660723L ^ j2;
        this.f757m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        this.f757m = (this.f757m >>> 8) | ((b & 255) << 56);
        int i = this.wordPos + 1;
        this.wordPos = i;
        if (i == 8) {
            processMessageWord();
            this.wordPos = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        int i3 = i2 & (-8);
        int i4 = this.wordPos;
        int i5 = 0;
        if (i4 == 0) {
            while (i5 < i3) {
                this.f757m = Pack.littleEndianToLong(bArr, i + i5);
                processMessageWord();
                i5 += 8;
            }
            while (i5 < i2) {
                long j = this.f757m >>> 8;
                this.f757m = j;
                this.f757m = j | ((bArr[i + i5] & 255) << 56);
                i5++;
            }
            this.wordPos = i2 - i3;
            return;
        }
        int i6 = i4 << 3;
        int i7 = 0;
        while (i7 < i3) {
            long littleEndianToLong = Pack.littleEndianToLong(bArr, i + i7);
            this.f757m = (this.f757m >>> (-i6)) | (littleEndianToLong << i6);
            processMessageWord();
            this.f757m = littleEndianToLong;
            i7 += 8;
        }
        while (i7 < i2) {
            long j2 = this.f757m >>> 8;
            this.f757m = j2;
            this.f757m = j2 | ((bArr[i + i7] & 255) << 56);
            int i8 = this.wordPos + 1;
            this.wordPos = i8;
            if (i8 == 8) {
                processMessageWord();
                this.wordPos = 0;
            }
            i7++;
        }
    }
}