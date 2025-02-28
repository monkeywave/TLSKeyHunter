package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/SipHash.class */
public class SipHash implements Mac {

    /* renamed from: c */
    protected final int f435c;

    /* renamed from: d */
    protected final int f436d;

    /* renamed from: k0 */
    protected long f437k0;

    /* renamed from: k1 */
    protected long f438k1;

    /* renamed from: v0 */
    protected long f439v0;

    /* renamed from: v1 */
    protected long f440v1;

    /* renamed from: v2 */
    protected long f441v2;

    /* renamed from: v3 */
    protected long f442v3;

    /* renamed from: m */
    protected long f443m;
    protected int wordPos;
    protected int wordCount;

    public SipHash() {
        this.f443m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
        this.f435c = 2;
        this.f436d = 4;
    }

    public SipHash(int i, int i2) {
        this.f443m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
        this.f435c = i;
        this.f436d = i2;
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "SipHash-" + this.f435c + "-" + this.f436d;
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
        this.f437k0 = Pack.littleEndianToLong(key, 0);
        this.f438k1 = Pack.littleEndianToLong(key, 8);
        reset();
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        this.f443m >>>= 8;
        this.f443m |= (b & 255) << 56;
        int i = this.wordPos + 1;
        this.wordPos = i;
        if (i == 8) {
            processMessageWord();
            this.wordPos = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        int i3 = 0;
        int i4 = i2 & (-8);
        if (this.wordPos == 0) {
            while (i3 < i4) {
                this.f443m = Pack.littleEndianToLong(bArr, i + i3);
                processMessageWord();
                i3 += 8;
            }
            while (i3 < i2) {
                this.f443m >>>= 8;
                this.f443m |= (bArr[i + i3] & 255) << 56;
                i3++;
            }
            this.wordPos = i2 - i4;
            return;
        }
        int i5 = this.wordPos << 3;
        while (i3 < i4) {
            long littleEndianToLong = Pack.littleEndianToLong(bArr, i + i3);
            this.f443m = (littleEndianToLong << i5) | (this.f443m >>> (-i5));
            processMessageWord();
            this.f443m = littleEndianToLong;
            i3 += 8;
        }
        while (i3 < i2) {
            this.f443m >>>= 8;
            this.f443m |= (bArr[i + i3] & 255) << 56;
            int i6 = this.wordPos + 1;
            this.wordPos = i6;
            if (i6 == 8) {
                processMessageWord();
                this.wordPos = 0;
            }
            i3++;
        }
    }

    public long doFinal() throws DataLengthException, IllegalStateException {
        this.f443m >>>= (7 - this.wordPos) << 3;
        this.f443m >>>= 8;
        this.f443m |= (((this.wordCount << 3) + this.wordPos) & 255) << 56;
        processMessageWord();
        this.f441v2 ^= 255;
        applySipRounds(this.f436d);
        long j = ((this.f439v0 ^ this.f440v1) ^ this.f441v2) ^ this.f442v3;
        reset();
        return j;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        Pack.longToLittleEndian(doFinal(), bArr, i);
        return 8;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        this.f439v0 = this.f437k0 ^ 8317987319222330741L;
        this.f440v1 = this.f438k1 ^ 7237128888997146477L;
        this.f441v2 = this.f437k0 ^ 7816392313619706465L;
        this.f442v3 = this.f438k1 ^ 8387220255154660723L;
        this.f443m = 0L;
        this.wordPos = 0;
        this.wordCount = 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void processMessageWord() {
        this.wordCount++;
        this.f442v3 ^= this.f443m;
        applySipRounds(this.f435c);
        this.f439v0 ^= this.f443m;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void applySipRounds(int i) {
        long j = this.f439v0;
        long j2 = this.f440v1;
        long j3 = this.f441v2;
        long j4 = this.f442v3;
        for (int i2 = 0; i2 < i; i2++) {
            long j5 = j + j2;
            long j6 = j3 + j4;
            long rotateLeft = rotateLeft(j2, 13) ^ j5;
            long rotateLeft2 = rotateLeft(j4, 16) ^ j6;
            long rotateLeft3 = rotateLeft(j5, 32);
            long j7 = j6 + rotateLeft;
            j = rotateLeft3 + rotateLeft2;
            j2 = rotateLeft(rotateLeft, 17) ^ j7;
            j4 = rotateLeft(rotateLeft2, 21) ^ j;
            j3 = rotateLeft(j7, 32);
        }
        this.f439v0 = j;
        this.f440v1 = j2;
        this.f441v2 = j3;
        this.f442v3 = j4;
    }

    protected static long rotateLeft(long j, int i) {
        return (j << i) | (j >>> (-i));
    }
}