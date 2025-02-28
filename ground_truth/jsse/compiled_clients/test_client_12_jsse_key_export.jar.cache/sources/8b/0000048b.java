package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/SerpentEngineBase.class */
public abstract class SerpentEngineBase implements BlockCipher {
    protected static final int BLOCK_SIZE = 16;
    static final int ROUNDS = 32;
    static final int PHI = -1640531527;
    protected boolean encrypting;
    protected int[] wKey;

    /* renamed from: X0 */
    protected int f372X0;

    /* renamed from: X1 */
    protected int f373X1;

    /* renamed from: X2 */
    protected int f374X2;

    /* renamed from: X3 */
    protected int f375X3;

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to " + getAlgorithmName() + " init - " + cipherParameters.getClass().getName());
        }
        this.encrypting = z;
        this.wKey = makeWorkingKey(((KeyParameter) cipherParameters).getKey());
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Serpent";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public final int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.wKey == null) {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }
        if (i + 16 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + 16 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.encrypting) {
            encryptBlock(bArr, i, bArr2, i2);
            return 16;
        }
        decryptBlock(bArr, i, bArr2, i2);
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    protected static int rotateRight(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb0(int i, int i2, int i3, int i4) {
        int i5 = i ^ i4;
        int i6 = i3 ^ i5;
        int i7 = i2 ^ i6;
        this.f375X3 = (i & i4) ^ i7;
        int i8 = i ^ (i2 & i5);
        this.f374X2 = i7 ^ (i3 | i8);
        int i9 = this.f375X3 & (i6 ^ i8);
        this.f373X1 = (i6 ^ (-1)) ^ i9;
        this.f372X0 = i9 ^ (i8 ^ (-1));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib0(int i, int i2, int i3, int i4) {
        int i5 = i ^ (-1);
        int i6 = i ^ i2;
        int i7 = i4 ^ (i5 | i6);
        int i8 = i3 ^ i7;
        this.f374X2 = i6 ^ i8;
        int i9 = i5 ^ (i4 & i6);
        this.f373X1 = i7 ^ (this.f374X2 & i9);
        this.f375X3 = (i & i7) ^ (i8 | this.f373X1);
        this.f372X0 = this.f375X3 ^ (i8 ^ i9);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb1(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ (i ^ (-1));
        int i6 = i3 ^ (i | i5);
        this.f374X2 = i4 ^ i6;
        int i7 = i2 ^ (i4 | i5);
        int i8 = i5 ^ this.f374X2;
        this.f375X3 = i8 ^ (i6 & i7);
        int i9 = i6 ^ i7;
        this.f373X1 = this.f375X3 ^ i9;
        this.f372X0 = i6 ^ (i8 & i9);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib1(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ i4;
        int i6 = i ^ (i2 & i5);
        int i7 = i5 ^ i6;
        this.f375X3 = i3 ^ i7;
        int i8 = i2 ^ (i5 & i6);
        this.f373X1 = i6 ^ (this.f375X3 | i8);
        int i9 = this.f373X1 ^ (-1);
        int i10 = this.f375X3 ^ i8;
        this.f372X0 = i9 ^ i10;
        this.f374X2 = i7 ^ (i9 | i10);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb2(int i, int i2, int i3, int i4) {
        int i5 = i ^ (-1);
        int i6 = i2 ^ i4;
        this.f372X0 = i6 ^ (i3 & i5);
        int i7 = i3 ^ i5;
        int i8 = i2 & (i3 ^ this.f372X0);
        this.f375X3 = i7 ^ i8;
        this.f374X2 = i ^ ((i4 | i8) & (this.f372X0 | i7));
        this.f373X1 = (i6 ^ this.f375X3) ^ (this.f374X2 ^ (i4 | i5));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib2(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ i4;
        int i6 = i5 ^ (-1);
        int i7 = i ^ i3;
        int i8 = i3 ^ i5;
        this.f372X0 = i7 ^ (i2 & i8);
        this.f375X3 = i5 ^ (i7 | (i4 ^ (i | i6)));
        int i9 = i8 ^ (-1);
        int i10 = this.f372X0 | this.f375X3;
        this.f373X1 = i9 ^ i10;
        this.f374X2 = (i4 & i9) ^ (i7 ^ i10);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb3(int i, int i2, int i3, int i4) {
        int i5 = i ^ i2;
        int i6 = i | i4;
        int i7 = i3 ^ i4;
        int i8 = (i & i3) | (i5 & i6);
        this.f374X2 = i7 ^ i8;
        int i9 = i8 ^ (i2 ^ i6);
        this.f372X0 = i5 ^ (i7 & i9);
        int i10 = this.f374X2 & this.f372X0;
        this.f373X1 = i9 ^ i10;
        this.f375X3 = (i2 | i4) ^ (i7 ^ i10);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib3(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ i3;
        int i6 = i ^ (i2 & i5);
        int i7 = i3 ^ i6;
        int i8 = i4 | i6;
        this.f372X0 = i5 ^ i8;
        int i9 = i4 ^ (i5 | i8);
        this.f374X2 = i7 ^ i9;
        int i10 = (i | i2) ^ i9;
        this.f375X3 = i6 ^ (this.f372X0 & i10);
        this.f373X1 = this.f375X3 ^ (this.f372X0 ^ i10);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb4(int i, int i2, int i3, int i4) {
        int i5 = i ^ i4;
        int i6 = i3 ^ (i4 & i5);
        int i7 = i2 | i6;
        this.f375X3 = i5 ^ i7;
        int i8 = i2 ^ (-1);
        this.f372X0 = i6 ^ (i5 | i8);
        int i9 = i5 ^ i8;
        this.f374X2 = (i & this.f372X0) ^ (i7 & i9);
        this.f373X1 = (i ^ i6) ^ (i9 & this.f374X2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib4(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ (i & (i3 | i4));
        int i6 = i3 ^ (i & i5);
        this.f373X1 = i4 ^ i6;
        int i7 = i ^ (-1);
        this.f375X3 = i5 ^ (i6 & this.f373X1);
        int i8 = i4 ^ (this.f373X1 | i7);
        this.f372X0 = this.f375X3 ^ i8;
        this.f374X2 = (i5 & i8) ^ (this.f373X1 ^ i7);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb5(int i, int i2, int i3, int i4) {
        int i5 = i ^ (-1);
        int i6 = i ^ i2;
        int i7 = i ^ i4;
        this.f372X0 = (i3 ^ i5) ^ (i6 | i7);
        int i8 = i4 & this.f372X0;
        this.f373X1 = i8 ^ (i6 ^ this.f372X0);
        int i9 = i5 | this.f372X0;
        int i10 = i6 | i8;
        int i11 = i7 ^ i9;
        this.f374X2 = i10 ^ i11;
        this.f375X3 = (i2 ^ i8) ^ (this.f373X1 & i11);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib5(int i, int i2, int i3, int i4) {
        int i5 = i3 ^ (-1);
        int i6 = i4 ^ (i2 & i5);
        int i7 = i & i6;
        this.f375X3 = i7 ^ (i2 ^ i5);
        int i8 = i2 | this.f375X3;
        this.f373X1 = i6 ^ (i & i8);
        int i9 = i | i4;
        this.f372X0 = i9 ^ (i5 ^ i8);
        this.f374X2 = (i2 & i9) ^ (i7 | (i ^ i3));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb6(int i, int i2, int i3, int i4) {
        int i5 = i ^ i4;
        int i6 = i2 ^ i5;
        int i7 = i3 ^ ((i ^ (-1)) | i5);
        this.f373X1 = i2 ^ i7;
        int i8 = i4 ^ (i5 | this.f373X1);
        this.f374X2 = i6 ^ (i7 & i8);
        int i9 = i7 ^ i8;
        this.f372X0 = this.f374X2 ^ i9;
        this.f375X3 = (i7 ^ (-1)) ^ (i6 & i9);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib6(int i, int i2, int i3, int i4) {
        int i5 = i ^ (-1);
        int i6 = i ^ i2;
        int i7 = i3 ^ i6;
        int i8 = i4 ^ (i3 | i5);
        this.f373X1 = i7 ^ i8;
        int i9 = i6 ^ (i7 & i8);
        this.f375X3 = i8 ^ (i2 | i9);
        int i10 = i2 | this.f375X3;
        this.f372X0 = i9 ^ i10;
        this.f374X2 = (i4 & i5) ^ (i7 ^ i10);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void sb7(int i, int i2, int i3, int i4) {
        int i5 = i2 ^ i3;
        int i6 = i4 ^ (i3 & i5);
        int i7 = i ^ i6;
        this.f373X1 = i2 ^ (i7 & (i4 | i5));
        int i8 = i6 | this.f373X1;
        this.f375X3 = i5 ^ (i & i7);
        int i9 = i7 ^ i8;
        this.f374X2 = i6 ^ (this.f375X3 & i9);
        this.f372X0 = (i9 ^ (-1)) ^ (this.f375X3 & this.f374X2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void ib7(int i, int i2, int i3, int i4) {
        int i5 = i3 | (i & i2);
        int i6 = i4 & (i | i2);
        this.f375X3 = i5 ^ i6;
        int i7 = i2 ^ i6;
        this.f373X1 = i ^ (i7 | (this.f375X3 ^ (i4 ^ (-1))));
        this.f372X0 = (i3 ^ i7) ^ (i4 | this.f373X1);
        this.f374X2 = (i5 ^ this.f373X1) ^ (this.f372X0 ^ (i & this.f375X3));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* renamed from: LT */
    public final void m38LT() {
        int rotateLeft = rotateLeft(this.f372X0, 13);
        int rotateLeft2 = rotateLeft(this.f374X2, 3);
        int i = (this.f373X1 ^ rotateLeft) ^ rotateLeft2;
        int i2 = (this.f375X3 ^ rotateLeft2) ^ (rotateLeft << 3);
        this.f373X1 = rotateLeft(i, 1);
        this.f375X3 = rotateLeft(i2, 7);
        this.f372X0 = rotateLeft((rotateLeft ^ this.f373X1) ^ this.f375X3, 5);
        this.f374X2 = rotateLeft((rotateLeft2 ^ this.f375X3) ^ (this.f373X1 << 7), 22);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void inverseLT() {
        int rotateRight = (rotateRight(this.f374X2, 22) ^ this.f375X3) ^ (this.f373X1 << 7);
        int rotateRight2 = (rotateRight(this.f372X0, 5) ^ this.f373X1) ^ this.f375X3;
        int rotateRight3 = rotateRight(this.f375X3, 7);
        int rotateRight4 = rotateRight(this.f373X1, 1);
        this.f375X3 = (rotateRight3 ^ rotateRight) ^ (rotateRight2 << 3);
        this.f373X1 = (rotateRight4 ^ rotateRight2) ^ rotateRight;
        this.f374X2 = rotateRight(rotateRight, 3);
        this.f372X0 = rotateRight(rotateRight2, 13);
    }

    protected abstract int[] makeWorkingKey(byte[] bArr);

    protected abstract void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2);

    protected abstract void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2);
}