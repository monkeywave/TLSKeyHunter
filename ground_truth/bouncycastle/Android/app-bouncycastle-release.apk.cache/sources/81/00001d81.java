package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class XoodyakEngine implements AEADCipher {

    /* renamed from: K */
    private byte[] f704K;
    private int Rabsorb;
    private boolean aadFinished;
    private boolean encrypted;
    private boolean forEncryption;

    /* renamed from: iv */
    private byte[] f706iv;
    private MODE mode;
    private int phase;
    private byte[] state;
    private byte[] tag;
    private final int f_bPrime = 48;
    private final int Rkout = 24;
    private final int PhaseDown = 1;
    private final int PhaseUp = 2;
    private final int MAXROUNDS = 12;
    private final int TAGLEN = 16;
    final int Rkin = 44;

    /* renamed from: RC */
    private final int[] f705RC = {88, 56, 960, 208, 288, 20, 96, 44, 896, 240, 416, 18};
    private boolean initialised = false;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public enum MODE {
        ModeHash,
        ModeKeyed
    }

    private void AbsorbAny(byte[] bArr, int i, int i2, int i3, int i4) {
        while (true) {
            if (this.phase != 2) {
                m48Up(null, 0, 0);
            }
            int min = Math.min(i2, i3);
            Down(bArr, i, min, i4);
            i += min;
            i2 -= min;
            if (i2 == 0) {
                return;
            }
            i4 = 0;
        }
    }

    /* renamed from: Up */
    private void m48Up(byte[] bArr, int i, int i2) {
        XoodyakEngine xoodyakEngine = this;
        if (xoodyakEngine.mode != MODE.ModeHash) {
            byte[] bArr2 = xoodyakEngine.state;
            bArr2[47] = (byte) (bArr2[47] ^ i2);
        }
        int littleEndianToInt = Pack.littleEndianToInt(xoodyakEngine.state, 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(xoodyakEngine.state, 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(xoodyakEngine.state, 8);
        int i3 = 12;
        int littleEndianToInt4 = Pack.littleEndianToInt(xoodyakEngine.state, 12);
        int littleEndianToInt5 = Pack.littleEndianToInt(xoodyakEngine.state, 16);
        int littleEndianToInt6 = Pack.littleEndianToInt(xoodyakEngine.state, 20);
        int littleEndianToInt7 = Pack.littleEndianToInt(xoodyakEngine.state, 24);
        int littleEndianToInt8 = Pack.littleEndianToInt(xoodyakEngine.state, 28);
        int littleEndianToInt9 = Pack.littleEndianToInt(xoodyakEngine.state, 32);
        int littleEndianToInt10 = Pack.littleEndianToInt(xoodyakEngine.state, 36);
        int littleEndianToInt11 = Pack.littleEndianToInt(xoodyakEngine.state, 40);
        int littleEndianToInt12 = Pack.littleEndianToInt(xoodyakEngine.state, 44);
        int i4 = 0;
        while (i4 < i3) {
            int i5 = (littleEndianToInt ^ littleEndianToInt5) ^ littleEndianToInt9;
            int i6 = (littleEndianToInt2 ^ littleEndianToInt6) ^ littleEndianToInt10;
            int i7 = i4;
            int i8 = (littleEndianToInt3 ^ littleEndianToInt7) ^ littleEndianToInt11;
            int i9 = (littleEndianToInt4 ^ littleEndianToInt8) ^ littleEndianToInt12;
            int i10 = littleEndianToInt12;
            int rotateLeft = Integers.rotateLeft(i9, 5) ^ Integers.rotateLeft(i9, 14);
            int i11 = littleEndianToInt8;
            int rotateLeft2 = Integers.rotateLeft(i5, 5) ^ Integers.rotateLeft(i5, 14);
            int rotateLeft3 = Integers.rotateLeft(i6, 5) ^ Integers.rotateLeft(i6, 14);
            int rotateLeft4 = Integers.rotateLeft(i8, 14) ^ Integers.rotateLeft(i8, 5);
            int i12 = littleEndianToInt ^ rotateLeft;
            int i13 = littleEndianToInt5 ^ rotateLeft;
            int i14 = littleEndianToInt2 ^ rotateLeft2;
            int i15 = littleEndianToInt6 ^ rotateLeft2;
            int i16 = rotateLeft2 ^ littleEndianToInt10;
            int i17 = littleEndianToInt3 ^ rotateLeft3;
            int i18 = littleEndianToInt7 ^ rotateLeft3;
            int i19 = rotateLeft3 ^ littleEndianToInt11;
            int i20 = littleEndianToInt4 ^ rotateLeft4;
            int i21 = i11 ^ rotateLeft4;
            int rotateLeft5 = Integers.rotateLeft(rotateLeft ^ littleEndianToInt9, 11);
            int rotateLeft6 = Integers.rotateLeft(i16, 11);
            int rotateLeft7 = Integers.rotateLeft(i19, 11);
            int rotateLeft8 = Integers.rotateLeft(i10 ^ rotateLeft4, 11);
            int i22 = i12 ^ this.f705RC[i7];
            int i23 = ((~i21) & rotateLeft5) ^ i22;
            int i24 = ((~i13) & rotateLeft6) ^ i14;
            int i25 = ((~i15) & rotateLeft7) ^ i17;
            int i26 = ((~i18) & rotateLeft8) ^ i20;
            int i27 = ((~rotateLeft7) & i17) ^ i15;
            int i28 = rotateLeft5 ^ ((~i22) & i21);
            int i29 = rotateLeft7 ^ ((~i17) & i15);
            littleEndianToInt5 = Integers.rotateLeft(((~rotateLeft5) & i22) ^ i21, 1);
            littleEndianToInt6 = Integers.rotateLeft(((~rotateLeft6) & i14) ^ i13, 1);
            littleEndianToInt7 = Integers.rotateLeft(i27, 1);
            littleEndianToInt8 = Integers.rotateLeft(((~rotateLeft8) & i20) ^ i18, 1);
            littleEndianToInt9 = Integers.rotateLeft(i29, 8);
            littleEndianToInt10 = Integers.rotateLeft(rotateLeft8 ^ ((~i20) & i18), 8);
            littleEndianToInt11 = Integers.rotateLeft(i28, 8);
            littleEndianToInt12 = Integers.rotateLeft(((~i14) & i13) ^ rotateLeft6, 8);
            i4 = i7 + 1;
            littleEndianToInt = i23;
            littleEndianToInt4 = i26;
            littleEndianToInt2 = i24;
            littleEndianToInt3 = i25;
            i3 = 12;
            xoodyakEngine = this;
        }
        Pack.intToLittleEndian(littleEndianToInt, xoodyakEngine.state, 0);
        Pack.intToLittleEndian(littleEndianToInt2, xoodyakEngine.state, 4);
        Pack.intToLittleEndian(littleEndianToInt3, xoodyakEngine.state, 8);
        Pack.intToLittleEndian(littleEndianToInt4, xoodyakEngine.state, 12);
        Pack.intToLittleEndian(littleEndianToInt5, xoodyakEngine.state, 16);
        Pack.intToLittleEndian(littleEndianToInt6, xoodyakEngine.state, 20);
        Pack.intToLittleEndian(littleEndianToInt7, xoodyakEngine.state, 24);
        Pack.intToLittleEndian(littleEndianToInt8, xoodyakEngine.state, 28);
        Pack.intToLittleEndian(littleEndianToInt9, xoodyakEngine.state, 32);
        Pack.intToLittleEndian(littleEndianToInt10, xoodyakEngine.state, 36);
        Pack.intToLittleEndian(littleEndianToInt11, xoodyakEngine.state, 40);
        Pack.intToLittleEndian(littleEndianToInt12, xoodyakEngine.state, 44);
        xoodyakEngine.phase = 2;
        if (bArr != null) {
            System.arraycopy(xoodyakEngine.state, 0, bArr, 0, i);
        }
    }

    private int encrypt(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        byte[] bArr3 = new byte[24];
        int i4 = this.encrypted ? 0 : 128;
        int i5 = i2;
        while (true) {
            if (i5 == 0 && this.encrypted) {
                return i2;
            }
            int min = Math.min(i5, 24);
            if (this.forEncryption) {
                System.arraycopy(bArr, i, bArr3, 0, min);
            }
            m48Up(null, 0, i4);
            int i6 = 0;
            while (i6 < min) {
                bArr2[i3 + i6] = (byte) (bArr[i] ^ this.state[i6]);
                i6++;
                i++;
            }
            if (this.forEncryption) {
                Down(bArr3, 0, min, 0);
            } else {
                Down(bArr2, i3, min, 0);
            }
            i3 += min;
            i5 -= min;
            this.encrypted = true;
            i4 = 0;
        }
    }

    private void processAAD() {
        if (this.aadFinished) {
            return;
        }
        byte[] byteArray = this.aadData.toByteArray();
        AbsorbAny(byteArray, 0, byteArray.length, this.Rabsorb, 3);
        this.aadFinished = true;
    }

    private void reset(boolean z) {
        if (z) {
            this.tag = null;
        }
        Arrays.fill(this.state, (byte) 0);
        this.aadFinished = false;
        this.encrypted = false;
        this.phase = 2;
        this.message.reset();
        this.aadData.reset();
        int length = this.f704K.length;
        int length2 = this.f706iv.length;
        byte[] bArr = new byte[44];
        this.mode = MODE.ModeKeyed;
        this.Rabsorb = 44;
        System.arraycopy(this.f704K, 0, bArr, 0, length);
        System.arraycopy(this.f706iv, 0, bArr, length, length2);
        int i = length + length2;
        bArr[i] = (byte) length2;
        AbsorbAny(bArr, 0, i + 1, this.Rabsorb, 2);
    }

    void Down(byte[] bArr, int i, int i2, int i3) {
        int i4 = 0;
        while (i4 < i2) {
            byte[] bArr2 = this.state;
            bArr2[i4] = (byte) (bArr[i] ^ bArr2[i4]);
            i4++;
            i++;
        }
        byte[] bArr3 = this.state;
        bArr3[i2] = (byte) (bArr3[i2] ^ 1);
        byte b = bArr3[47];
        if (this.mode == MODE.ModeHash) {
            i3 &= 1;
        }
        bArr3[47] = (byte) (b ^ i3);
        this.phase = 1;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        int i2;
        if (this.initialised) {
            byte[] byteArray = this.message.toByteArray();
            int size = this.message.size();
            boolean z = this.forEncryption;
            if ((!z || size + 16 + i <= bArr.length) && (z || (size - 16) + i <= bArr.length)) {
                processAAD();
                if (this.forEncryption) {
                    encrypt(byteArray, 0, size, bArr, i);
                    byte[] bArr2 = new byte[16];
                    this.tag = bArr2;
                    m48Up(bArr2, 16, 64);
                    System.arraycopy(this.tag, 0, bArr, i + size, 16);
                    i2 = size + 16;
                } else {
                    i2 = size - 16;
                    encrypt(byteArray, 0, i2, bArr, i);
                    byte[] bArr3 = new byte[16];
                    this.tag = bArr3;
                    m48Up(bArr3, 16, 64);
                    int i3 = i2;
                    int i4 = 0;
                    while (i4 < 16) {
                        int i5 = i3 + 1;
                        if (this.tag[i4] != byteArray[i3]) {
                            throw new IllegalArgumentException("Mac does not match");
                        }
                        i4++;
                        i3 = i5;
                    }
                }
                reset(false);
                return i2;
            }
            throw new OutputLengthException("output buffer too short");
        }
        throw new IllegalArgumentException("Need call init function before encryption/decryption");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return "Xoodyak AEAD";
    }

    public int getBlockSize() {
        return 24;
    }

    public int getIVBytesSize() {
        return 16;
    }

    public int getKeyBytesSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        return this.tag;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getOutputSize(int i) {
        return i + 16;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int i) {
        return i;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("Xoodyak init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        this.f706iv = iv;
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("Xoodyak requires exactly 16 bytes of IV");
        }
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("Xoodyak init parameters must include a key");
        }
        byte[] key = ((KeyParameter) parametersWithIV.getParameters()).getKey();
        this.f704K = key;
        if (key.length != 16) {
            throw new IllegalArgumentException("Xoodyak key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
        this.state = new byte[48];
        this.tag = new byte[16];
        this.initialised = true;
        reset();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        if (this.aadFinished) {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + getBlockSize() + " bytes) of input for " + (this.forEncryption ? "encryption" : "decryption"));
        }
        this.aadData.write(b);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (this.aadFinished) {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + getBlockSize() + " bytes) of input for " + (this.forEncryption ? "encryption" : "decryption"));
        } else if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        } else {
            this.aadData.write(bArr, i, i2);
        }
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        return processBytes(new byte[]{b}, 0, 1, bArr, i);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (this.initialised) {
            if (this.mode == MODE.ModeKeyed) {
                if (i + i2 <= bArr.length) {
                    this.message.write(bArr, i, i2);
                    int size = this.message.size() - (this.forEncryption ? 0 : 16);
                    if (size >= getBlockSize()) {
                        byte[] byteArray = this.message.toByteArray();
                        int blockSize = (size / getBlockSize()) * getBlockSize();
                        if (blockSize + i3 <= bArr2.length) {
                            processAAD();
                            encrypt(byteArray, 0, blockSize, bArr2, i3);
                            this.message.reset();
                            this.message.write(byteArray, blockSize, byteArray.length - blockSize);
                            return blockSize;
                        }
                        throw new OutputLengthException("output buffer is too short");
                    }
                    return 0;
                }
                throw new DataLengthException("input buffer too short");
            }
            throw new IllegalArgumentException("Xoodyak has not been initialised");
        }
        throw new IllegalArgumentException("Need call init function before encryption/decryption");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        if (!this.initialised) {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        reset(true);
    }
}