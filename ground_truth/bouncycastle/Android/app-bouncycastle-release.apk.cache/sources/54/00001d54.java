package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: classes2.dex */
public class PhotonBeetleEngine implements AEADCipher {

    /* renamed from: A */
    private byte[] f657A;

    /* renamed from: K */
    private byte[] f661K;
    private final int LAST_THREE_BITS_OFFSET;

    /* renamed from: N */
    private byte[] f662N;
    private final int RATE_INBYTES;
    private final int RATE_INBYTES_HALF;
    private final int STATE_INBYTES;

    /* renamed from: T */
    private byte[] f665T;
    private boolean encrypted;
    private boolean forEncryption;
    private boolean initialised;
    private boolean input_empty;
    private byte[] state;
    private byte[][] state_2d;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final int CRYPTO_KEYBYTES = 16;
    private final int CRYPTO_NPUBBYTES = 16;
    private final int TAG_INBYTES = 16;
    private final int ROUND = 12;

    /* renamed from: D */
    private final int f658D = 8;

    /* renamed from: Dq */
    private final int f659Dq = 3;

    /* renamed from: Dr */
    private final int f660Dr = 7;
    private final int DSquare = 64;

    /* renamed from: S */
    private final int f664S = 4;
    private final int S_1 = 3;

    /* renamed from: RC */
    private final byte[][] f663RC = {new byte[]{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10}, new byte[]{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11}, new byte[]{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9}, new byte[]{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13}, new byte[]{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5}, new byte[]{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4}, new byte[]{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6}, new byte[]{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}};
    private final byte[][] MixColMatrix = {new byte[]{2, 4, 2, 11, 2, 8, 5, 6}, new byte[]{12, 9, 8, 13, 7, 7, 5, 2}, new byte[]{4, 4, 13, 13, 9, 4, 13, 9}, new byte[]{1, 6, 5, 1, 12, 13, 15, 14}, new byte[]{15, 12, 9, 13, 14, 5, 14, 13}, new byte[]{9, 14, 5, 15, 4, 12, 9, 6}, new byte[]{12, 2, 2, 10, 3, 1, 1, 14}, new byte[]{15, 1, 13, 10, 5, 10, 2, 3}};
    private final byte[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    /* renamed from: org.bouncycastle.crypto.engines.PhotonBeetleEngine$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C11901 {

        /* renamed from: $SwitchMap$org$bouncycastle$crypto$engines$PhotonBeetleEngine$PhotonBeetleParameters */
        static final /* synthetic */ int[] f666x8b160f06;

        static {
            int[] iArr = new int[PhotonBeetleParameters.values().length];
            f666x8b160f06 = iArr;
            try {
                iArr[PhotonBeetleParameters.pb32.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f666x8b160f06[PhotonBeetleParameters.pb128.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public enum PhotonBeetleParameters {
        pb32,
        pb128
    }

    public PhotonBeetleEngine(PhotonBeetleParameters photonBeetleParameters) {
        int i;
        int i2;
        int i3 = C11901.f666x8b160f06[photonBeetleParameters.ordinal()];
        if (i3 != 1) {
            i = i3 != 2 ? 0 : 128;
            i2 = i;
        } else {
            i = 32;
            i2 = BERTags.FLAGS;
        }
        int i4 = i + 7;
        this.RATE_INBYTES = i4 >>> 3;
        this.RATE_INBYTES_HALF = i4 >>> 4;
        int i5 = i + i2;
        int i6 = (i5 + 7) >>> 3;
        this.STATE_INBYTES = i6;
        this.LAST_THREE_BITS_OFFSET = (i5 - ((i6 - 1) << 3)) - 3;
        this.initialised = false;
    }

    private void PHOTON_Permutation() {
        for (int i = 0; i < 64; i++) {
            this.state_2d[i >>> 3][i & 7] = (byte) (((this.state[i >> 1] & UByte.MAX_VALUE) >>> ((i & 1) * 4)) & 15);
        }
        for (int i2 = 0; i2 < 12; i2++) {
            for (int i3 = 0; i3 < 8; i3++) {
                byte[] bArr = this.state_2d[i3];
                bArr[0] = (byte) (bArr[0] ^ this.f663RC[i3][i2]);
            }
            for (int i4 = 0; i4 < 8; i4++) {
                for (int i5 = 0; i5 < 8; i5++) {
                    byte[] bArr2 = this.state_2d[i4];
                    bArr2[i5] = this.sbox[bArr2[i5]];
                }
            }
            for (int i6 = 1; i6 < 8; i6++) {
                System.arraycopy(this.state_2d[i6], 0, this.state, 0, 8);
                int i7 = 8 - i6;
                System.arraycopy(this.state, i6, this.state_2d[i6], 0, i7);
                System.arraycopy(this.state, 0, this.state_2d[i6], i7, i6);
            }
            for (int i8 = 0; i8 < 8; i8++) {
                for (int i9 = 0; i9 < 8; i9++) {
                    int i10 = 0;
                    for (int i11 = 0; i11 < 8; i11++) {
                        byte b = this.MixColMatrix[i9][i11];
                        byte b2 = this.state_2d[i11][i8];
                        i10 = (((i10 ^ ((b2 & 1) * b)) ^ ((b2 & 2) * b)) ^ ((b2 & 4) * b)) ^ (b * (b2 & 8));
                    }
                    int i12 = i10 >>> 4;
                    int i13 = (i12 << 1) ^ ((i10 & 15) ^ i12);
                    int i14 = i13 >>> 4;
                    this.state[i9] = (byte) (((i13 & 15) ^ i14) ^ (i14 << 1));
                }
                for (int i15 = 0; i15 < 8; i15++) {
                    this.state_2d[i15][i8] = this.state[i15];
                }
            }
        }
        for (int i16 = 0; i16 < 64; i16 += 2) {
            byte[] bArr3 = this.state_2d[i16 >>> 3];
            this.state[i16 >>> 1] = (byte) (((bArr3[(i16 + 1) & 7] & 15) << 4) | (bArr3[i16 & 7] & 15));
        }
    }

    private void XOR(byte[] bArr, int i, int i2) {
        int i3 = 0;
        while (i3 < i2) {
            byte[] bArr2 = this.state;
            bArr2[i3] = (byte) (bArr[i] ^ bArr2[i3]);
            i3++;
            i++;
        }
    }

    private void reset(boolean z) {
        if (z) {
            this.f665T = null;
        }
        this.input_empty = true;
        this.aadData.reset();
        this.message.reset();
        byte[] bArr = this.f661K;
        System.arraycopy(bArr, 0, this.state, 0, bArr.length);
        byte[] bArr2 = this.f662N;
        System.arraycopy(bArr2, 0, this.state, this.f661K.length, bArr2.length);
        this.encrypted = false;
    }

    private void rhoohr(byte[] bArr, int i, byte[] bArr2, int i2, int i3) {
        int i4;
        int i5 = 0;
        byte[] bArr3 = this.state_2d[0];
        int min = Math.min(i3, this.RATE_INBYTES_HALF);
        int i6 = 0;
        while (true) {
            i4 = this.RATE_INBYTES_HALF;
            if (i6 >= i4 - 1) {
                break;
            }
            byte[] bArr4 = this.state;
            int i7 = i6 + 1;
            bArr3[i6] = (byte) (((bArr4[i7] & 1) << 7) | ((bArr4[i6] & UByte.MAX_VALUE) >>> 1));
            i6 = i7;
        }
        byte[] bArr5 = this.state;
        bArr3[i4 - 1] = (byte) (((bArr5[i6] & UByte.MAX_VALUE) >>> 1) | ((bArr5[0] & 1) << 7));
        while (i5 < min) {
            bArr[i5 + i] = (byte) (bArr2[i5 + i2] ^ this.state[this.RATE_INBYTES_HALF + i5]);
            i5++;
        }
        while (i5 < i3) {
            bArr[i5 + i] = (byte) (bArr2[i5 + i2] ^ bArr3[i5 - this.RATE_INBYTES_HALF]);
            i5++;
        }
        if (this.forEncryption) {
            XOR(bArr2, i2, i3);
        } else {
            XOR(bArr, i2, i3);
        }
    }

    private byte select(boolean z, boolean z2, byte b, byte b2) {
        if (z && z2) {
            return (byte) 1;
        }
        if (z) {
            return (byte) 2;
        }
        return z2 ? b : b2;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        if (this.initialised) {
            int size = this.message.size();
            boolean z = this.forEncryption;
            int i2 = size - (z ? 0 : 16);
            if ((!z || i2 + 16 + i <= bArr.length) && (z || i2 + i <= bArr.length)) {
                byte[] byteArray = this.message.toByteArray();
                byte[] byteArray2 = this.aadData.toByteArray();
                this.f657A = byteArray2;
                int length = byteArray2.length;
                if (length != 0 || i2 != 0) {
                    this.input_empty = false;
                }
                byte select = select(i2 != 0, length % this.RATE_INBYTES == 0, (byte) 3, (byte) 4);
                byte select2 = select(length != 0, i2 % this.RATE_INBYTES == 0, (byte) 5, (byte) 6);
                if (length != 0) {
                    int i3 = this.RATE_INBYTES;
                    int i4 = ((length + i3) - 1) / i3;
                    int i5 = 0;
                    while (true) {
                        int i6 = i4 - 1;
                        PHOTON_Permutation();
                        if (i5 >= i6) {
                            break;
                        }
                        byte[] bArr2 = this.f657A;
                        int i7 = this.RATE_INBYTES;
                        XOR(bArr2, i5 * i7, i7);
                        i5++;
                    }
                    int i8 = this.RATE_INBYTES;
                    int i9 = length - (i5 * i8);
                    XOR(this.f657A, i5 * i8, i9);
                    if (i9 < this.RATE_INBYTES) {
                        byte[] bArr3 = this.state;
                        bArr3[i9] = (byte) (bArr3[i9] ^ 1);
                    }
                    byte[] bArr4 = this.state;
                    int i10 = this.STATE_INBYTES - 1;
                    bArr4[i10] = (byte) ((select << this.LAST_THREE_BITS_OFFSET) ^ bArr4[i10]);
                }
                if (i2 != 0) {
                    int i11 = this.RATE_INBYTES;
                    int i12 = ((i2 + i11) - 1) / i11;
                    int i13 = 0;
                    while (true) {
                        int i14 = i12 - 1;
                        PHOTON_Permutation();
                        if (i13 >= i14) {
                            break;
                        }
                        int i15 = this.RATE_INBYTES;
                        rhoohr(bArr, i + (i13 * i15), byteArray, i13 * i15, i15);
                        i13++;
                    }
                    int i16 = this.RATE_INBYTES;
                    int i17 = i2 - (i13 * i16);
                    rhoohr(bArr, i + (i13 * i16), byteArray, i13 * i16, i17);
                    if (i17 < this.RATE_INBYTES) {
                        byte[] bArr5 = this.state;
                        bArr5[i17] = (byte) (bArr5[i17] ^ 1);
                    }
                    byte[] bArr6 = this.state;
                    int i18 = this.STATE_INBYTES - 1;
                    bArr6[i18] = (byte) (bArr6[i18] ^ (select2 << this.LAST_THREE_BITS_OFFSET));
                }
                int i19 = i + i2;
                if (this.input_empty) {
                    byte[] bArr7 = this.state;
                    int i20 = this.STATE_INBYTES - 1;
                    bArr7[i20] = (byte) (bArr7[i20] ^ (1 << this.LAST_THREE_BITS_OFFSET));
                }
                PHOTON_Permutation();
                byte[] bArr8 = new byte[16];
                this.f665T = bArr8;
                System.arraycopy(this.state, 0, bArr8, 0, 16);
                if (this.forEncryption) {
                    System.arraycopy(this.f665T, 0, bArr, i19, 16);
                    i2 += 16;
                } else {
                    for (int i21 = 0; i21 < 16; i21++) {
                        if (this.f665T[i21] != byteArray[i2 + i21]) {
                            throw new IllegalArgumentException("Mac does not match");
                        }
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
        return "Photon-Beetle AEAD";
    }

    public int getBlockSize() {
        return this.RATE_INBYTES;
    }

    public int getIVBytesSize() {
        return 16;
    }

    public int getKeyBytesSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        return this.f665T;
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
            throw new IllegalArgumentException("Photon-Beetle AEAD init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        this.f662N = iv;
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("Photon-Beetle AEAD requires exactly 16 bytes of IV");
        }
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("Photon-Beetle AEAD init parameters must include a key");
        }
        byte[] key = ((KeyParameter) parametersWithIV.getParameters()).getKey();
        this.f661K = key;
        if (key.length != 16) {
            throw new IllegalArgumentException("Photon-Beetle AEAD key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
        this.state = new byte[this.STATE_INBYTES];
        this.state_2d = (byte[][]) Array.newInstance(Byte.TYPE, 8, 8);
        this.f665T = new byte[16];
        this.initialised = true;
        reset(false);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        this.aadData.write(b);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        this.aadData.write(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        return processBytes(new byte[]{b}, 0, 1, bArr, i);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (i + i2 <= bArr.length) {
            this.message.write(bArr, i, i2);
            return 0;
        }
        throw new DataLengthException("input buffer too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        if (!this.initialised) {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        reset(true);
    }
}