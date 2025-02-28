package org.bouncycastle.crypto.engines;

import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.digests.SparkleDigest;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SparkleEngine implements AEADCipher {
    private static final int[] RCON = {-1209970334, -1083090816, 951376470, 844003128, -1156479509, 1333558103, -809524792, -1028445891};
    private final int CAP_MASK;
    private final int KEY_BYTES;
    private final int KEY_WORDS;
    private final int RATE_BYTES;
    private final int RATE_WORDS;
    private final int SCHWAEMM_KEY_LEN;
    private final int SCHWAEMM_NONCE_LEN;
    private final int SPARKLE_STEPS_BIG;
    private final int SPARKLE_STEPS_SLIM;
    private final int STATE_WORDS;
    private final int TAG_BYTES;
    private final int TAG_WORDS;
    private final int _A0;
    private final int _A1;
    private final int _M2;
    private final int _M3;
    private String algorithmName;
    private boolean encrypted;
    private byte[] initialAssociatedText;

    /* renamed from: k */
    private final int[] f689k;
    private final byte[] m_buf;
    private final int m_bufferSizeDecrypt;
    private final int[] npub;
    private final int[] state;
    private byte[] tag;
    private State m_state = State.Uninitialized;
    private int m_bufPos = 0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: org.bouncycastle.crypto.engines.SparkleEngine$1 */
    /* loaded from: classes2.dex */
    public static /* synthetic */ class C11921 {

        /* renamed from: $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$SparkleParameters */
        static final /* synthetic */ int[] f690xfdf3810e;
        static final /* synthetic */ int[] $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State;

        static {
            int[] iArr = new int[State.values().length];
            $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State = iArr;
            try {
                iArr[State.DecInit.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.DecAad.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.DecData.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.DecFinal.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.EncData.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.EncFinal.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.EncInit.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[State.EncAad.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            int[] iArr2 = new int[SparkleParameters.values().length];
            f690xfdf3810e = iArr2;
            try {
                iArr2[SparkleParameters.SCHWAEMM128_128.ordinal()] = 1;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f690xfdf3810e[SparkleParameters.SCHWAEMM256_128.ordinal()] = 2;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f690xfdf3810e[SparkleParameters.SCHWAEMM192_192.ordinal()] = 3;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f690xfdf3810e[SparkleParameters.SCHWAEMM256_256.ordinal()] = 4;
            } catch (NoSuchFieldError unused12) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public enum SparkleParameters {
        SCHWAEMM128_128,
        SCHWAEMM256_128,
        SCHWAEMM192_192,
        SCHWAEMM256_256
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public enum State {
        Uninitialized,
        EncInit,
        EncAad,
        EncData,
        EncFinal,
        DecInit,
        DecAad,
        DecData,
        DecFinal
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0096  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public SparkleEngine(org.bouncycastle.crypto.engines.SparkleEngine.SparkleParameters r9) {
        /*
            Method dump skipped, instructions count: 195
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.engines.SparkleEngine.<init>(org.bouncycastle.crypto.engines.SparkleEngine$SparkleParameters):void");
    }

    private static int ELL(int i) {
        return (i & 65535) ^ Integers.rotateRight(i, 16);
    }

    private void checkAAD() {
        State state;
        int i = C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()];
        if (i == 1) {
            state = State.DecAad;
        } else if (i == 2) {
            return;
        } else {
            if (i == 6) {
                throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
            }
            if (i != 7) {
                if (i != 8) {
                    throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
                }
                return;
            }
            state = State.EncAad;
        }
        this.m_state = state;
    }

    private boolean checkData() {
        switch (C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()]) {
            case 1:
            case 2:
                finishAAD(State.DecData);
                return false;
            case 3:
                return false;
            case 4:
            default:
                throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
            case 5:
                return true;
            case 6:
                throw new IllegalStateException(getAlgorithmName() + " cannot be reused for encryption");
            case 7:
            case 8:
                finishAAD(State.EncData);
                return true;
        }
    }

    private void finishAAD(State state) {
        int i = C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()];
        if (i == 2 || i == 8) {
            processFinalAAD();
        }
        this.m_bufPos = 0;
        this.m_state = state;
    }

    private void processBufferAAD(byte[] bArr, int i) {
        int i2 = 0;
        while (true) {
            int i3 = this.RATE_WORDS;
            if (i2 >= i3 / 2) {
                sparkle_opt(this.state, this.SPARKLE_STEPS_SLIM);
                return;
            }
            int i4 = (i3 / 2) + i2;
            int[] iArr = this.state;
            int i5 = iArr[i2];
            int i6 = iArr[i4];
            int littleEndianToInt = Pack.littleEndianToInt(bArr, (i2 * 4) + i);
            int littleEndianToInt2 = Pack.littleEndianToInt(bArr, (i4 * 4) + i);
            int[] iArr2 = this.state;
            int i7 = this.RATE_WORDS;
            iArr2[i2] = (littleEndianToInt ^ i6) ^ iArr2[i7 + i2];
            iArr2[i4] = ((i6 ^ i5) ^ littleEndianToInt2) ^ iArr2[i7 + (this.CAP_MASK & i4)];
            i2++;
        }
    }

    private void processBufferDecrypt(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (i2 > bArr2.length - this.RATE_BYTES) {
            throw new OutputLengthException("output buffer too short");
        }
        int i3 = 0;
        while (true) {
            int i4 = this.RATE_WORDS;
            if (i3 >= i4 / 2) {
                sparkle_opt(this.state, this.SPARKLE_STEPS_SLIM);
                this.encrypted = true;
                return;
            }
            int i5 = (i4 / 2) + i3;
            int[] iArr = this.state;
            int i6 = iArr[i3];
            int i7 = iArr[i5];
            int i8 = i3 * 4;
            int littleEndianToInt = Pack.littleEndianToInt(bArr, i + i8);
            int i9 = i5 * 4;
            int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + i9);
            int[] iArr2 = this.state;
            int i10 = this.RATE_WORDS;
            iArr2[i3] = ((i6 ^ i7) ^ littleEndianToInt) ^ iArr2[i10 + i3];
            iArr2[i5] = (i6 ^ littleEndianToInt2) ^ iArr2[i10 + (this.CAP_MASK & i5)];
            Pack.intToLittleEndian(littleEndianToInt ^ i6, bArr2, i2 + i8);
            Pack.intToLittleEndian(littleEndianToInt2 ^ i7, bArr2, i2 + i9);
            i3++;
        }
    }

    private void processBufferEncrypt(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (i2 > bArr2.length - this.RATE_BYTES) {
            throw new OutputLengthException("output buffer too short");
        }
        int i3 = 0;
        while (true) {
            int i4 = this.RATE_WORDS;
            if (i3 >= i4 / 2) {
                sparkle_opt(this.state, this.SPARKLE_STEPS_SLIM);
                this.encrypted = true;
                return;
            }
            int i5 = (i4 / 2) + i3;
            int[] iArr = this.state;
            int i6 = iArr[i3];
            int i7 = iArr[i5];
            int i8 = i3 * 4;
            int littleEndianToInt = Pack.littleEndianToInt(bArr, i + i8);
            int i9 = i5 * 4;
            int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + i9);
            int[] iArr2 = this.state;
            int i10 = this.RATE_WORDS;
            iArr2[i3] = (i7 ^ littleEndianToInt) ^ iArr2[i10 + i3];
            iArr2[i5] = ((i6 ^ i7) ^ littleEndianToInt2) ^ iArr2[i10 + (this.CAP_MASK & i5)];
            Pack.intToLittleEndian(littleEndianToInt ^ i6, bArr2, i2 + i8);
            Pack.intToLittleEndian(littleEndianToInt2 ^ i7, bArr2, i2 + i9);
            i3++;
        }
    }

    private void processFinalAAD() {
        int i = this.m_bufPos;
        int i2 = 0;
        if (i < this.RATE_BYTES) {
            int[] iArr = this.state;
            int i3 = this.STATE_WORDS - 1;
            iArr[i3] = iArr[i3] ^ this._A0;
            this.m_buf[i] = ByteCompanionObject.MIN_VALUE;
            while (true) {
                int i4 = this.m_bufPos + 1;
                this.m_bufPos = i4;
                if (i4 >= this.RATE_BYTES) {
                    break;
                }
                this.m_buf[i4] = 0;
            }
        } else {
            int[] iArr2 = this.state;
            int i5 = this.STATE_WORDS - 1;
            iArr2[i5] = iArr2[i5] ^ this._A1;
        }
        while (true) {
            int i6 = this.RATE_WORDS;
            if (i2 >= i6 / 2) {
                sparkle_opt(this.state, this.SPARKLE_STEPS_BIG);
                return;
            }
            int i7 = (i6 / 2) + i2;
            int[] iArr3 = this.state;
            int i8 = iArr3[i2];
            int i9 = iArr3[i7];
            int littleEndianToInt = Pack.littleEndianToInt(this.m_buf, i2 * 4);
            int littleEndianToInt2 = Pack.littleEndianToInt(this.m_buf, i7 * 4);
            int[] iArr4 = this.state;
            int i10 = this.RATE_WORDS;
            iArr4[i2] = (littleEndianToInt ^ i9) ^ iArr4[i10 + i2];
            iArr4[i7] = ((i9 ^ i8) ^ littleEndianToInt2) ^ iArr4[i10 + (this.CAP_MASK & i7)];
            i2++;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private void reset(boolean z) {
        if (z) {
            this.tag = null;
        }
        Arrays.clear(this.m_buf);
        this.m_bufPos = 0;
        this.encrypted = false;
        switch (C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()]) {
            case 1:
            case 7:
                break;
            case 2:
            case 3:
            case 4:
                this.m_state = State.DecInit;
                break;
            case 5:
            case 6:
            case 8:
                this.m_state = State.EncFinal;
                return;
            default:
                throw new IllegalStateException(getAlgorithmName() + " needs to be initialized");
        }
        System.arraycopy(this.npub, 0, this.state, 0, this.RATE_WORDS);
        System.arraycopy(this.f689k, 0, this.state, this.RATE_WORDS, this.KEY_WORDS);
        sparkle_opt(this.state, this.SPARKLE_STEPS_BIG);
        byte[] bArr = this.initialAssociatedText;
        if (bArr != null) {
            processAADBytes(bArr, 0, bArr.length);
        }
    }

    private static void sparkle_opt(int[] iArr, int i) {
        int length = iArr.length;
        if (length == 8) {
            sparkle_opt8(iArr, i);
        } else if (length == 12) {
            sparkle_opt12(iArr, i);
        } else if (length != 16) {
            throw new IllegalStateException();
        } else {
            sparkle_opt16(iArr, i);
        }
    }

    public static void sparkle_opt12(SparkleDigest.Friend friend, int[] iArr, int i) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by SparkleDigest");
        }
        sparkle_opt12(iArr, i);
    }

    static void sparkle_opt12(int[] iArr, int i) {
        char c = 0;
        int i2 = iArr[0];
        char c2 = 1;
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = iArr[7];
        int i10 = iArr[8];
        int i11 = iArr[9];
        int i12 = iArr[10];
        int i13 = 0;
        int i14 = i11;
        int i15 = iArr[11];
        while (i13 < i) {
            int[] iArr2 = RCON;
            int i16 = i3 ^ iArr2[i13 & 7];
            int i17 = i5 ^ i13;
            int i18 = iArr2[c];
            int rotateRight = i2 + Integers.rotateRight(i16, 31);
            int rotateRight2 = i16 ^ Integers.rotateRight(rotateRight, 24);
            int rotateRight3 = (rotateRight ^ i18) + Integers.rotateRight(rotateRight2, 17);
            int rotateRight4 = rotateRight2 ^ Integers.rotateRight(rotateRight3, 17);
            int i19 = (rotateRight3 ^ i18) + rotateRight4;
            int rotateRight5 = rotateRight4 ^ Integers.rotateRight(i19, 31);
            int rotateRight6 = (i19 ^ i18) + Integers.rotateRight(rotateRight5, 24);
            int rotateRight7 = rotateRight5 ^ Integers.rotateRight(rotateRight6, 16);
            int i20 = rotateRight6 ^ i18;
            int i21 = iArr2[c2];
            int rotateRight8 = i4 + Integers.rotateRight(i17, 31);
            int rotateRight9 = i17 ^ Integers.rotateRight(rotateRight8, 24);
            int rotateRight10 = (rotateRight8 ^ i21) + Integers.rotateRight(rotateRight9, 17);
            int rotateRight11 = rotateRight9 ^ Integers.rotateRight(rotateRight10, 17);
            int i22 = (rotateRight10 ^ i21) + rotateRight11;
            int rotateRight12 = rotateRight11 ^ Integers.rotateRight(i22, 31);
            int rotateRight13 = (i22 ^ i21) + Integers.rotateRight(rotateRight12, 24);
            int rotateRight14 = rotateRight12 ^ Integers.rotateRight(rotateRight13, 16);
            int i23 = rotateRight13 ^ i21;
            int i24 = iArr2[2];
            int rotateRight15 = i6 + Integers.rotateRight(i7, 31);
            int rotateRight16 = Integers.rotateRight(rotateRight15, 24) ^ i7;
            int rotateRight17 = (rotateRight15 ^ i24) + Integers.rotateRight(rotateRight16, 17);
            int rotateRight18 = rotateRight16 ^ Integers.rotateRight(rotateRight17, 17);
            int i25 = (rotateRight17 ^ i24) + rotateRight18;
            int rotateRight19 = rotateRight18 ^ Integers.rotateRight(i25, 31);
            int rotateRight20 = (i25 ^ i24) + Integers.rotateRight(rotateRight19, 24);
            int rotateRight21 = rotateRight19 ^ Integers.rotateRight(rotateRight20, 16);
            int i26 = rotateRight20 ^ i24;
            int i27 = iArr2[3];
            int rotateRight22 = i8 + Integers.rotateRight(i9, 31);
            int rotateRight23 = Integers.rotateRight(rotateRight22, 24) ^ i9;
            int rotateRight24 = (rotateRight22 ^ i27) + Integers.rotateRight(rotateRight23, 17);
            int rotateRight25 = rotateRight23 ^ Integers.rotateRight(rotateRight24, 17);
            int i28 = (rotateRight24 ^ i27) + rotateRight25;
            int rotateRight26 = rotateRight25 ^ Integers.rotateRight(i28, 31);
            int rotateRight27 = (i28 ^ i27) + Integers.rotateRight(rotateRight26, 24);
            int rotateRight28 = rotateRight26 ^ Integers.rotateRight(rotateRight27, 16);
            int i29 = rotateRight27 ^ i27;
            int i30 = iArr2[4];
            int rotateRight29 = i10 + Integers.rotateRight(i14, 31);
            int rotateRight30 = i14 ^ Integers.rotateRight(rotateRight29, 24);
            int rotateRight31 = (rotateRight29 ^ i30) + Integers.rotateRight(rotateRight30, 17);
            int rotateRight32 = rotateRight30 ^ Integers.rotateRight(rotateRight31, 17);
            int i31 = (rotateRight31 ^ i30) + rotateRight32;
            int rotateRight33 = rotateRight32 ^ Integers.rotateRight(i31, 31);
            int rotateRight34 = (i31 ^ i30) + Integers.rotateRight(rotateRight33, 24);
            int rotateRight35 = rotateRight33 ^ Integers.rotateRight(rotateRight34, 16);
            int i32 = iArr2[5];
            int rotateRight36 = i12 + Integers.rotateRight(i15, 31);
            int rotateRight37 = i15 ^ Integers.rotateRight(rotateRight36, 24);
            int rotateRight38 = (rotateRight36 ^ i32) + Integers.rotateRight(rotateRight37, 17);
            int rotateRight39 = Integers.rotateRight(rotateRight38, 17) ^ rotateRight37;
            int i33 = (rotateRight38 ^ i32) + rotateRight39;
            int rotateRight40 = Integers.rotateRight(i33, 31) ^ rotateRight39;
            int rotateRight41 = (i33 ^ i32) + Integers.rotateRight(rotateRight40, 24);
            int rotateRight42 = rotateRight40 ^ Integers.rotateRight(rotateRight41, 16);
            int ELL = ELL((i20 ^ i23) ^ i26);
            int ELL2 = ELL((rotateRight7 ^ rotateRight14) ^ rotateRight21);
            int i34 = ((rotateRight34 ^ i30) ^ i23) ^ ELL2;
            int i35 = ((rotateRight41 ^ i32) ^ i26) ^ ELL2;
            int i36 = (rotateRight42 ^ rotateRight21) ^ ELL;
            int i37 = (i29 ^ i20) ^ ELL2;
            i7 = (rotateRight28 ^ rotateRight7) ^ ELL;
            i13++;
            i9 = rotateRight7;
            i3 = (rotateRight35 ^ rotateRight14) ^ ELL;
            i10 = i23;
            i4 = i35;
            i15 = rotateRight21;
            i12 = i26;
            i6 = i37;
            i5 = i36;
            i8 = i20;
            i2 = i34;
            c = 0;
            i14 = rotateRight14;
            c2 = 1;
        }
        iArr[c] = i2;
        iArr[1] = i3;
        iArr[2] = i4;
        iArr[3] = i5;
        iArr[4] = i6;
        iArr[5] = i7;
        iArr[6] = i8;
        iArr[7] = i9;
        iArr[8] = i10;
        iArr[9] = i14;
        iArr[10] = i12;
        iArr[11] = i15;
    }

    public static void sparkle_opt16(SparkleDigest.Friend friend, int[] iArr, int i) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by SparkleDigest");
        }
        sparkle_opt16(iArr, i);
    }

    static void sparkle_opt16(int[] iArr, int i) {
        char c = 0;
        int i2 = iArr[0];
        char c2 = 1;
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = iArr[7];
        int i10 = iArr[8];
        int i11 = iArr[9];
        int i12 = iArr[10];
        int i13 = iArr[11];
        int i14 = iArr[12];
        int i15 = iArr[13];
        int i16 = iArr[14];
        int i17 = i;
        int i18 = 0;
        int i19 = i11;
        int i20 = i13;
        int i21 = i15;
        int i22 = iArr[15];
        while (i18 < i17) {
            int[] iArr2 = RCON;
            int i23 = i3 ^ iArr2[i18 & 7];
            int i24 = i5 ^ i18;
            int i25 = iArr2[c];
            int rotateRight = i2 + Integers.rotateRight(i23, 31);
            int rotateRight2 = i23 ^ Integers.rotateRight(rotateRight, 24);
            int rotateRight3 = (rotateRight ^ i25) + Integers.rotateRight(rotateRight2, 17);
            int rotateRight4 = rotateRight2 ^ Integers.rotateRight(rotateRight3, 17);
            int i26 = (rotateRight3 ^ i25) + rotateRight4;
            int rotateRight5 = rotateRight4 ^ Integers.rotateRight(i26, 31);
            int rotateRight6 = (i26 ^ i25) + Integers.rotateRight(rotateRight5, 24);
            int rotateRight7 = rotateRight5 ^ Integers.rotateRight(rotateRight6, 16);
            int i27 = rotateRight6 ^ i25;
            int i28 = iArr2[c2];
            int rotateRight8 = i4 + Integers.rotateRight(i24, 31);
            int rotateRight9 = i24 ^ Integers.rotateRight(rotateRight8, 24);
            int rotateRight10 = (rotateRight8 ^ i28) + Integers.rotateRight(rotateRight9, 17);
            int rotateRight11 = rotateRight9 ^ Integers.rotateRight(rotateRight10, 17);
            int i29 = (rotateRight10 ^ i28) + rotateRight11;
            int rotateRight12 = rotateRight11 ^ Integers.rotateRight(i29, 31);
            int rotateRight13 = (i29 ^ i28) + Integers.rotateRight(rotateRight12, 24);
            int rotateRight14 = rotateRight12 ^ Integers.rotateRight(rotateRight13, 16);
            int i30 = rotateRight13 ^ i28;
            int i31 = iArr2[2];
            int rotateRight15 = i6 + Integers.rotateRight(i7, 31);
            int rotateRight16 = Integers.rotateRight(rotateRight15, 24) ^ i7;
            int rotateRight17 = (rotateRight15 ^ i31) + Integers.rotateRight(rotateRight16, 17);
            int rotateRight18 = rotateRight16 ^ Integers.rotateRight(rotateRight17, 17);
            int i32 = (rotateRight17 ^ i31) + rotateRight18;
            int rotateRight19 = rotateRight18 ^ Integers.rotateRight(i32, 31);
            int rotateRight20 = (i32 ^ i31) + Integers.rotateRight(rotateRight19, 24);
            int rotateRight21 = rotateRight19 ^ Integers.rotateRight(rotateRight20, 16);
            int i33 = rotateRight20 ^ i31;
            int i34 = iArr2[3];
            int rotateRight22 = i8 + Integers.rotateRight(i9, 31);
            int rotateRight23 = Integers.rotateRight(rotateRight22, 24) ^ i9;
            int rotateRight24 = (rotateRight22 ^ i34) + Integers.rotateRight(rotateRight23, 17);
            int rotateRight25 = rotateRight23 ^ Integers.rotateRight(rotateRight24, 17);
            int i35 = (rotateRight24 ^ i34) + rotateRight25;
            int rotateRight26 = rotateRight25 ^ Integers.rotateRight(i35, 31);
            int rotateRight27 = (i35 ^ i34) + Integers.rotateRight(rotateRight26, 24);
            int rotateRight28 = rotateRight26 ^ Integers.rotateRight(rotateRight27, 16);
            int i36 = rotateRight27 ^ i34;
            int i37 = iArr2[4];
            int rotateRight29 = i10 + Integers.rotateRight(i19, 31);
            int rotateRight30 = i19 ^ Integers.rotateRight(rotateRight29, 24);
            int rotateRight31 = (rotateRight29 ^ i37) + Integers.rotateRight(rotateRight30, 17);
            int rotateRight32 = rotateRight30 ^ Integers.rotateRight(rotateRight31, 17);
            int i38 = (rotateRight31 ^ i37) + rotateRight32;
            int rotateRight33 = rotateRight32 ^ Integers.rotateRight(i38, 31);
            int rotateRight34 = (i38 ^ i37) + Integers.rotateRight(rotateRight33, 24);
            int rotateRight35 = rotateRight33 ^ Integers.rotateRight(rotateRight34, 16);
            int i39 = iArr2[5];
            int rotateRight36 = i12 + Integers.rotateRight(i20, 31);
            int rotateRight37 = i20 ^ Integers.rotateRight(rotateRight36, 24);
            int rotateRight38 = (rotateRight36 ^ i39) + Integers.rotateRight(rotateRight37, 17);
            int rotateRight39 = rotateRight37 ^ Integers.rotateRight(rotateRight38, 17);
            int i40 = (rotateRight38 ^ i39) + rotateRight39;
            int rotateRight40 = rotateRight39 ^ Integers.rotateRight(i40, 31);
            int rotateRight41 = (i40 ^ i39) + Integers.rotateRight(rotateRight40, 24);
            int rotateRight42 = rotateRight40 ^ Integers.rotateRight(rotateRight41, 16);
            int i41 = rotateRight41 ^ i39;
            int i42 = iArr2[6];
            int i43 = i21;
            int rotateRight43 = i14 + Integers.rotateRight(i43, 31);
            int rotateRight44 = i43 ^ Integers.rotateRight(rotateRight43, 24);
            int rotateRight45 = (rotateRight43 ^ i42) + Integers.rotateRight(rotateRight44, 17);
            int rotateRight46 = rotateRight44 ^ Integers.rotateRight(rotateRight45, 17);
            int i44 = (rotateRight45 ^ i42) + rotateRight46;
            int rotateRight47 = rotateRight46 ^ Integers.rotateRight(i44, 31);
            int rotateRight48 = (i44 ^ i42) + Integers.rotateRight(rotateRight47, 24);
            int rotateRight49 = rotateRight47 ^ Integers.rotateRight(rotateRight48, 16);
            int i45 = rotateRight48 ^ i42;
            int i46 = iArr2[7];
            int i47 = i18;
            int i48 = i22;
            int rotateRight50 = i16 + Integers.rotateRight(i48, 31);
            int rotateRight51 = i48 ^ Integers.rotateRight(rotateRight50, 24);
            int rotateRight52 = (rotateRight50 ^ i46) + Integers.rotateRight(rotateRight51, 17);
            int rotateRight53 = rotateRight51 ^ Integers.rotateRight(rotateRight52, 17);
            int i49 = (rotateRight52 ^ i46) + rotateRight53;
            int rotateRight54 = rotateRight53 ^ Integers.rotateRight(i49, 31);
            int rotateRight55 = (i49 ^ i46) + Integers.rotateRight(rotateRight54, 24);
            int rotateRight56 = rotateRight54 ^ Integers.rotateRight(rotateRight55, 16);
            int i50 = rotateRight55 ^ i46;
            int ELL = ELL(((i27 ^ i30) ^ i33) ^ i36);
            int ELL2 = ELL(((rotateRight7 ^ rotateRight14) ^ rotateRight21) ^ rotateRight28);
            int i51 = (i41 ^ i30) ^ ELL2;
            int i52 = (rotateRight42 ^ rotateRight14) ^ ELL;
            int i53 = (i45 ^ i33) ^ ELL2;
            int i54 = (rotateRight21 ^ rotateRight49) ^ ELL;
            int i55 = (i50 ^ i36) ^ ELL2;
            int i56 = (rotateRight56 ^ rotateRight28) ^ ELL;
            int i57 = ((rotateRight34 ^ i37) ^ i27) ^ ELL2;
            i9 = ELL ^ (rotateRight35 ^ rotateRight7);
            int i58 = i47 + 1;
            i10 = i27;
            i21 = rotateRight21;
            i14 = i33;
            i22 = rotateRight28;
            i2 = i51;
            i16 = i36;
            i8 = i57;
            i5 = i54;
            i20 = rotateRight14;
            i19 = rotateRight7;
            i12 = i30;
            i3 = i52;
            i6 = i55;
            i7 = i56;
            c2 = 1;
            i17 = i;
            i4 = i53;
            i18 = i58;
            c = 0;
        }
        iArr[c] = i2;
        iArr[1] = i3;
        iArr[2] = i4;
        iArr[3] = i5;
        iArr[4] = i6;
        iArr[5] = i7;
        iArr[6] = i8;
        iArr[7] = i9;
        iArr[8] = i10;
        iArr[9] = i19;
        iArr[10] = i12;
        iArr[11] = i20;
        iArr[12] = i14;
        iArr[13] = i21;
        iArr[14] = i16;
        iArr[15] = i22;
    }

    static void sparkle_opt8(int[] iArr, int i) {
        char c = 0;
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = iArr[7];
        int i10 = 0;
        while (i10 < i) {
            int[] iArr2 = RCON;
            int i11 = i3 ^ iArr2[i10 & 7];
            int i12 = i5 ^ i10;
            int i13 = iArr2[c];
            int rotateRight = i2 + Integers.rotateRight(i11, 31);
            int rotateRight2 = i11 ^ Integers.rotateRight(rotateRight, 24);
            int rotateRight3 = (rotateRight ^ i13) + Integers.rotateRight(rotateRight2, 17);
            int rotateRight4 = rotateRight2 ^ Integers.rotateRight(rotateRight3, 17);
            int i14 = (rotateRight3 ^ i13) + rotateRight4;
            int rotateRight5 = rotateRight4 ^ Integers.rotateRight(i14, 31);
            int rotateRight6 = (i14 ^ i13) + Integers.rotateRight(rotateRight5, 24);
            int rotateRight7 = rotateRight5 ^ Integers.rotateRight(rotateRight6, 16);
            int i15 = rotateRight6 ^ i13;
            int i16 = iArr2[1];
            int rotateRight8 = i4 + Integers.rotateRight(i12, 31);
            int rotateRight9 = i12 ^ Integers.rotateRight(rotateRight8, 24);
            int rotateRight10 = (rotateRight8 ^ i16) + Integers.rotateRight(rotateRight9, 17);
            int rotateRight11 = rotateRight9 ^ Integers.rotateRight(rotateRight10, 17);
            int i17 = (rotateRight10 ^ i16) + rotateRight11;
            int rotateRight12 = rotateRight11 ^ Integers.rotateRight(i17, 31);
            int rotateRight13 = (i17 ^ i16) + Integers.rotateRight(rotateRight12, 24);
            int rotateRight14 = rotateRight12 ^ Integers.rotateRight(rotateRight13, 16);
            int i18 = rotateRight13 ^ i16;
            int i19 = iArr2[2];
            int rotateRight15 = i6 + Integers.rotateRight(i7, 31);
            int rotateRight16 = i7 ^ Integers.rotateRight(rotateRight15, 24);
            int rotateRight17 = (rotateRight15 ^ i19) + Integers.rotateRight(rotateRight16, 17);
            int rotateRight18 = rotateRight16 ^ Integers.rotateRight(rotateRight17, 17);
            int i20 = (rotateRight17 ^ i19) + rotateRight18;
            int rotateRight19 = rotateRight18 ^ Integers.rotateRight(i20, 31);
            int rotateRight20 = (i20 ^ i19) + Integers.rotateRight(rotateRight19, 24);
            int i21 = iArr2[3];
            int rotateRight21 = i8 + Integers.rotateRight(i9, 31);
            int rotateRight22 = i9 ^ Integers.rotateRight(rotateRight21, 24);
            int rotateRight23 = (rotateRight21 ^ i21) + Integers.rotateRight(rotateRight22, 17);
            int rotateRight24 = Integers.rotateRight(rotateRight23, 17) ^ rotateRight22;
            int i22 = (rotateRight23 ^ i21) + rotateRight24;
            int rotateRight25 = rotateRight24 ^ Integers.rotateRight(i22, 31);
            int rotateRight26 = (i22 ^ i21) + Integers.rotateRight(rotateRight25, 24);
            int rotateRight27 = rotateRight25 ^ Integers.rotateRight(rotateRight26, 16);
            int i23 = rotateRight26 ^ i21;
            int ELL = ELL(i15 ^ i18);
            int ELL2 = ELL(rotateRight7 ^ rotateRight14);
            int i24 = (rotateRight27 ^ rotateRight14) ^ ELL;
            int rotateRight28 = ELL ^ ((rotateRight19 ^ Integers.rotateRight(rotateRight20, 16)) ^ rotateRight7);
            i10++;
            i7 = rotateRight7;
            i8 = i18;
            i9 = rotateRight14;
            i5 = rotateRight28;
            i4 = ((rotateRight20 ^ i19) ^ i15) ^ ELL2;
            i3 = i24;
            i6 = i15;
            i2 = (i23 ^ i18) ^ ELL2;
            c = 0;
        }
        iArr[c] = i2;
        iArr[1] = i3;
        iArr[2] = i4;
        iArr[3] = i5;
        iArr[4] = i6;
        iArr[5] = i7;
        iArr[6] = i8;
        iArr[7] = i9;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        int i2;
        int i3;
        boolean checkData = checkData();
        int i4 = this.m_bufPos;
        int i5 = this.TAG_BYTES;
        if (checkData) {
            i2 = i4 + i5;
        } else if (i4 < i5) {
            throw new InvalidCipherTextException("data too short");
        } else {
            i2 = i4 - i5;
            this.m_bufPos = i2;
        }
        if (i <= bArr.length - i2) {
            if (this.encrypted || this.m_bufPos > 0) {
                int[] iArr = this.state;
                int i6 = this.STATE_WORDS - 1;
                iArr[i6] = iArr[i6] ^ (this.m_bufPos < this.RATE_BYTES ? this._M2 : this._M3);
                int[] iArr2 = new int[this.RATE_WORDS];
                int i7 = 0;
                while (true) {
                    i3 = this.m_bufPos;
                    if (i7 >= i3) {
                        break;
                    }
                    int i8 = i7 >>> 2;
                    iArr2[i8] = iArr2[i8] | ((this.m_buf[i7] & UByte.MAX_VALUE) << ((i7 & 3) << 3));
                    i7++;
                }
                if (i3 < this.RATE_BYTES) {
                    if (!checkData) {
                        int i9 = (i3 & 3) << 3;
                        int i10 = i3 >>> 2;
                        int i11 = iArr2[i10];
                        int[] iArr3 = this.state;
                        iArr2[i10] = ((iArr3[i3 >>> 2] >>> i9) << i9) | i11;
                        int i12 = (i3 >>> 2) + 1;
                        System.arraycopy(iArr3, i12, iArr2, i12, this.RATE_WORDS - i12);
                    }
                    int i13 = this.m_bufPos;
                    int i14 = i13 >>> 2;
                    iArr2[i14] = (128 << ((i13 & 3) << 3)) ^ iArr2[i14];
                }
                int i15 = 0;
                while (true) {
                    int i16 = this.RATE_WORDS;
                    if (i15 >= i16 / 2) {
                        break;
                    }
                    int i17 = (i16 / 2) + i15;
                    int[] iArr4 = this.state;
                    int i18 = iArr4[i15];
                    int i19 = iArr4[i17];
                    if (checkData) {
                        iArr4[i15] = (iArr2[i15] ^ i19) ^ iArr4[i16 + i15];
                        iArr4[i17] = iArr4[i16 + (this.CAP_MASK & i17)] ^ ((i18 ^ i19) ^ iArr2[i17]);
                    } else {
                        iArr4[i15] = ((i18 ^ i19) ^ iArr2[i15]) ^ iArr4[i16 + i15];
                        iArr4[i17] = iArr4[i16 + (this.CAP_MASK & i17)] ^ (iArr2[i17] ^ i18);
                    }
                    iArr2[i15] = iArr2[i15] ^ i18;
                    iArr2[i17] = iArr2[i17] ^ i19;
                    i15++;
                }
                int i20 = 0;
                while (i20 < this.m_bufPos) {
                    bArr[i] = (byte) (iArr2[i20 >>> 2] >>> ((i20 & 3) << 3));
                    i20++;
                    i++;
                }
                sparkle_opt(this.state, this.SPARKLE_STEPS_BIG);
            }
            for (int i21 = 0; i21 < this.KEY_WORDS; i21++) {
                int[] iArr5 = this.state;
                int i22 = this.RATE_WORDS + i21;
                iArr5[i22] = iArr5[i22] ^ this.f689k[i21];
            }
            byte[] bArr2 = new byte[this.TAG_BYTES];
            this.tag = bArr2;
            Pack.intToLittleEndian(this.state, this.RATE_WORDS, this.TAG_WORDS, bArr2, 0);
            if (checkData) {
                System.arraycopy(this.tag, 0, bArr, i, this.TAG_BYTES);
            } else if (!Arrays.constantTimeAreEqual(this.TAG_BYTES, this.tag, 0, this.m_buf, this.m_bufPos)) {
                throw new InvalidCipherTextException(this.algorithmName + " mac does not match");
            }
            reset(!checkData);
            return i2;
        }
        throw new OutputLengthException("output buffer too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public int getIVBytesSize() {
        return this.RATE_BYTES;
    }

    public int getKeyBytesSize() {
        return this.KEY_BYTES;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        return this.tag;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getOutputSize(int i) {
        int max = Math.max(0, i);
        switch (C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()]) {
            case 1:
            case 2:
                return Math.max(0, max - this.TAG_BYTES);
            case 3:
            case 4:
                return Math.max(0, (max + this.m_bufPos) - this.TAG_BYTES);
            case 5:
            case 6:
                return max + this.m_bufPos + this.TAG_BYTES;
            default:
                return max + this.TAG_BYTES;
        }
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int i) {
        int i2;
        int max = Math.max(0, i) - 1;
        switch (C11921.$SwitchMap$org$bouncycastle$crypto$engines$SparkleEngine$State[this.m_state.ordinal()]) {
            case 1:
            case 2:
                i2 = max - this.TAG_BYTES;
                max = Math.max(0, i2);
                return max - (max % this.RATE_BYTES);
            case 3:
            case 4:
                max += this.m_bufPos;
                i2 = max - this.TAG_BYTES;
                max = Math.max(0, i2);
                return max - (max % this.RATE_BYTES);
            case 5:
            case 6:
                i2 = max + this.m_bufPos;
                max = Math.max(0, i2);
                return max - (max % this.RATE_BYTES);
            default:
                return max - (max % this.RATE_BYTES);
        }
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        KeyParameter keyParameter;
        byte[] iv;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            keyParameter = aEADParameters.getKey();
            iv = aEADParameters.getNonce();
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            int macSize = aEADParameters.getMacSize();
            if (macSize != this.TAG_BYTES * 8) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSize);
            }
        } else if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("invalid parameters passed to Sparkle");
        } else {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            CipherParameters parameters = parametersWithIV.getParameters();
            keyParameter = parameters instanceof KeyParameter ? (KeyParameter) parameters : null;
            iv = parametersWithIV.getIV();
            this.initialAssociatedText = null;
        }
        if (keyParameter == null) {
            throw new IllegalArgumentException("Sparkle init parameters must include a key");
        }
        int i = this.KEY_WORDS * 4;
        if (i != keyParameter.getKeyLength()) {
            throw new IllegalArgumentException(this.algorithmName + " requires exactly " + i + " bytes of key");
        }
        int i2 = this.RATE_WORDS * 4;
        if (iv == null || i2 != iv.length) {
            throw new IllegalArgumentException(this.algorithmName + " requires exactly " + i2 + " bytes of IV");
        }
        Pack.littleEndianToInt(keyParameter.getKey(), 0, this.f689k);
        Pack.littleEndianToInt(iv, 0, this.npub);
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
        this.m_state = z ? State.EncInit : State.DecInit;
        reset();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        checkAAD();
        if (this.m_bufPos == this.RATE_BYTES) {
            processBufferAAD(this.m_buf, 0);
            this.m_bufPos = 0;
        }
        byte[] bArr = this.m_buf;
        int i = this.m_bufPos;
        this.m_bufPos = i + 1;
        bArr[i] = b;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (i > bArr.length - i2) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 <= 0) {
            return;
        }
        checkAAD();
        int i3 = this.m_bufPos;
        if (i3 > 0) {
            int i4 = this.RATE_BYTES - i3;
            if (i2 <= i4) {
                System.arraycopy(bArr, i, this.m_buf, i3, i2);
                this.m_bufPos += i2;
                return;
            }
            System.arraycopy(bArr, i, this.m_buf, i3, i4);
            i += i4;
            i2 -= i4;
            processBufferAAD(this.m_buf, 0);
        }
        while (i2 > this.RATE_BYTES) {
            processBufferAAD(bArr, i);
            int i5 = this.RATE_BYTES;
            i += i5;
            i2 -= i5;
        }
        System.arraycopy(bArr, i, this.m_buf, 0, i2);
        this.m_bufPos = i2;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        return processBytes(new byte[]{b}, 0, 1, bArr, i);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        int i4;
        int i5;
        if (i <= bArr.length - i2) {
            if (checkData()) {
                int i6 = this.m_bufPos;
                if (i6 > 0) {
                    int i7 = this.RATE_BYTES - i6;
                    if (i2 <= i7) {
                        System.arraycopy(bArr, i, this.m_buf, i6, i2);
                        this.m_bufPos += i2;
                        return 0;
                    }
                    System.arraycopy(bArr, i, this.m_buf, i6, i7);
                    i += i7;
                    i2 -= i7;
                    processBufferEncrypt(this.m_buf, 0, bArr2, i3);
                    i5 = this.RATE_BYTES;
                } else {
                    i5 = 0;
                }
                while (i2 > this.RATE_BYTES) {
                    processBufferEncrypt(bArr, i, bArr2, i3 + i5);
                    int i8 = this.RATE_BYTES;
                    i += i8;
                    i2 -= i8;
                    i5 += i8;
                }
                System.arraycopy(bArr, i, this.m_buf, 0, i2);
                this.m_bufPos = i2;
                return i5;
            }
            int i9 = this.m_bufferSizeDecrypt;
            int i10 = this.m_bufPos;
            int i11 = i9 - i10;
            if (i2 <= i11) {
                System.arraycopy(bArr, i, this.m_buf, i10, i2);
                this.m_bufPos += i2;
                return 0;
            }
            if (i10 > this.RATE_BYTES) {
                processBufferDecrypt(this.m_buf, 0, bArr2, i3);
                int i12 = this.m_bufPos;
                int i13 = this.RATE_BYTES;
                int i14 = i12 - i13;
                this.m_bufPos = i14;
                byte[] bArr3 = this.m_buf;
                System.arraycopy(bArr3, i13, bArr3, 0, i14);
                i4 = this.RATE_BYTES;
                if (i2 <= i11 + i4) {
                    System.arraycopy(bArr, i, this.m_buf, this.m_bufPos, i2);
                    this.m_bufPos += i2;
                    return i4;
                }
            } else {
                i4 = 0;
            }
            int i15 = this.RATE_BYTES;
            int i16 = this.m_bufPos;
            int i17 = i15 - i16;
            System.arraycopy(bArr, i, this.m_buf, i16, i17);
            i += i17;
            i2 -= i17;
            processBufferDecrypt(this.m_buf, 0, bArr2, i3 + i4);
            i5 = i4 + this.RATE_BYTES;
            while (i2 > this.m_bufferSizeDecrypt) {
                processBufferDecrypt(bArr, i, bArr2, i3 + i5);
                int i18 = this.RATE_BYTES;
                i += i18;
                i2 -= i18;
                i5 += i18;
            }
            System.arraycopy(bArr, i, this.m_buf, 0, i2);
            this.m_bufPos = i2;
            return i5;
        }
        throw new DataLengthException("input buffer too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        reset(true);
    }
}