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
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class ISAPEngine implements AEADCipher {
    private ISAP_AEAD ISAPAEAD;
    private int ISAP_rH;
    private int ISAP_rH_SZ;

    /* renamed from: ad */
    private byte[] f640ad;
    private String algorithmName;

    /* renamed from: c */
    private byte[] f641c;
    private boolean forEncryption;
    private boolean initialised;

    /* renamed from: k */
    private byte[] f642k;
    private byte[] mac;
    private byte[] npub;
    final int CRYPTO_KEYBYTES = 16;
    final int CRYPTO_NPUBBYTES = 16;
    final int ISAP_STATE_SZ = 40;
    private ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    /* renamed from: org.bouncycastle.crypto.engines.ISAPEngine$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C11891 {
        static final /* synthetic */ int[] $SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType;

        static {
            int[] iArr = new int[IsapType.values().length];
            $SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType = iArr;
            try {
                iArr[IsapType.ISAP_A_128A.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType[IsapType.ISAP_K_128A.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType[IsapType.ISAP_A_128.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType[IsapType.ISAP_K_128.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    /* loaded from: classes2.dex */
    public abstract class ISAPAEAD_A implements ISAP_AEAD {
        protected long ISAP_IV1_64;
        protected long ISAP_IV2_64;
        protected long ISAP_IV3_64;
        protected long[] k64;
        protected long[] npub64;

        /* renamed from: t0 */
        protected long f643t0;

        /* renamed from: t1 */
        protected long f644t1;

        /* renamed from: t2 */
        protected long f645t2;

        /* renamed from: t3 */
        protected long f646t3;

        /* renamed from: t4 */
        protected long f647t4;

        /* renamed from: x0 */
        protected long f648x0;

        /* renamed from: x1 */
        protected long f649x1;

        /* renamed from: x2 */
        protected long f650x2;

        /* renamed from: x3 */
        protected long f651x3;

        /* renamed from: x4 */
        protected long f652x4;

        public ISAPAEAD_A() {
            ISAPEngine.this.ISAP_rH = 64;
            ISAPEngine.this.ISAP_rH_SZ = (ISAPEngine.this.ISAP_rH + 7) >> 3;
        }

        private long ROTR(long j, long j2) {
            return (j << ((int) (64 - j2))) | (j >>> ((int) j2));
        }

        private int getLongSize(int i) {
            return (i >>> 3) + ((i & 7) != 0 ? 1 : 0);
        }

        protected void ABSORB_MAC(byte[] bArr, int i) {
            int length = bArr.length >> 3;
            long[] jArr = new long[length];
            Pack.littleEndianToLong(bArr, 0, jArr, 0, length);
            int i2 = 0;
            while (i >= ISAPEngine.this.ISAP_rH_SZ) {
                this.f648x0 ^= U64BIG(jArr[i2]);
                P12();
                i -= ISAPEngine.this.ISAP_rH_SZ;
                i2++;
            }
            for (int i3 = 0; i3 < i; i3++) {
                this.f648x0 ^= (bArr[(i2 << 3) + i3] & 255) << ((7 - i3) << 3);
            }
            this.f648x0 = (128 << ((7 - i) << 3)) ^ this.f648x0;
            P12();
        }

        public void P12() {
            ROUND(240L);
            ROUND(225L);
            ROUND(210L);
            ROUND(195L);
            ROUND(180L);
            ROUND(165L);
            m64P6();
        }

        /* renamed from: P6 */
        protected void m64P6() {
            ROUND(150L);
            ROUND(135L);
            ROUND(120L);
            ROUND(105L);
            ROUND(90L);
            ROUND(75L);
        }

        protected abstract void PX1();

        protected abstract void PX2();

        protected void ROUND(long j) {
            long j2 = this.f648x0;
            long j3 = this.f649x1;
            long j4 = this.f650x2;
            long j5 = this.f651x3;
            long j6 = this.f652x4;
            long j7 = ((((j2 ^ j3) ^ j4) ^ j5) ^ j) ^ ((((j2 ^ j4) ^ j6) ^ j) & j3);
            this.f643t0 = j7;
            this.f644t1 = ((((j2 ^ j4) ^ j5) ^ j6) ^ j) ^ (((j3 ^ j4) ^ j) & (j3 ^ j5));
            this.f645t2 = (((j3 ^ j4) ^ j6) ^ j) ^ (j5 & j6);
            this.f646t3 = ((j4 ^ (j2 ^ j3)) ^ j) ^ ((~j2) & (j5 ^ j6));
            this.f647t4 = ((j2 ^ j6) & j3) ^ ((j3 ^ j5) ^ j6);
            this.f648x0 = (ROTR(j7, 19L) ^ j7) ^ ROTR(this.f643t0, 28L);
            long j8 = this.f644t1;
            this.f649x1 = (j8 ^ ROTR(j8, 39L)) ^ ROTR(this.f644t1, 61L);
            long j9 = this.f645t2;
            this.f650x2 = ~((j9 ^ ROTR(j9, 1L)) ^ ROTR(this.f645t2, 6L));
            long j10 = this.f646t3;
            this.f651x3 = (j10 ^ ROTR(j10, 10L)) ^ ROTR(this.f646t3, 17L);
            long j11 = this.f647t4;
            this.f652x4 = (j11 ^ ROTR(j11, 7L)) ^ ROTR(this.f647t4, 41L);
        }

        protected long U64BIG(long j) {
            return (ROTR(j, 56L) & 1095216660735L) | (ROTR(j, 8L) & (-72057589759737856L)) | (ROTR(j, 24L) & 71776119077928960L) | (ROTR(j, 40L) & 280375465148160L);
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void init() {
            this.npub64 = new long[getLongSize(ISAPEngine.this.npub.length)];
            byte[] bArr = ISAPEngine.this.npub;
            long[] jArr = this.npub64;
            Pack.littleEndianToLong(bArr, 0, jArr, 0, jArr.length);
            long[] jArr2 = this.npub64;
            jArr2[0] = U64BIG(jArr2[0]);
            long[] jArr3 = this.npub64;
            jArr3[1] = U64BIG(jArr3[1]);
            this.k64 = new long[getLongSize(ISAPEngine.this.f642k.length)];
            byte[] bArr2 = ISAPEngine.this.f642k;
            long[] jArr4 = this.k64;
            Pack.littleEndianToLong(bArr2, 0, jArr4, 0, jArr4.length);
            long[] jArr5 = this.k64;
            jArr5[0] = U64BIG(jArr5[0]);
            long[] jArr6 = this.k64;
            jArr6[1] = U64BIG(jArr6[1]);
            reset();
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void isap_enc(byte[] bArr, int i, int i2, byte[] bArr2, int i3, int i4) {
            int i5;
            int i6 = i2 >> 3;
            long[] jArr = new long[i6];
            Pack.littleEndianToLong(bArr, i, jArr, 0, i6);
            long[] jArr2 = new long[i6];
            int i7 = 0;
            while (i2 >= ISAPEngine.this.ISAP_rH_SZ) {
                jArr2[i7] = U64BIG(this.f648x0) ^ jArr[i7];
                PX1();
                i7++;
                i2 -= ISAPEngine.this.ISAP_rH_SZ;
            }
            Pack.longToLittleEndian(jArr2, 0, i6, bArr2, i3);
            byte[] longToLittleEndian = Pack.longToLittleEndian(this.f648x0);
            while (i2 > 0) {
                byte b = longToLittleEndian[ISAPEngine.this.ISAP_rH_SZ - i2];
                i2--;
                bArr2[((i5 + i3) + i2) - 1] = (byte) (bArr[((i7 << 3) + i) + i2] ^ b);
            }
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void isap_mac(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
            long[] jArr = this.npub64;
            this.f648x0 = jArr[0];
            this.f649x1 = jArr[1];
            this.f650x2 = this.ISAP_IV1_64;
            this.f652x4 = 0L;
            this.f651x3 = 0L;
            P12();
            ABSORB_MAC(bArr, i);
            this.f652x4 ^= 1;
            ABSORB_MAC(bArr2, i2);
            Pack.longToLittleEndian(U64BIG(this.f648x0), bArr3, 0);
            Pack.longToLittleEndian(U64BIG(this.f649x1), bArr3, 8);
            long j = this.f650x2;
            long j2 = this.f651x3;
            long j3 = this.f652x4;
            isap_rk(this.ISAP_IV2_64, bArr3, 16);
            this.f650x2 = j;
            this.f651x3 = j2;
            this.f652x4 = j3;
            P12();
            Pack.longToLittleEndian(U64BIG(this.f648x0), bArr3, i3);
            Pack.longToLittleEndian(U64BIG(this.f649x1), bArr3, i3 + 8);
        }

        public void isap_rk(long j, byte[] bArr, int i) {
            long[] jArr = this.k64;
            this.f648x0 = jArr[0];
            this.f649x1 = jArr[1];
            this.f650x2 = j;
            this.f652x4 = 0L;
            this.f651x3 = 0L;
            P12();
            for (int i2 = 0; i2 < (i << 3) - 1; i2++) {
                this.f648x0 ^= ((((bArr[i2 >>> 3] >>> (7 - (i2 & 7))) & 1) << 7) & 255) << 56;
                PX2();
            }
            this.f648x0 ^= (bArr[i - 1] & 1) << 63;
            P12();
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void reset() {
            isap_rk(this.ISAP_IV3_64, ISAPEngine.this.npub, 16);
            long[] jArr = this.npub64;
            this.f651x3 = jArr[0];
            this.f652x4 = jArr[1];
            PX1();
        }
    }

    /* loaded from: classes2.dex */
    private class ISAPAEAD_A_128 extends ISAPAEAD_A {
        public ISAPAEAD_A_128() {
            super();
            this.ISAP_IV1_64 = 108156764298152972L;
            this.ISAP_IV2_64 = 180214358336080908L;
            this.ISAP_IV3_64 = 252271952374008844L;
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_A
        protected void PX1() {
            P12();
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_A
        protected void PX2() {
            P12();
        }
    }

    /* loaded from: classes2.dex */
    private class ISAPAEAD_A_128A extends ISAPAEAD_A {
        public ISAPAEAD_A_128A() {
            super();
            this.ISAP_IV1_64 = 108156764297430540L;
            this.ISAP_IV2_64 = 180214358335358476L;
            this.ISAP_IV3_64 = 252271952373286412L;
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_A
        protected void PX1() {
            m64P6();
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_A
        protected void PX2() {
            ROUND(75L);
        }
    }

    /* loaded from: classes2.dex */
    private abstract class ISAPAEAD_K implements ISAP_AEAD {
        protected short[] ISAP_IV1_16;
        protected short[] ISAP_IV2_16;
        protected short[] ISAP_IV3_16;
        protected short[] iv16;
        protected short[] k16;
        final int ISAP_STATE_SZ_CRYPTO_NPUBBYTES = 24;
        private final int[] KeccakF400RoundConstants = {1, 32898, 32906, 32768, 32907, 1, 32897, 32777, CipherSuite.TLS_PSK_WITH_RC4_128_SHA, CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, 32777, 10, 32907, CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, 32905, 32771, 32770, 128, 32778, 10};

        /* renamed from: SX */
        protected short[] f655SX = new short[25];

        /* renamed from: E */
        protected short[] f654E = new short[25];

        /* renamed from: C */
        protected short[] f653C = new short[5];

        public ISAPAEAD_K() {
            ISAPEngine.this.ISAP_rH = CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA;
            ISAPEngine.this.ISAP_rH_SZ = (ISAPEngine.this.ISAP_rH + 7) >> 3;
        }

        private short ROL16(short s, int i) {
            int i2 = s & 65535;
            return (short) ((i2 >>> (16 - i)) ^ (i2 << i));
        }

        private void byteToShort(byte[] bArr, short[] sArr, int i) {
            for (int i2 = 0; i2 < i; i2++) {
                sArr[i2] = Pack.littleEndianToShort(bArr, i2 << 1);
            }
        }

        private void byteToShortXor(byte[] bArr, short[] sArr, int i) {
            for (int i2 = 0; i2 < i; i2++) {
                sArr[i2] = (short) (sArr[i2] ^ Pack.littleEndianToShort(bArr, i2 << 1));
            }
        }

        private void shortToByte(short[] sArr, byte[] bArr, int i) {
            for (int i2 = 0; i2 < 8; i2++) {
                Pack.shortToLittleEndian(sArr[i2], bArr, (i2 << 1) + i);
            }
        }

        protected void ABSORB_MAC(short[] sArr, byte[] bArr, int i, short[] sArr2, short[] sArr3) {
            int i2 = 0;
            int i3 = 0;
            while (i > ISAPEngine.this.ISAP_rH_SZ) {
                byteToShortXor(bArr, sArr, ISAPEngine.this.ISAP_rH_SZ >> 1);
                i3 += ISAPEngine.this.ISAP_rH_SZ;
                i -= ISAPEngine.this.ISAP_rH_SZ;
                PermuteRoundsHX(sArr, sArr2, sArr3);
            }
            if (i == ISAPEngine.this.ISAP_rH_SZ) {
                byteToShortXor(bArr, sArr, ISAPEngine.this.ISAP_rH_SZ >> 1);
                PermuteRoundsHX(sArr, sArr2, sArr3);
                sArr[0] = (short) (sArr[0] ^ 128);
            } else {
                while (i2 < i) {
                    int i4 = i2 >> 1;
                    sArr[i4] = (short) (((bArr[i3] & 255) << ((i2 & 1) << 3)) ^ sArr[i4]);
                    i2++;
                    i3++;
                }
                int i5 = i >> 1;
                sArr[i5] = (short) ((128 << ((i & 1) << 3)) ^ sArr[i5]);
            }
            PermuteRoundsHX(sArr, sArr2, sArr3);
        }

        protected abstract void PermuteRoundsBX(short[] sArr, short[] sArr2, short[] sArr3);

        protected abstract void PermuteRoundsHX(short[] sArr, short[] sArr2, short[] sArr3);

        protected abstract void PermuteRoundsKX(short[] sArr, short[] sArr2, short[] sArr3);

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void init() {
            this.k16 = new short[ISAPEngine.this.f642k.length >> 1];
            byte[] bArr = ISAPEngine.this.f642k;
            short[] sArr = this.k16;
            byteToShort(bArr, sArr, sArr.length);
            this.iv16 = new short[ISAPEngine.this.npub.length >> 1];
            byte[] bArr2 = ISAPEngine.this.npub;
            short[] sArr2 = this.iv16;
            byteToShort(bArr2, sArr2, sArr2.length);
            reset();
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void isap_enc(byte[] bArr, int i, int i2, byte[] bArr2, int i3, int i4) {
            int i5;
            while (true) {
                i5 = 0;
                if (i2 < ISAPEngine.this.ISAP_rH_SZ) {
                    break;
                }
                while (i5 < ISAPEngine.this.ISAP_rH_SZ) {
                    bArr2[i3] = (byte) (bArr[i] ^ (this.f655SX[i5 >> 1] >>> ((i5 & 1) << 3)));
                    i5++;
                    i3++;
                    i++;
                }
                i2 -= ISAPEngine.this.ISAP_rH_SZ;
                PermuteRoundsKX(this.f655SX, this.f654E, this.f653C);
            }
            while (i5 < i2) {
                bArr2[i3] = (byte) (bArr[i] ^ (this.f655SX[i5 >> 1] >>> ((i5 & 1) << 3)));
                i5++;
                i3++;
                i++;
            }
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void isap_mac(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
            short[] sArr = new short[25];
            this.f655SX = sArr;
            System.arraycopy(this.iv16, 0, sArr, 0, 8);
            System.arraycopy(this.ISAP_IV1_16, 0, this.f655SX, 8, 4);
            PermuteRoundsHX(this.f655SX, this.f654E, this.f653C);
            ABSORB_MAC(this.f655SX, bArr, i, this.f654E, this.f653C);
            short[] sArr2 = this.f655SX;
            sArr2[24] = (short) (sArr2[24] ^ 256);
            ABSORB_MAC(sArr2, bArr2, i2, this.f654E, this.f653C);
            shortToByte(this.f655SX, bArr3, i3);
            isap_rk(this.ISAP_IV2_16, bArr3, 16, this.f655SX, 16, this.f653C);
            PermuteRoundsHX(this.f655SX, this.f654E, this.f653C);
            shortToByte(this.f655SX, bArr3, i3);
        }

        public void isap_rk(short[] sArr, byte[] bArr, int i, short[] sArr2, int i2, short[] sArr3) {
            short[] sArr4 = new short[25];
            short[] sArr5 = new short[25];
            System.arraycopy(this.k16, 0, sArr4, 0, 8);
            System.arraycopy(sArr, 0, sArr4, 8, 4);
            PermuteRoundsKX(sArr4, sArr5, sArr3);
            for (int i3 = 0; i3 < (i << 3) - 1; i3++) {
                sArr4[0] = (short) (sArr4[0] ^ (((bArr[i3 >> 3] >>> (7 - (i3 & 7))) & 1) << 7));
                PermuteRoundsBX(sArr4, sArr5, sArr3);
            }
            sArr4[0] = (short) (sArr4[0] ^ ((bArr[i - 1] & 1) << 7));
            PermuteRoundsKX(sArr4, sArr5, sArr3);
            System.arraycopy(sArr4, 0, sArr2, 0, i2 == 24 ? 17 : 8);
        }

        protected void prepareThetaX(short[] sArr, short[] sArr2) {
            sArr2[0] = (short) ((((sArr[0] ^ sArr[5]) ^ sArr[10]) ^ sArr[15]) ^ sArr[20]);
            sArr2[1] = (short) ((((sArr[1] ^ sArr[6]) ^ sArr[11]) ^ sArr[16]) ^ sArr[21]);
            sArr2[2] = (short) ((((sArr[2] ^ sArr[7]) ^ sArr[12]) ^ sArr[17]) ^ sArr[22]);
            sArr2[3] = (short) ((((sArr[3] ^ sArr[8]) ^ sArr[13]) ^ sArr[18]) ^ sArr[23]);
            sArr2[4] = (short) (sArr[24] ^ (((sArr[4] ^ sArr[9]) ^ sArr[14]) ^ sArr[19]));
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAP_AEAD
        public void reset() {
            this.f655SX = new short[25];
            this.f654E = new short[25];
            this.f653C = new short[5];
            isap_rk(this.ISAP_IV3_16, ISAPEngine.this.npub, 16, this.f655SX, 24, this.f653C);
            System.arraycopy(this.iv16, 0, this.f655SX, 17, 8);
            PermuteRoundsKX(this.f655SX, this.f654E, this.f653C);
        }

        protected void rounds12X(short[] sArr, short[] sArr2, short[] sArr3) {
            prepareThetaX(sArr, sArr3);
            rounds_8_18(sArr, sArr2, sArr3);
        }

        protected void rounds_12_18(short[] sArr, short[] sArr2, short[] sArr3) {
            thetaRhoPiChiIotaPrepareTheta(12, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(13, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(14, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(15, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(16, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(17, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(18, sArr, sArr2, sArr3);
            thetaRhoPiChiIota(sArr2, sArr, sArr3);
        }

        protected void rounds_4_18(short[] sArr, short[] sArr2, short[] sArr3) {
            thetaRhoPiChiIotaPrepareTheta(4, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(5, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(6, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(7, sArr2, sArr, sArr3);
            rounds_8_18(sArr, sArr2, sArr3);
        }

        protected void rounds_8_18(short[] sArr, short[] sArr2, short[] sArr3) {
            thetaRhoPiChiIotaPrepareTheta(8, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(9, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(10, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(11, sArr2, sArr, sArr3);
            rounds_12_18(sArr, sArr2, sArr3);
        }

        protected void thetaRhoPiChiIota(short[] sArr, short[] sArr2, short[] sArr3) {
            short ROL16 = (short) (sArr3[4] ^ ROL16(sArr3[1], 1));
            short ROL162 = (short) (sArr3[0] ^ ROL16(sArr3[2], 1));
            short ROL163 = (short) (sArr3[1] ^ ROL16(sArr3[3], 1));
            short ROL164 = (short) (sArr3[2] ^ ROL16(sArr3[4], 1));
            short ROL165 = (short) (sArr3[3] ^ ROL16(sArr3[0], 1));
            short s = (short) (sArr[0] ^ ROL16);
            sArr[0] = s;
            short s2 = (short) (sArr[6] ^ ROL162);
            sArr[6] = s2;
            short ROL166 = ROL16(s2, 12);
            short s3 = (short) (sArr[12] ^ ROL163);
            sArr[12] = s3;
            short ROL167 = ROL16(s3, 11);
            short s4 = (short) (sArr[18] ^ ROL164);
            sArr[18] = s4;
            short ROL168 = ROL16(s4, 5);
            short s5 = (short) (sArr[24] ^ ROL165);
            sArr[24] = s5;
            short ROL169 = ROL16(s5, 14);
            sArr2[0] = (short) ((((~ROL166) & ROL167) ^ s) ^ this.KeccakF400RoundConstants[19]);
            sArr2[1] = (short) (((~ROL167) & ROL168) ^ ROL166);
            sArr2[2] = (short) (((~ROL168) & ROL169) ^ ROL167);
            sArr2[3] = (short) (((~ROL169) & s) ^ ROL168);
            sArr2[4] = (short) (((~s) & ROL166) ^ ROL169);
            short s6 = (short) (sArr[3] ^ ROL164);
            sArr[3] = s6;
            short ROL1610 = ROL16(s6, 12);
            short s7 = (short) (sArr[9] ^ ROL165);
            sArr[9] = s7;
            short ROL1611 = ROL16(s7, 4);
            short s8 = (short) (sArr[10] ^ ROL16);
            sArr[10] = s8;
            short ROL1612 = ROL16(s8, 3);
            short s9 = (short) (sArr[16] ^ ROL162);
            sArr[16] = s9;
            short ROL1613 = ROL16(s9, 13);
            short s10 = (short) (sArr[22] ^ ROL163);
            sArr[22] = s10;
            short ROL1614 = ROL16(s10, 13);
            sArr2[5] = (short) (((~ROL1611) & ROL1612) ^ ROL1610);
            sArr2[6] = (short) (((~ROL1612) & ROL1613) ^ ROL1611);
            sArr2[7] = (short) (((~ROL1613) & ROL1614) ^ ROL1612);
            sArr2[8] = (short) (((~ROL1614) & ROL1610) ^ ROL1613);
            sArr2[9] = (short) (((~ROL1610) & ROL1611) ^ ROL1614);
            short s11 = (short) (sArr[1] ^ ROL162);
            sArr[1] = s11;
            short ROL1615 = ROL16(s11, 1);
            short s12 = (short) (sArr[7] ^ ROL163);
            sArr[7] = s12;
            short ROL1616 = ROL16(s12, 6);
            short s13 = (short) (sArr[13] ^ ROL164);
            sArr[13] = s13;
            short ROL1617 = ROL16(s13, 9);
            short s14 = (short) (sArr[19] ^ ROL165);
            sArr[19] = s14;
            short ROL1618 = ROL16(s14, 8);
            short s15 = (short) (sArr[20] ^ ROL16);
            sArr[20] = s15;
            short ROL1619 = ROL16(s15, 2);
            sArr2[10] = (short) (((~ROL1616) & ROL1617) ^ ROL1615);
            sArr2[11] = (short) (((~ROL1617) & ROL1618) ^ ROL1616);
            sArr2[12] = (short) (ROL1617 ^ ((~ROL1618) & ROL1619));
            sArr2[13] = (short) (((~ROL1619) & ROL1615) ^ ROL1618);
            sArr2[14] = (short) (((~ROL1615) & ROL1616) ^ ROL1619);
            short s16 = (short) (sArr[4] ^ ROL165);
            sArr[4] = s16;
            short ROL1620 = ROL16(s16, 11);
            short s17 = (short) (sArr[5] ^ ROL16);
            sArr[5] = s17;
            short ROL1621 = ROL16(s17, 4);
            short s18 = (short) (sArr[11] ^ ROL162);
            sArr[11] = s18;
            short ROL1622 = ROL16(s18, 10);
            short s19 = (short) (sArr[17] ^ ROL163);
            sArr[17] = s19;
            short ROL1623 = ROL16(s19, 15);
            short s20 = (short) (sArr[23] ^ ROL164);
            sArr[23] = s20;
            short ROL1624 = ROL16(s20, 8);
            sArr2[15] = (short) (((~ROL1621) & ROL1622) ^ ROL1620);
            sArr2[16] = (short) (((~ROL1622) & ROL1623) ^ ROL1621);
            sArr2[17] = (short) (ROL1622 ^ ((~ROL1623) & ROL1624));
            sArr2[18] = (short) (((~ROL1624) & ROL1620) ^ ROL1623);
            sArr2[19] = (short) ((ROL1621 & (~ROL1620)) ^ ROL1624);
            short s21 = (short) (sArr[2] ^ ROL163);
            sArr[2] = s21;
            short ROL1625 = ROL16(s21, 14);
            short s22 = (short) (sArr[8] ^ ROL164);
            sArr[8] = s22;
            short ROL1626 = ROL16(s22, 7);
            short s23 = (short) (sArr[14] ^ ROL165);
            sArr[14] = s23;
            short ROL1627 = ROL16(s23, 7);
            short s24 = (short) (ROL16 ^ sArr[15]);
            sArr[15] = s24;
            short ROL1628 = ROL16(s24, 9);
            short s25 = (short) (ROL162 ^ sArr[21]);
            sArr[21] = s25;
            short ROL1629 = ROL16(s25, 2);
            sArr2[20] = (short) (((~ROL1626) & ROL1627) ^ ROL1625);
            sArr2[21] = (short) (((~ROL1627) & ROL1628) ^ ROL1626);
            sArr2[22] = (short) (ROL1627 ^ ((~ROL1628) & ROL1629));
            sArr2[23] = (short) (ROL1628 ^ ((~ROL1629) & ROL1625));
            sArr2[24] = (short) (((~ROL1625) & ROL1626) ^ ROL1629);
        }

        protected void thetaRhoPiChiIotaPrepareTheta(int i, short[] sArr, short[] sArr2, short[] sArr3) {
            short ROL16 = (short) (sArr3[4] ^ ROL16(sArr3[1], 1));
            short ROL162 = (short) (sArr3[0] ^ ROL16(sArr3[2], 1));
            short ROL163 = (short) (sArr3[1] ^ ROL16(sArr3[3], 1));
            short ROL164 = (short) (sArr3[2] ^ ROL16(sArr3[4], 1));
            short ROL165 = (short) (sArr3[3] ^ ROL16(sArr3[0], 1));
            short s = (short) (sArr[0] ^ ROL16);
            sArr[0] = s;
            short s2 = (short) (sArr[6] ^ ROL162);
            sArr[6] = s2;
            short ROL166 = ROL16(s2, 12);
            short s3 = (short) (sArr[12] ^ ROL163);
            sArr[12] = s3;
            short ROL167 = ROL16(s3, 11);
            short s4 = (short) (sArr[18] ^ ROL164);
            sArr[18] = s4;
            short ROL168 = ROL16(s4, 5);
            short s5 = (short) (sArr[24] ^ ROL165);
            sArr[24] = s5;
            short ROL169 = ROL16(s5, 14);
            short s6 = (short) ((((~ROL166) & ROL167) ^ s) ^ this.KeccakF400RoundConstants[i]);
            sArr2[0] = s6;
            sArr3[0] = s6;
            short s7 = (short) (((~ROL167) & ROL168) ^ ROL166);
            sArr2[1] = s7;
            sArr3[1] = s7;
            short s8 = (short) (((~ROL168) & ROL169) ^ ROL167);
            sArr2[2] = s8;
            sArr3[2] = s8;
            short s9 = (short) (((~ROL169) & s) ^ ROL168);
            sArr2[3] = s9;
            sArr3[3] = s9;
            short s10 = (short) (((~s) & ROL166) ^ ROL169);
            sArr2[4] = s10;
            sArr3[4] = s10;
            short s11 = (short) (sArr[3] ^ ROL164);
            sArr[3] = s11;
            short ROL1610 = ROL16(s11, 12);
            short s12 = (short) (sArr[9] ^ ROL165);
            sArr[9] = s12;
            short ROL1611 = ROL16(s12, 4);
            short s13 = (short) (sArr[10] ^ ROL16);
            sArr[10] = s13;
            short ROL1612 = ROL16(s13, 3);
            short s14 = (short) (sArr[16] ^ ROL162);
            sArr[16] = s14;
            short ROL1613 = ROL16(s14, 13);
            short s15 = (short) (sArr[22] ^ ROL163);
            sArr[22] = s15;
            short ROL1614 = ROL16(s15, 13);
            short s16 = (short) (((~ROL1611) & ROL1612) ^ ROL1610);
            sArr2[5] = s16;
            sArr3[0] = (short) (sArr3[0] ^ s16);
            short s17 = (short) (((~ROL1612) & ROL1613) ^ ROL1611);
            sArr2[6] = s17;
            sArr3[1] = (short) (sArr3[1] ^ s17);
            short s18 = (short) (ROL1612 ^ ((~ROL1613) & ROL1614));
            sArr2[7] = s18;
            sArr3[2] = (short) (sArr3[2] ^ s18);
            short s19 = (short) (((~ROL1614) & ROL1610) ^ ROL1613);
            sArr2[8] = s19;
            sArr3[3] = (short) (sArr3[3] ^ s19);
            short s20 = (short) (((~ROL1610) & ROL1611) ^ ROL1614);
            sArr2[9] = s20;
            sArr3[4] = (short) (s20 ^ sArr3[4]);
            short s21 = (short) (sArr[1] ^ ROL162);
            sArr[1] = s21;
            short ROL1615 = ROL16(s21, 1);
            short s22 = (short) (sArr[7] ^ ROL163);
            sArr[7] = s22;
            short ROL1616 = ROL16(s22, 6);
            short s23 = (short) (sArr[13] ^ ROL164);
            sArr[13] = s23;
            short ROL1617 = ROL16(s23, 9);
            short s24 = (short) (sArr[19] ^ ROL165);
            sArr[19] = s24;
            short ROL1618 = ROL16(s24, 8);
            short s25 = (short) (sArr[20] ^ ROL16);
            sArr[20] = s25;
            short ROL1619 = ROL16(s25, 2);
            short s26 = (short) (((~ROL1616) & ROL1617) ^ ROL1615);
            sArr2[10] = s26;
            sArr3[0] = (short) (sArr3[0] ^ s26);
            short s27 = (short) (((~ROL1617) & ROL1618) ^ ROL1616);
            sArr2[11] = s27;
            sArr3[1] = (short) (sArr3[1] ^ s27);
            short s28 = (short) (ROL1617 ^ ((~ROL1618) & ROL1619));
            sArr2[12] = s28;
            sArr3[2] = (short) (s28 ^ sArr3[2]);
            short s29 = (short) (ROL1618 ^ ((~ROL1619) & ROL1615));
            sArr2[13] = s29;
            sArr3[3] = (short) (s29 ^ sArr3[3]);
            short s30 = (short) (((~ROL1615) & ROL1616) ^ ROL1619);
            sArr2[14] = s30;
            sArr3[4] = (short) (s30 ^ sArr3[4]);
            short s31 = (short) (sArr[4] ^ ROL165);
            sArr[4] = s31;
            short ROL1620 = ROL16(s31, 11);
            short s32 = (short) (sArr[5] ^ ROL16);
            sArr[5] = s32;
            short ROL1621 = ROL16(s32, 4);
            short s33 = (short) (sArr[11] ^ ROL162);
            sArr[11] = s33;
            short ROL1622 = ROL16(s33, 10);
            short s34 = (short) (sArr[17] ^ ROL163);
            sArr[17] = s34;
            short ROL1623 = ROL16(s34, 15);
            short s35 = (short) (sArr[23] ^ ROL164);
            sArr[23] = s35;
            short ROL1624 = ROL16(s35, 8);
            short s36 = (short) (((~ROL1621) & ROL1622) ^ ROL1620);
            sArr2[15] = s36;
            sArr3[0] = (short) (sArr3[0] ^ s36);
            short s37 = (short) (((~ROL1622) & ROL1623) ^ ROL1621);
            sArr2[16] = s37;
            sArr3[1] = (short) (sArr3[1] ^ s37);
            short s38 = (short) (ROL1622 ^ ((~ROL1623) & ROL1624));
            sArr2[17] = s38;
            sArr3[2] = (short) (sArr3[2] ^ s38);
            short s39 = (short) (((~ROL1624) & ROL1620) ^ ROL1623);
            sArr2[18] = s39;
            sArr3[3] = (short) (s39 ^ sArr3[3]);
            short s40 = (short) (((~ROL1620) & ROL1621) ^ ROL1624);
            sArr2[19] = s40;
            sArr3[4] = (short) (s40 ^ sArr3[4]);
            short s41 = (short) (sArr[2] ^ ROL163);
            sArr[2] = s41;
            short ROL1625 = ROL16(s41, 14);
            short s42 = (short) (sArr[8] ^ ROL164);
            sArr[8] = s42;
            short ROL1626 = ROL16(s42, 7);
            short s43 = (short) (sArr[14] ^ ROL165);
            sArr[14] = s43;
            short ROL1627 = ROL16(s43, 7);
            short s44 = (short) (ROL16 ^ sArr[15]);
            sArr[15] = s44;
            short ROL1628 = ROL16(s44, 9);
            short s45 = (short) (ROL162 ^ sArr[21]);
            sArr[21] = s45;
            short ROL1629 = ROL16(s45, 2);
            short s46 = (short) (((~ROL1626) & ROL1627) ^ ROL1625);
            sArr2[20] = s46;
            sArr3[0] = (short) (s46 ^ sArr3[0]);
            short s47 = (short) (((~ROL1627) & ROL1628) ^ ROL1626);
            sArr2[21] = s47;
            sArr3[1] = (short) (s47 ^ sArr3[1]);
            short s48 = (short) (ROL1627 ^ ((~ROL1628) & ROL1629));
            sArr2[22] = s48;
            sArr3[2] = (short) (s48 ^ sArr3[2]);
            short s49 = (short) (((~ROL1629) & ROL1625) ^ ROL1628);
            sArr2[23] = s49;
            sArr3[3] = (short) (s49 ^ sArr3[3]);
            short s50 = (short) (((~ROL1625) & ROL1626) ^ ROL1629);
            sArr2[24] = s50;
            sArr3[4] = (short) (s50 ^ sArr3[4]);
        }
    }

    /* loaded from: classes2.dex */
    private class ISAPAEAD_K_128 extends ISAPAEAD_K {
        public ISAPAEAD_K_128() {
            super();
            this.ISAP_IV1_16 = new short[]{-32767, 400, 3092, 3084};
            this.ISAP_IV2_16 = new short[]{-32766, 400, 3092, 3084};
            this.ISAP_IV3_16 = new short[]{-32765, 400, 3092, 3084};
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsBX(short[] sArr, short[] sArr2, short[] sArr3) {
            rounds12X(sArr, sArr2, sArr3);
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsHX(short[] sArr, short[] sArr2, short[] sArr3) {
            prepareThetaX(sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(0, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(1, sArr2, sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(2, sArr, sArr2, sArr3);
            thetaRhoPiChiIotaPrepareTheta(3, sArr2, sArr, sArr3);
            rounds_4_18(sArr, sArr2, sArr3);
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsKX(short[] sArr, short[] sArr2, short[] sArr3) {
            rounds12X(sArr, sArr2, sArr3);
        }
    }

    /* loaded from: classes2.dex */
    private class ISAPAEAD_K_128A extends ISAPAEAD_K {
        public ISAPAEAD_K_128A() {
            super();
            this.ISAP_IV1_16 = new short[]{-32767, 400, 272, 2056};
            this.ISAP_IV2_16 = new short[]{-32766, 400, 272, 2056};
            this.ISAP_IV3_16 = new short[]{-32765, 400, 272, 2056};
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsBX(short[] sArr, short[] sArr2, short[] sArr3) {
            prepareThetaX(sArr, sArr3);
            thetaRhoPiChiIotaPrepareTheta(19, sArr, sArr2, sArr3);
            System.arraycopy(sArr2, 0, sArr, 0, sArr2.length);
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsHX(short[] sArr, short[] sArr2, short[] sArr3) {
            prepareThetaX(sArr, sArr3);
            rounds_4_18(sArr, sArr2, sArr3);
        }

        @Override // org.bouncycastle.crypto.engines.ISAPEngine.ISAPAEAD_K
        protected void PermuteRoundsKX(short[] sArr, short[] sArr2, short[] sArr3) {
            prepareThetaX(sArr, sArr3);
            rounds_12_18(sArr, sArr2, sArr3);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes2.dex */
    public interface ISAP_AEAD {
        void init();

        void isap_enc(byte[] bArr, int i, int i2, byte[] bArr2, int i3, int i4);

        void isap_mac(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3);

        void reset();
    }

    /* loaded from: classes2.dex */
    public enum IsapType {
        ISAP_A_128A,
        ISAP_K_128A,
        ISAP_A_128,
        ISAP_K_128
    }

    public ISAPEngine(IsapType isapType) {
        String str;
        int i = C11891.$SwitchMap$org$bouncycastle$crypto$engines$ISAPEngine$IsapType[isapType.ordinal()];
        if (i == 1) {
            this.ISAPAEAD = new ISAPAEAD_A_128A();
            str = "ISAP-A-128A AEAD";
        } else if (i == 2) {
            this.ISAPAEAD = new ISAPAEAD_K_128A();
            str = "ISAP-K-128A AEAD";
        } else if (i == 3) {
            this.ISAPAEAD = new ISAPAEAD_A_128();
            str = "ISAP-A-128 AEAD";
        } else if (i != 4) {
            return;
        } else {
            this.ISAPAEAD = new ISAPAEAD_K_128();
            str = "ISAP-K-128 AEAD";
        }
        this.algorithmName = str;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        if (this.initialised) {
            if (this.forEncryption) {
                byte[] byteArray = this.message.toByteArray();
                int length = byteArray.length;
                int i2 = i + length;
                if (i2 + 16 <= bArr.length) {
                    this.ISAPAEAD.isap_enc(byteArray, 0, length, bArr, i, bArr.length);
                    this.outputStream.write(bArr, i, length);
                    this.f640ad = this.aadData.toByteArray();
                    byte[] byteArray2 = this.outputStream.toByteArray();
                    this.f641c = byteArray2;
                    byte[] bArr2 = new byte[16];
                    this.mac = bArr2;
                    ISAP_AEAD isap_aead = this.ISAPAEAD;
                    byte[] bArr3 = this.f640ad;
                    isap_aead.isap_mac(bArr3, bArr3.length, byteArray2, byteArray2.length, bArr2, 0);
                    System.arraycopy(this.mac, 0, bArr, i2, 16);
                    return length + 16;
                }
                throw new OutputLengthException("output buffer is too short");
            }
            this.f640ad = this.aadData.toByteArray();
            byte[] byteArray3 = this.message.toByteArray();
            this.f641c = byteArray3;
            byte[] bArr4 = new byte[16];
            this.mac = bArr4;
            int length2 = byteArray3.length - bArr4.length;
            if (length2 + i <= bArr.length) {
                ISAP_AEAD isap_aead2 = this.ISAPAEAD;
                byte[] bArr5 = this.f640ad;
                isap_aead2.isap_mac(bArr5, bArr5.length, byteArray3, length2, bArr4, 0);
                this.ISAPAEAD.reset();
                for (int i3 = 0; i3 < 16; i3++) {
                    if (this.mac[i3] != this.f641c[length2 + i3]) {
                        throw new IllegalArgumentException("Mac does not match");
                    }
                }
                this.ISAPAEAD.isap_enc(this.f641c, 0, length2, bArr, i, bArr.length);
                return length2;
            }
            throw new OutputLengthException("output buffer is too short");
        }
        throw new IllegalArgumentException("Need call init function before encryption/decryption");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public int getBlockSize() {
        return this.ISAP_rH_SZ;
    }

    public int getIVBytesSize() {
        return 16;
    }

    public int getKeyBytesSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        return this.mac;
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
            throw new IllegalArgumentException("ISAP AEAD init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("ISAP AEAD requires exactly 12 bytes of IV");
        }
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("ISAP AEAD init parameters must include a key");
        }
        byte[] key = ((KeyParameter) parametersWithIV.getParameters()).getKey();
        if (key.length != 16) {
            throw new IllegalArgumentException("ISAP AEAD key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
        byte[] bArr = new byte[iv.length];
        this.npub = bArr;
        this.f642k = new byte[key.length];
        System.arraycopy(iv, 0, bArr, 0, iv.length);
        System.arraycopy(key, 0, this.f642k, 0, key.length);
        this.ISAPAEAD.init();
        this.initialised = true;
        reset();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        this.aadData.write(b);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short".concat(this.forEncryption ? "encryption" : "decryption"));
        }
        this.aadData.write(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        return processBytes(new byte[]{b}, 0, 1, bArr, i);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        if (this.initialised) {
            if (i + i2 <= bArr.length) {
                this.message.write(bArr, i, i2);
                if (!this.forEncryption || this.message.size() < this.ISAP_rH_SZ) {
                    return 0;
                }
                int size = this.message.size();
                int i4 = this.ISAP_rH_SZ;
                int i5 = (size / i4) * i4;
                if (i3 + i5 <= bArr2.length) {
                    byte[] byteArray = this.message.toByteArray();
                    this.ISAPAEAD.isap_enc(byteArray, 0, i5, bArr2, i3, bArr2.length);
                    this.outputStream.write(bArr2, i3, i5);
                    this.message.reset();
                    this.message.write(byteArray, i5, byteArray.length - i5);
                    return i5;
                }
                throw new OutputLengthException("output buffer is too short");
            }
            throw new DataLengthException("input buffer too short");
        }
        throw new IllegalArgumentException("Need call init function before encryption/decryption");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        if (!this.initialised) {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        this.aadData.reset();
        this.ISAPAEAD.reset();
        this.message.reset();
        this.outputStream.reset();
    }
}