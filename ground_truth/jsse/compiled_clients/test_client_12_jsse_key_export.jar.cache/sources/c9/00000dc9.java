package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusEngine.class */
public abstract class SPHINCSPlusEngine {
    final boolean robust;

    /* renamed from: N */
    final int f912N;
    final int WOTS_W;
    final int WOTS_LOGW;
    final int WOTS_LEN;
    final int WOTS_LEN1;
    final int WOTS_LEN2;

    /* renamed from: D */
    final int f913D;

    /* renamed from: A */
    final int f914A;

    /* renamed from: K */
    final int f915K;

    /* renamed from: H */
    final int f916H;
    final int H_PRIME;

    /* renamed from: T */
    final int f917T;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusEngine$Sha256Engine.class */
    static class Sha256Engine extends SPHINCSPlusEngine {
        private final byte[] padding;
        private final Digest treeDigest;
        private final byte[] digestBuf;
        private final HMac treeHMac;
        private final MGF1BytesGenerator mgf1;
        private final byte[] hmacBuf;
        private final Digest msgDigest;

        public Sha256Engine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
            super(z, i, i2, i3, i4, i5, i6);
            this.padding = new byte[64];
            this.treeDigest = new SHA256Digest();
            if (i == 32) {
                this.msgDigest = new SHA512Digest();
                this.treeHMac = new HMac(new SHA512Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA512Digest());
            } else {
                this.msgDigest = new SHA256Digest();
                this.treeHMac = new HMac(new SHA256Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA256Digest());
            }
            this.digestBuf = new byte[this.treeDigest.getDigestSize()];
            this.hmacBuf = new byte[this.treeHMac.getMacSize()];
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: F */
        public byte[] mo4F(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                bArr2 = bitmask256(Arrays.concatenate(bArr, compressedADRS), bArr2);
            }
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(this.padding, 0, 64 - bArr.length);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.f912N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: H */
        public byte[] mo3H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            byte[] concatenate = Arrays.concatenate(bArr2, bArr3);
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                concatenate = bitmask256(Arrays.concatenate(bArr, compressedADRS), concatenate);
            }
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(this.padding, 0, 64 - this.f912N);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(concatenate, 0, concatenate.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.f912N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
            int i = ((this.f914A * this.f915K) + 7) / 8;
            int i2 = this.f916H / this.f913D;
            int i3 = this.f916H - i2;
            int i4 = (i2 + 7) / 8;
            int i5 = (i3 + 7) / 8;
            byte[] bArr5 = new byte[i + i4 + i5];
            byte[] bArr6 = new byte[this.msgDigest.getDigestSize()];
            this.msgDigest.update(bArr, 0, bArr.length);
            this.msgDigest.update(bArr2, 0, bArr2.length);
            this.msgDigest.update(bArr3, 0, bArr3.length);
            this.msgDigest.update(bArr4, 0, bArr4.length);
            this.msgDigest.doFinal(bArr6, 0);
            byte[] bitmask = bitmask(Arrays.concatenate(bArr, bArr2, bArr6), bArr5);
            byte[] bArr7 = new byte[8];
            System.arraycopy(bitmask, i, bArr7, 8 - i5, i5);
            long bigEndianToLong = Pack.bigEndianToLong(bArr7, 0) & ((-1) >>> (64 - i3));
            byte[] bArr8 = new byte[4];
            System.arraycopy(bitmask, i + i5, bArr8, 4 - i4, i4);
            return new IndexedDigest(bigEndianToLong, Pack.bigEndianToInt(bArr8, 0) & ((-1) >>> (32 - i2)), Arrays.copyOfRange(bitmask, 0, i));
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                bArr2 = bitmask256(Arrays.concatenate(bArr, compressedADRS), bArr2);
            }
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(this.padding, 0, 64 - this.f912N);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, this.f912N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] PRF(byte[] bArr, ADRS adrs) {
            int length = bArr.length;
            this.treeDigest.update(bArr, 0, bArr.length);
            byte[] compressedADRS = compressedADRS(adrs);
            this.treeDigest.update(compressedADRS, 0, compressedADRS.length);
            this.treeDigest.doFinal(this.digestBuf, 0);
            return Arrays.copyOfRange(this.digestBuf, 0, length);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            this.treeHMac.init(new KeyParameter(bArr));
            this.treeHMac.update(bArr2, 0, bArr2.length);
            this.treeHMac.update(bArr3, 0, bArr3.length);
            this.treeHMac.doFinal(this.hmacBuf, 0);
            return Arrays.copyOfRange(this.hmacBuf, 0, this.f912N);
        }

        private byte[] compressedADRS(ADRS adrs) {
            byte[] bArr = new byte[22];
            System.arraycopy(adrs.value, 3, bArr, 0, 1);
            System.arraycopy(adrs.value, 8, bArr, 1, 8);
            System.arraycopy(adrs.value, 19, bArr, 9, 1);
            System.arraycopy(adrs.value, 20, bArr, 10, 12);
            return bArr;
        }

        protected byte[] bitmask(byte[] bArr, byte[] bArr2) {
            byte[] bArr3 = new byte[bArr2.length];
            this.mgf1.init(new MGFParameters(bArr));
            this.mgf1.generateBytes(bArr3, 0, bArr3.length);
            for (int i = 0; i < bArr2.length; i++) {
                int i2 = i;
                bArr3[i2] = (byte) (bArr3[i2] ^ bArr2[i]);
            }
            return bArr3;
        }

        protected byte[] bitmask256(byte[] bArr, byte[] bArr2) {
            byte[] bArr3 = new byte[bArr2.length];
            MGF1BytesGenerator mGF1BytesGenerator = new MGF1BytesGenerator(new SHA256Digest());
            mGF1BytesGenerator.init(new MGFParameters(bArr));
            mGF1BytesGenerator.generateBytes(bArr3, 0, bArr3.length);
            for (int i = 0; i < bArr2.length; i++) {
                int i2 = i;
                bArr3[i2] = (byte) (bArr3[i2] ^ bArr2[i]);
            }
            return bArr3;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusEngine$Shake256Engine.class */
    static class Shake256Engine extends SPHINCSPlusEngine {
        private final Xof treeDigest;

        public Shake256Engine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
            super(z, i, i2, i3, i4, i5, i6);
            this.treeDigest = new SHAKEDigest(256);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: F */
        byte[] mo4F(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] bArr3 = bArr2;
            if (this.robust) {
                bArr3 = bitmask(bArr, adrs, bArr2);
            }
            byte[] bArr4 = new byte[this.f912N];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            this.treeDigest.doFinal(bArr4, 0, bArr4.length);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: H */
        byte[] mo3H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            byte[] concatenate = Arrays.concatenate(bArr2, bArr3);
            if (this.robust) {
                concatenate = bitmask(bArr, adrs, concatenate);
            }
            byte[] bArr4 = new byte[this.f912N];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(concatenate, 0, concatenate.length);
            this.treeDigest.doFinal(bArr4, 0, bArr4.length);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
            int i = ((this.f914A * this.f915K) + 7) / 8;
            int i2 = this.f916H / this.f913D;
            int i3 = this.f916H - i2;
            int i4 = (i2 + 7) / 8;
            int i5 = (i3 + 7) / 8;
            byte[] bArr5 = new byte[i + i4 + i5];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            this.treeDigest.update(bArr4, 0, bArr4.length);
            this.treeDigest.doFinal(bArr5, 0, bArr5.length);
            byte[] bArr6 = new byte[8];
            System.arraycopy(bArr5, i, bArr6, 8 - i5, i5);
            long bigEndianToLong = Pack.bigEndianToLong(bArr6, 0) & ((-1) >>> (64 - i3));
            byte[] bArr7 = new byte[4];
            System.arraycopy(bArr5, i + i5, bArr7, 4 - i4, i4);
            return new IndexedDigest(bigEndianToLong, Pack.bigEndianToInt(bArr7, 0) & ((-1) >>> (32 - i2)), Arrays.copyOfRange(bArr5, 0, i));
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] bArr3 = bArr2;
            if (this.robust) {
                bArr3 = bitmask(bArr, adrs, bArr2);
            }
            byte[] bArr4 = new byte[this.f912N];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            this.treeDigest.doFinal(bArr4, 0, bArr4.length);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] PRF(byte[] bArr, ADRS adrs) {
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            byte[] bArr2 = new byte[this.f912N];
            this.treeDigest.doFinal(bArr2, 0, this.f912N);
            return bArr2;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            byte[] bArr4 = new byte[this.f912N];
            this.treeDigest.doFinal(bArr4, 0, bArr4.length);
            return bArr4;
        }

        protected byte[] bitmask(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] bArr3 = new byte[bArr2.length];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.doFinal(bArr3, 0, bArr3.length);
            for (int i = 0; i < bArr2.length; i++) {
                int i2 = i;
                bArr3[i2] = (byte) (bArr3[i2] ^ bArr2[i]);
            }
            return bArr3;
        }
    }

    protected static byte[] xor(byte[] bArr, byte[] bArr2) {
        byte[] clone = Arrays.clone(bArr);
        for (int i = 0; i < bArr.length; i++) {
            int i2 = i;
            clone[i2] = (byte) (clone[i2] ^ bArr2[i]);
        }
        return clone;
    }

    public SPHINCSPlusEngine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
        this.f912N = i;
        if (i2 == 16) {
            this.WOTS_LOGW = 4;
            this.WOTS_LEN1 = (8 * this.f912N) / this.WOTS_LOGW;
            if (this.f912N <= 8) {
                this.WOTS_LEN2 = 2;
            } else if (this.f912N <= 136) {
                this.WOTS_LEN2 = 3;
            } else if (this.f912N > 256) {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            } else {
                this.WOTS_LEN2 = 4;
            }
        } else if (i2 != 256) {
            throw new IllegalArgumentException("wots_w assumed 16 or 256");
        } else {
            this.WOTS_LOGW = 8;
            this.WOTS_LEN1 = (8 * this.f912N) / this.WOTS_LOGW;
            if (this.f912N <= 1) {
                this.WOTS_LEN2 = 1;
            } else if (this.f912N > 256) {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            } else {
                this.WOTS_LEN2 = 2;
            }
        }
        this.WOTS_W = i2;
        this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
        this.robust = z;
        this.f913D = i3;
        this.f914A = i4;
        this.f915K = i5;
        this.f916H = i6;
        this.H_PRIME = i6 / i3;
        this.f917T = 1 << i4;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: F */
    public abstract byte[] mo4F(byte[] bArr, ADRS adrs, byte[] bArr2);

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: H */
    public abstract byte[] mo3H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] PRF(byte[] bArr, ADRS adrs);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3);
}