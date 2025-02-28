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
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public abstract class SPHINCSPlusEngine {

    /* renamed from: A */
    final int f1425A;

    /* renamed from: D */
    final int f1426D;

    /* renamed from: H */
    final int f1427H;
    final int H_PRIME;

    /* renamed from: K */
    final int f1428K;

    /* renamed from: N */
    final int f1429N;

    /* renamed from: T */
    final int f1430T;
    final int WOTS_LEN;
    final int WOTS_LEN1;
    final int WOTS_LEN2;
    final int WOTS_LOGW;
    final int WOTS_W;
    @Deprecated
    final boolean robust;

    /* loaded from: classes2.dex */
    static class HarakaSEngine extends SPHINCSPlusEngine {
        private HarakaS256Digest harakaS256Digest;
        private HarakaS512Digest harakaS512Digest;
        private HarakaSXof harakaSXof;

        public HarakaSEngine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
            super(z, i, i2, i3, i4, i5, i6);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: F */
        public byte[] mo13F(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] bArr3 = new byte[32];
            this.harakaS512Digest.update(adrs.value, 0, adrs.value.length);
            if (this.robust) {
                this.harakaS256Digest.update(adrs.value, 0, adrs.value.length);
                this.harakaS256Digest.doFinal(bArr3, 0);
                Bytes.xorTo(bArr2.length, bArr2, bArr3);
                this.harakaS512Digest.update(bArr3, 0, bArr2.length);
            } else {
                this.harakaS512Digest.update(bArr2, 0, bArr2.length);
            }
            this.harakaS512Digest.doFinal(bArr3, 0);
            return Arrays.copyOf(bArr3, this.f1429N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: H */
        public byte[] mo12H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            int i = this.f1429N;
            byte[] bArr4 = new byte[i];
            byte[] bArr5 = new byte[bArr2.length + bArr3.length];
            System.arraycopy(bArr2, 0, bArr5, 0, bArr2.length);
            System.arraycopy(bArr3, 0, bArr5, bArr2.length, bArr3.length);
            byte[] bitmask = bitmask(adrs, bArr5);
            this.harakaSXof.update(adrs.value, 0, adrs.value.length);
            this.harakaSXof.update(bitmask, 0, bitmask.length);
            this.harakaSXof.doFinal(bArr4, 0, i);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
            int i = ((this.f1425A * this.f1428K) + 7) >> 3;
            int i2 = this.f1427H / this.f1426D;
            int i3 = this.f1427H - i2;
            int i4 = (i2 + 7) >> 3;
            int i5 = (i3 + 7) >> 3;
            int i6 = i + i4 + i5;
            byte[] bArr5 = new byte[i6];
            this.harakaSXof.update(bArr, 0, bArr.length);
            this.harakaSXof.update(bArr3, 0, bArr3.length);
            this.harakaSXof.update(bArr4, 0, bArr4.length);
            this.harakaSXof.doFinal(bArr5, 0, i6);
            byte[] bArr6 = new byte[8];
            System.arraycopy(bArr5, i, bArr6, 8 - i5, i5);
            byte[] bArr7 = new byte[4];
            System.arraycopy(bArr5, i5 + i, bArr7, 4 - i4, i4);
            return new IndexedDigest(Pack.bigEndianToLong(bArr6, 0) & ((-1) >>> (64 - i3)), Pack.bigEndianToInt(bArr7, 0) & ((-1) >>> (32 - i2)), Arrays.copyOfRange(bArr5, 0, i));
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] PRF(byte[] bArr, byte[] bArr2, ADRS adrs) {
            byte[] bArr3 = new byte[32];
            this.harakaS512Digest.update(adrs.value, 0, adrs.value.length);
            this.harakaS512Digest.update(bArr2, 0, bArr2.length);
            this.harakaS512Digest.doFinal(bArr3, 0);
            return Arrays.copyOf(bArr3, this.f1429N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            int i = this.f1429N;
            byte[] bArr4 = new byte[i];
            this.harakaSXof.update(bArr, 0, bArr.length);
            this.harakaSXof.update(bArr2, 0, bArr2.length);
            this.harakaSXof.update(bArr3, 0, bArr3.length);
            this.harakaSXof.doFinal(bArr4, 0, i);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2) {
            int i = this.f1429N;
            byte[] bArr3 = new byte[i];
            byte[] bitmask = bitmask(adrs, bArr2);
            this.harakaSXof.update(adrs.value, 0, adrs.value.length);
            this.harakaSXof.update(bitmask, 0, bitmask.length);
            this.harakaSXof.doFinal(bArr3, 0, i);
            return bArr3;
        }

        protected byte[] bitmask(ADRS adrs, byte[] bArr) {
            if (this.robust) {
                int length = bArr.length;
                byte[] bArr2 = new byte[length];
                this.harakaSXof.update(adrs.value, 0, adrs.value.length);
                this.harakaSXof.doFinal(bArr2, 0, length);
                Bytes.xorTo(bArr.length, bArr2, bArr);
            }
            return bArr;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        void init(byte[] bArr) {
            this.harakaSXof = new HarakaSXof(bArr);
            this.harakaS256Digest = new HarakaS256Digest(this.harakaSXof);
            this.harakaS512Digest = new HarakaS512Digest(this.harakaSXof);
        }
    }

    /* loaded from: classes2.dex */
    static class Sha2Engine extends SPHINCSPlusEngine {

        /* renamed from: bl */
        private final int f1431bl;
        private final byte[] hmacBuf;
        private final MGF1BytesGenerator mgf1;
        private final Digest msgDigest;
        private final byte[] msgDigestBuf;
        private Memoable msgMemo;
        private final Digest sha256;
        private final byte[] sha256Buf;
        private Memoable sha256Memo;
        private final HMac treeHMac;

        public Sha2Engine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
            super(z, i, i2, i3, i4, i5, i6);
            int i7;
            SHA256Digest sHA256Digest = new SHA256Digest();
            this.sha256 = sHA256Digest;
            this.sha256Buf = new byte[sHA256Digest.getDigestSize()];
            if (i == 16) {
                this.msgDigest = new SHA256Digest();
                this.treeHMac = new HMac(new SHA256Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA256Digest());
                i7 = 64;
            } else {
                this.msgDigest = new SHA512Digest();
                this.treeHMac = new HMac(new SHA512Digest());
                this.mgf1 = new MGF1BytesGenerator(new SHA512Digest());
                i7 = 128;
            }
            this.f1431bl = i7;
            this.hmacBuf = new byte[this.treeHMac.getMacSize()];
            this.msgDigestBuf = new byte[this.msgDigest.getDigestSize()];
        }

        private byte[] compressedADRS(ADRS adrs) {
            byte[] bArr = new byte[22];
            System.arraycopy(adrs.value, 3, bArr, 0, 1);
            System.arraycopy(adrs.value, 8, bArr, 1, 8);
            System.arraycopy(adrs.value, 19, bArr, 9, 1);
            System.arraycopy(adrs.value, 20, bArr, 10, 12);
            return bArr;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: F */
        public byte[] mo13F(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                bArr2 = bitmask256(Arrays.concatenate(bArr, compressedADRS), bArr2);
            }
            ((Memoable) this.sha256).reset(this.sha256Memo);
            this.sha256.update(compressedADRS, 0, compressedADRS.length);
            this.sha256.update(bArr2, 0, bArr2.length);
            this.sha256.doFinal(this.sha256Buf, 0);
            return Arrays.copyOfRange(this.sha256Buf, 0, this.f1429N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: H */
        public byte[] mo12H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            byte[] compressedADRS = compressedADRS(adrs);
            ((Memoable) this.msgDigest).reset(this.msgMemo);
            this.msgDigest.update(compressedADRS, 0, compressedADRS.length);
            if (this.robust) {
                byte[] bitmask = bitmask(Arrays.concatenate(bArr, compressedADRS), bArr2, bArr3);
                this.msgDigest.update(bitmask, 0, bitmask.length);
            } else {
                this.msgDigest.update(bArr2, 0, bArr2.length);
                this.msgDigest.update(bArr3, 0, bArr3.length);
            }
            this.msgDigest.doFinal(this.msgDigestBuf, 0);
            return Arrays.copyOfRange(this.msgDigestBuf, 0, this.f1429N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
            int i = ((this.f1425A * this.f1428K) + 7) / 8;
            int i2 = this.f1427H / this.f1426D;
            int i3 = this.f1427H - i2;
            int i4 = (i2 + 7) / 8;
            int i5 = (i3 + 7) / 8;
            byte[] bArr5 = new byte[this.msgDigest.getDigestSize()];
            this.msgDigest.update(bArr, 0, bArr.length);
            this.msgDigest.update(bArr2, 0, bArr2.length);
            this.msgDigest.update(bArr3, 0, bArr3.length);
            this.msgDigest.update(bArr4, 0, bArr4.length);
            this.msgDigest.doFinal(bArr5, 0);
            byte[] bitmask = bitmask(Arrays.concatenate(bArr, bArr2, bArr5), new byte[i + i4 + i5]);
            byte[] bArr6 = new byte[8];
            System.arraycopy(bitmask, i, bArr6, 8 - i5, i5);
            byte[] bArr7 = new byte[4];
            System.arraycopy(bitmask, i5 + i, bArr7, 4 - i4, i4);
            return new IndexedDigest(Pack.bigEndianToLong(bArr6, 0) & ((-1) >>> (64 - i3)), Pack.bigEndianToInt(bArr7, 0) & ((-1) >>> (32 - i2)), Arrays.copyOfRange(bitmask, 0, i));
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] PRF(byte[] bArr, byte[] bArr2, ADRS adrs) {
            int length = bArr2.length;
            ((Memoable) this.sha256).reset(this.sha256Memo);
            byte[] compressedADRS = compressedADRS(adrs);
            this.sha256.update(compressedADRS, 0, compressedADRS.length);
            this.sha256.update(bArr2, 0, bArr2.length);
            this.sha256.doFinal(this.sha256Buf, 0);
            return Arrays.copyOfRange(this.sha256Buf, 0, length);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            this.treeHMac.init(new KeyParameter(bArr));
            this.treeHMac.update(bArr2, 0, bArr2.length);
            this.treeHMac.update(bArr3, 0, bArr3.length);
            this.treeHMac.doFinal(this.hmacBuf, 0);
            return Arrays.copyOfRange(this.hmacBuf, 0, this.f1429N);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2) {
            byte[] compressedADRS = compressedADRS(adrs);
            if (this.robust) {
                bArr2 = bitmask(Arrays.concatenate(bArr, compressedADRS), bArr2);
            }
            ((Memoable) this.msgDigest).reset(this.msgMemo);
            this.msgDigest.update(compressedADRS, 0, compressedADRS.length);
            this.msgDigest.update(bArr2, 0, bArr2.length);
            this.msgDigest.doFinal(this.msgDigestBuf, 0);
            return Arrays.copyOfRange(this.msgDigestBuf, 0, this.f1429N);
        }

        protected byte[] bitmask(byte[] bArr, byte[] bArr2) {
            int length = bArr2.length;
            byte[] bArr3 = new byte[length];
            this.mgf1.init(new MGFParameters(bArr));
            this.mgf1.generateBytes(bArr3, 0, length);
            Bytes.xorTo(bArr2.length, bArr2, bArr3);
            return bArr3;
        }

        protected byte[] bitmask(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            int length = bArr2.length + bArr3.length;
            byte[] bArr4 = new byte[length];
            this.mgf1.init(new MGFParameters(bArr));
            this.mgf1.generateBytes(bArr4, 0, length);
            Bytes.xorTo(bArr2.length, bArr2, bArr4);
            Bytes.xorTo(bArr3.length, bArr3, 0, bArr4, bArr2.length);
            return bArr4;
        }

        protected byte[] bitmask256(byte[] bArr, byte[] bArr2) {
            int length = bArr2.length;
            byte[] bArr3 = new byte[length];
            MGF1BytesGenerator mGF1BytesGenerator = new MGF1BytesGenerator(new SHA256Digest());
            mGF1BytesGenerator.init(new MGFParameters(bArr));
            mGF1BytesGenerator.generateBytes(bArr3, 0, length);
            Bytes.xorTo(bArr2.length, bArr2, bArr3);
            return bArr3;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        void init(byte[] bArr) {
            byte[] bArr2 = new byte[this.f1431bl];
            this.msgDigest.update(bArr, 0, bArr.length);
            this.msgDigest.update(bArr2, 0, this.f1431bl - this.f1429N);
            this.msgMemo = ((Memoable) this.msgDigest).copy();
            this.msgDigest.reset();
            this.sha256.update(bArr, 0, bArr.length);
            this.sha256.update(bArr2, 0, 64 - bArr.length);
            this.sha256Memo = ((Memoable) this.sha256).copy();
            this.sha256.reset();
        }
    }

    /* loaded from: classes2.dex */
    static class Shake256Engine extends SPHINCSPlusEngine {
        private final Xof maskDigest;
        private final Xof treeDigest;

        public Shake256Engine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
            super(z, i, i2, i3, i4, i5, i6);
            this.treeDigest = new SHAKEDigest(256);
            this.maskDigest = new SHAKEDigest(256);
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: F */
        byte[] mo13F(byte[] bArr, ADRS adrs, byte[] bArr2) {
            if (this.robust) {
                bArr2 = bitmask(bArr, adrs, bArr2);
            }
            int i = this.f1429N;
            byte[] bArr3 = new byte[i];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.doFinal(bArr3, 0, i);
            return bArr3;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        /* renamed from: H */
        byte[] mo12H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            int i = this.f1429N;
            byte[] bArr4 = new byte[i];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            if (this.robust) {
                byte[] bitmask = bitmask(bArr, adrs, bArr2, bArr3);
                this.treeDigest.update(bitmask, 0, bitmask.length);
            } else {
                this.treeDigest.update(bArr2, 0, bArr2.length);
                this.treeDigest.update(bArr3, 0, bArr3.length);
            }
            this.treeDigest.doFinal(bArr4, 0, i);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
            int i = ((this.f1425A * this.f1428K) + 7) / 8;
            int i2 = this.f1427H / this.f1426D;
            int i3 = this.f1427H - i2;
            int i4 = (i2 + 7) / 8;
            int i5 = (i3 + 7) / 8;
            int i6 = i + i4 + i5;
            byte[] bArr5 = new byte[i6];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            this.treeDigest.update(bArr4, 0, bArr4.length);
            this.treeDigest.doFinal(bArr5, 0, i6);
            byte[] bArr6 = new byte[8];
            System.arraycopy(bArr5, i, bArr6, 8 - i5, i5);
            long bigEndianToLong = Pack.bigEndianToLong(bArr6, 0) & ((-1) >>> (64 - i3));
            byte[] bArr7 = new byte[4];
            System.arraycopy(bArr5, i5 + i, bArr7, 4 - i4, i4);
            return new IndexedDigest(bigEndianToLong, Pack.bigEndianToInt(bArr7, 0) & ((-1) >>> (32 - i2)), Arrays.copyOfRange(bArr5, 0, i));
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] PRF(byte[] bArr, byte[] bArr2, ADRS adrs) {
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            byte[] bArr3 = new byte[this.f1429N];
            this.treeDigest.doFinal(bArr3, 0, this.f1429N);
            return bArr3;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        public byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3) {
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.update(bArr3, 0, bArr3.length);
            int i = this.f1429N;
            byte[] bArr4 = new byte[i];
            this.treeDigest.doFinal(bArr4, 0, i);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2) {
            if (this.robust) {
                bArr2 = bitmask(bArr, adrs, bArr2);
            }
            int i = this.f1429N;
            byte[] bArr3 = new byte[i];
            this.treeDigest.update(bArr, 0, bArr.length);
            this.treeDigest.update(adrs.value, 0, adrs.value.length);
            this.treeDigest.update(bArr2, 0, bArr2.length);
            this.treeDigest.doFinal(bArr3, 0, i);
            return bArr3;
        }

        protected byte[] bitmask(byte[] bArr, ADRS adrs, byte[] bArr2) {
            int length = bArr2.length;
            byte[] bArr3 = new byte[length];
            this.maskDigest.update(bArr, 0, bArr.length);
            this.maskDigest.update(adrs.value, 0, adrs.value.length);
            this.maskDigest.doFinal(bArr3, 0, length);
            Bytes.xorTo(bArr2.length, bArr2, bArr3);
            return bArr3;
        }

        protected byte[] bitmask(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3) {
            int length = bArr2.length + bArr3.length;
            byte[] bArr4 = new byte[length];
            this.maskDigest.update(bArr, 0, bArr.length);
            this.maskDigest.update(adrs.value, 0, adrs.value.length);
            this.maskDigest.doFinal(bArr4, 0, length);
            Bytes.xorTo(bArr2.length, bArr2, bArr4);
            Bytes.xorTo(bArr3.length, bArr3, 0, bArr4, bArr2.length);
            return bArr4;
        }

        @Override // org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine
        void init(byte[] bArr) {
        }
    }

    public SPHINCSPlusEngine(boolean z, int i, int i2, int i3, int i4, int i5, int i6) {
        this.f1429N = i;
        if (i2 == 16) {
            this.WOTS_LOGW = 4;
            this.WOTS_LEN1 = (i * 8) / 4;
            if (i > 8) {
                if (i <= 136) {
                    this.WOTS_LEN2 = 3;
                } else if (i > 256) {
                    throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                } else {
                    this.WOTS_LEN2 = 4;
                }
                this.WOTS_W = i2;
                this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
                this.robust = z;
                this.f1426D = i3;
                this.f1425A = i4;
                this.f1428K = i5;
                this.f1427H = i6;
                this.H_PRIME = i6 / i3;
                this.f1430T = 1 << i4;
            }
            this.WOTS_LEN2 = 2;
            this.WOTS_W = i2;
            this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
            this.robust = z;
            this.f1426D = i3;
            this.f1425A = i4;
            this.f1428K = i5;
            this.f1427H = i6;
            this.H_PRIME = i6 / i3;
            this.f1430T = 1 << i4;
        } else if (i2 != 256) {
            throw new IllegalArgumentException("wots_w assumed 16 or 256");
        } else {
            this.WOTS_LOGW = 8;
            this.WOTS_LEN1 = (i * 8) / 8;
            if (i <= 1) {
                this.WOTS_LEN2 = 1;
                this.WOTS_W = i2;
                this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
                this.robust = z;
                this.f1426D = i3;
                this.f1425A = i4;
                this.f1428K = i5;
                this.f1427H = i6;
                this.H_PRIME = i6 / i3;
                this.f1430T = 1 << i4;
            }
            if (i > 256) {
                throw new IllegalArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
            }
            this.WOTS_LEN2 = 2;
            this.WOTS_W = i2;
            this.WOTS_LEN = this.WOTS_LEN1 + this.WOTS_LEN2;
            this.robust = z;
            this.f1426D = i3;
            this.f1425A = i4;
            this.f1428K = i5;
            this.f1427H = i6;
            this.H_PRIME = i6 / i3;
            this.f1430T = 1 << i4;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: F */
    public abstract byte[] mo13F(byte[] bArr, ADRS adrs, byte[] bArr2);

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: H */
    public abstract byte[] mo12H(byte[] bArr, ADRS adrs, byte[] bArr2, byte[] bArr3);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract IndexedDigest H_msg(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] PRF(byte[] bArr, byte[] bArr2, ADRS adrs);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] PRF_msg(byte[] bArr, byte[] bArr2, byte[] bArr3);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] T_l(byte[] bArr, ADRS adrs, byte[] bArr2);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void init(byte[] bArr);
}