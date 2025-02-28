package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class ParallelHash implements Xof, Digest {
    private static final byte[] N_PARALLEL_HASH = Strings.toByteArray("ParallelHash");

    /* renamed from: B */
    private final int f460B;
    private final int bitLength;
    private int bufOff;
    private final byte[] buffer;
    private final CSHAKEDigest compressor;
    private final byte[] compressorBuffer;
    private final CSHAKEDigest cshake;
    private boolean firstOutput;
    private int nCount;
    private final int outputLength;
    private final CryptoServicePurpose purpose;

    public ParallelHash(int i, byte[] bArr, int i2) {
        this(i, bArr, i2, i * 2, CryptoServicePurpose.ANY);
    }

    public ParallelHash(int i, byte[] bArr, int i2, int i3) {
        this(i, bArr, i2, i3, CryptoServicePurpose.ANY);
    }

    public ParallelHash(int i, byte[] bArr, int i2, int i3, CryptoServicePurpose cryptoServicePurpose) {
        this.cshake = new CSHAKEDigest(i, N_PARALLEL_HASH, bArr);
        this.compressor = new CSHAKEDigest(i, new byte[0], new byte[0]);
        this.bitLength = i;
        this.f460B = i2;
        this.outputLength = (i3 + 7) / 8;
        this.buffer = new byte[i2];
        this.compressorBuffer = new byte[(i * 2) / 8];
        this.purpose = cryptoServicePurpose;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, i, cryptoServicePurpose));
        reset();
    }

    public ParallelHash(ParallelHash parallelHash) {
        this.cshake = new CSHAKEDigest(parallelHash.cshake);
        this.compressor = new CSHAKEDigest(parallelHash.compressor);
        int i = parallelHash.bitLength;
        this.bitLength = i;
        this.f460B = parallelHash.f460B;
        this.outputLength = parallelHash.outputLength;
        this.buffer = Arrays.clone(parallelHash.buffer);
        this.compressorBuffer = Arrays.clone(parallelHash.compressorBuffer);
        CryptoServicePurpose cryptoServicePurpose = parallelHash.purpose;
        this.purpose = cryptoServicePurpose;
        this.firstOutput = parallelHash.firstOutput;
        this.nCount = parallelHash.nCount;
        this.bufOff = parallelHash.bufOff;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, i, cryptoServicePurpose));
    }

    private void compress() {
        compress(this.buffer, 0, this.bufOff);
        this.bufOff = 0;
    }

    private void compress(byte[] bArr, int i, int i2) {
        this.compressor.update(bArr, i, i2);
        CSHAKEDigest cSHAKEDigest = this.compressor;
        byte[] bArr2 = this.compressorBuffer;
        cSHAKEDigest.doFinal(bArr2, 0, bArr2.length);
        CSHAKEDigest cSHAKEDigest2 = this.cshake;
        byte[] bArr3 = this.compressorBuffer;
        cSHAKEDigest2.update(bArr3, 0, bArr3.length);
        this.nCount++;
    }

    private void wrapUp(int i) {
        if (this.bufOff != 0) {
            compress();
        }
        byte[] rightEncode = XofUtils.rightEncode(this.nCount);
        byte[] rightEncode2 = XofUtils.rightEncode(i * 8);
        this.cshake.update(rightEncode, 0, rightEncode.length);
        this.cshake.update(rightEncode2, 0, rightEncode2.length);
        this.firstOutput = false;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        if (this.firstOutput) {
            wrapUp(this.outputLength);
        }
        int doFinal = this.cshake.doFinal(bArr, i, getDigestSize());
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Xof
    public int doFinal(byte[] bArr, int i, int i2) {
        if (this.firstOutput) {
            wrapUp(this.outputLength);
        }
        int doFinal = this.cshake.doFinal(bArr, i, i2);
        reset();
        return doFinal;
    }

    @Override // org.bouncycastle.crypto.Xof
    public int doOutput(byte[] bArr, int i, int i2) {
        if (this.firstOutput) {
            wrapUp(0);
        }
        return this.cshake.doOutput(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "ParallelHash" + this.cshake.getAlgorithmName().substring(6);
    }

    @Override // org.bouncycastle.crypto.ExtendedDigest
    public int getByteLength() {
        return this.cshake.getByteLength();
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.outputLength;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.cshake.reset();
        Arrays.clear(this.buffer);
        byte[] leftEncode = XofUtils.leftEncode(this.f460B);
        this.cshake.update(leftEncode, 0, leftEncode.length);
        this.nCount = 0;
        this.bufOff = 0;
        this.firstOutput = true;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) throws IllegalStateException {
        byte[] bArr = this.buffer;
        int i = this.bufOff;
        int i2 = i + 1;
        this.bufOff = i2;
        bArr[i] = b;
        if (i2 == bArr.length) {
            compress();
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        int i3 = 0;
        int max = Math.max(0, i2);
        if (this.bufOff != 0) {
            while (i3 < max) {
                int i4 = this.bufOff;
                byte[] bArr2 = this.buffer;
                if (i4 == bArr2.length) {
                    break;
                }
                this.bufOff = i4 + 1;
                bArr2[i4] = bArr[i3 + i];
                i3++;
            }
            if (this.bufOff == this.buffer.length) {
                compress();
            }
        }
        if (i3 < max) {
            while (true) {
                int i5 = max - i3;
                int i6 = this.f460B;
                if (i5 < i6) {
                    break;
                }
                compress(bArr, i + i3, i6);
                i3 += this.f460B;
            }
        }
        while (i3 < max) {
            update(bArr[i3 + i]);
            i3++;
        }
    }
}