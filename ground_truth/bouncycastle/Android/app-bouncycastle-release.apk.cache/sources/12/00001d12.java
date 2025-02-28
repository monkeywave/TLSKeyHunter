package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class OAEPEncoding implements AsymmetricBlockCipher {
    private final byte[] defHash;
    private final AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private final Digest mgf1Hash;
    private final int mgf1NoMemoLimit;
    private SecureRandom random;

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher) {
        this(asymmetricBlockCipher, DigestFactory.createSHA1(), null);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest) {
        this(asymmetricBlockCipher, digest, null);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest, Digest digest2, byte[] bArr) {
        this.engine = asymmetricBlockCipher;
        this.mgf1Hash = digest2;
        this.mgf1NoMemoLimit = getMGF1NoMemoLimit(digest2);
        byte[] bArr2 = new byte[digest.getDigestSize()];
        this.defHash = bArr2;
        digest.reset();
        if (bArr != null) {
            digest.update(bArr, 0, bArr.length);
        }
        digest.doFinal(bArr2, 0);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest, byte[] bArr) {
        this(asymmetricBlockCipher, digest, digest, bArr);
    }

    private static int getMGF1NoMemoLimit(Digest digest) {
        if ((digest instanceof Memoable) && (digest instanceof ExtendedDigest)) {
            return ((ExtendedDigest) digest).getByteLength() - 1;
        }
        return Integer.MAX_VALUE;
    }

    private void maskGeneratorFunction1(byte[] bArr, int i, int i2, byte[] bArr2, int i3, int i4) {
        int i5;
        int digestSize = this.mgf1Hash.getDigestSize();
        byte[] bArr3 = new byte[digestSize];
        byte[] bArr4 = new byte[4];
        int i6 = i4 + i3;
        int i7 = i6 - digestSize;
        this.mgf1Hash.update(bArr, i, i2);
        if (i2 > this.mgf1NoMemoLimit) {
            Memoable memoable = (Memoable) this.mgf1Hash;
            Memoable copy = memoable.copy();
            i5 = 0;
            while (i3 < i7) {
                Pack.intToBigEndian(i5, bArr4, 0);
                this.mgf1Hash.update(bArr4, 0, 4);
                this.mgf1Hash.doFinal(bArr3, 0);
                memoable.reset(copy);
                Bytes.xorTo(digestSize, bArr3, 0, bArr2, i3);
                i3 += digestSize;
                i5++;
            }
        } else {
            int i8 = i3;
            int i9 = 0;
            while (i8 < i7) {
                Pack.intToBigEndian(i9, bArr4, 0);
                this.mgf1Hash.update(bArr4, 0, 4);
                this.mgf1Hash.doFinal(bArr3, 0);
                this.mgf1Hash.update(bArr, i, i2);
                Bytes.xorTo(digestSize, bArr3, 0, bArr2, i8);
                i8 += digestSize;
                i9++;
            }
            i5 = i9;
            i3 = i8;
        }
        Pack.intToBigEndian(i5, bArr4, 0);
        this.mgf1Hash.update(bArr4, 0, 4);
        this.mgf1Hash.doFinal(bArr3, 0);
        Bytes.xorTo(i6 - i3, bArr3, 0, bArr2, i3);
    }

    public byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        int outputBlockSize = getOutputBlockSize();
        int outputBlockSize2 = this.engine.getOutputBlockSize();
        byte[] bArr3 = new byte[outputBlockSize2];
        byte[] processBlock = this.engine.processBlock(bArr, i, i2);
        int length = ((outputBlockSize2 - processBlock.length) | outputBlockSize) >> 31;
        int min = Math.min(outputBlockSize2, processBlock.length);
        System.arraycopy(processBlock, 0, bArr3, outputBlockSize2 - min, min);
        Arrays.fill(processBlock, (byte) 0);
        this.mgf1Hash.reset();
        byte[] bArr4 = this.defHash;
        maskGeneratorFunction1(bArr3, bArr4.length, outputBlockSize2 - bArr4.length, bArr3, 0, bArr4.length);
        byte[] bArr5 = this.defHash;
        maskGeneratorFunction1(bArr3, 0, bArr5.length, bArr3, bArr5.length, outputBlockSize2 - bArr5.length);
        int i3 = 0;
        while (true) {
            bArr2 = this.defHash;
            if (i3 == bArr2.length) {
                break;
            }
            length |= bArr3[bArr2.length + i3] ^ bArr2[i3];
            i3++;
        }
        int i4 = -1;
        for (int length2 = bArr2.length * 2; length2 != outputBlockSize2; length2++) {
            i4 += (((-(bArr3[length2] & 255)) & i4) >> 31) & length2;
        }
        if (((i4 >> 31) | length | (bArr3[i4 + 1] ^ 1)) != 0) {
            Arrays.fill(bArr3, (byte) 0);
            throw new InvalidCipherTextException("data wrong");
        }
        int i5 = i4 + 2;
        int i6 = outputBlockSize2 - i5;
        byte[] bArr6 = new byte[i6];
        System.arraycopy(bArr3, i5, bArr6, 0, i6);
        Arrays.fill(bArr3, (byte) 0);
        return bArr6;
    }

    public byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        int inputBlockSize = getInputBlockSize();
        if (i2 <= inputBlockSize) {
            int length = inputBlockSize + 1 + (this.defHash.length * 2);
            byte[] bArr2 = new byte[length];
            int i3 = length - i2;
            System.arraycopy(bArr, i, bArr2, i3, i2);
            bArr2[i3 - 1] = 1;
            byte[] bArr3 = this.defHash;
            System.arraycopy(bArr3, 0, bArr2, bArr3.length, bArr3.length);
            int length2 = this.defHash.length;
            byte[] bArr4 = new byte[length2];
            this.random.nextBytes(bArr4);
            System.arraycopy(bArr4, 0, bArr2, 0, this.defHash.length);
            this.mgf1Hash.reset();
            byte[] bArr5 = this.defHash;
            maskGeneratorFunction1(bArr4, 0, length2, bArr2, bArr5.length, length - bArr5.length);
            byte[] bArr6 = this.defHash;
            maskGeneratorFunction1(bArr2, bArr6.length, length - bArr6.length, bArr2, 0, bArr6.length);
            return this.engine.processBlock(bArr2, 0, length);
        }
        throw new DataLengthException("input data too long");
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int inputBlockSize = this.engine.getInputBlockSize();
        return this.forEncryption ? (inputBlockSize - 1) - (this.defHash.length * 2) : inputBlockSize;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int outputBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? outputBlockSize : (outputBlockSize - 1) - (this.defHash.length * 2);
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        this.random = z ? CryptoServicesRegistrar.getSecureRandom(cipherParameters instanceof ParametersWithRandom ? ((ParametersWithRandom) cipherParameters).getRandom() : null) : null;
        this.forEncryption = z;
        this.engine.init(z, cipherParameters);
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }
}