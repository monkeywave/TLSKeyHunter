package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/encodings/OAEPEncoding.class */
public class OAEPEncoding implements AsymmetricBlockCipher {
    private byte[] defHash;
    private Digest mgf1Hash;
    private AsymmetricBlockCipher engine;
    private SecureRandom random;
    private boolean forEncryption;

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher) {
        this(asymmetricBlockCipher, DigestFactory.createSHA1(), null);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest) {
        this(asymmetricBlockCipher, digest, null);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest, byte[] bArr) {
        this(asymmetricBlockCipher, digest, digest, bArr);
    }

    public OAEPEncoding(AsymmetricBlockCipher asymmetricBlockCipher, Digest digest, Digest digest2, byte[] bArr) {
        this.engine = asymmetricBlockCipher;
        this.mgf1Hash = digest2;
        this.defHash = new byte[digest.getDigestSize()];
        digest.reset();
        if (bArr != null) {
            digest.update(bArr, 0, bArr.length);
        }
        digest.doFinal(this.defHash, 0);
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithRandom) {
            this.random = ((ParametersWithRandom) cipherParameters).getRandom();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
        this.engine.init(z, cipherParameters);
        this.forEncryption = z;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int inputBlockSize = this.engine.getInputBlockSize();
        return this.forEncryption ? (inputBlockSize - 1) - (2 * this.defHash.length) : inputBlockSize;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int outputBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? outputBlockSize : (outputBlockSize - 1) - (2 * this.defHash.length);
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }

    public byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (i2 > getInputBlockSize()) {
            throw new DataLengthException("input data too long");
        }
        byte[] bArr2 = new byte[getInputBlockSize() + 1 + (2 * this.defHash.length)];
        System.arraycopy(bArr, i, bArr2, bArr2.length - i2, i2);
        bArr2[(bArr2.length - i2) - 1] = 1;
        System.arraycopy(this.defHash, 0, bArr2, this.defHash.length, this.defHash.length);
        byte[] bArr3 = new byte[this.defHash.length];
        this.random.nextBytes(bArr3);
        byte[] maskGeneratorFunction1 = maskGeneratorFunction1(bArr3, 0, bArr3.length, bArr2.length - this.defHash.length);
        for (int length = this.defHash.length; length != bArr2.length; length++) {
            int i3 = length;
            bArr2[i3] = (byte) (bArr2[i3] ^ maskGeneratorFunction1[length - this.defHash.length]);
        }
        System.arraycopy(bArr3, 0, bArr2, 0, this.defHash.length);
        byte[] maskGeneratorFunction12 = maskGeneratorFunction1(bArr2, this.defHash.length, bArr2.length - this.defHash.length, this.defHash.length);
        for (int i4 = 0; i4 != this.defHash.length; i4++) {
            int i5 = i4;
            bArr2[i5] = (byte) (bArr2[i5] ^ maskGeneratorFunction12[i4]);
        }
        return this.engine.processBlock(bArr2, 0, bArr2.length);
    }

    public byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] processBlock = this.engine.processBlock(bArr, i, i2);
        byte[] bArr2 = new byte[this.engine.getOutputBlockSize()];
        boolean z = bArr2.length < (2 * this.defHash.length) + 1;
        if (processBlock.length <= bArr2.length) {
            System.arraycopy(processBlock, 0, bArr2, bArr2.length - processBlock.length, processBlock.length);
        } else {
            System.arraycopy(processBlock, 0, bArr2, 0, bArr2.length);
            z = true;
        }
        byte[] maskGeneratorFunction1 = maskGeneratorFunction1(bArr2, this.defHash.length, bArr2.length - this.defHash.length, this.defHash.length);
        for (int i3 = 0; i3 != this.defHash.length; i3++) {
            int i4 = i3;
            bArr2[i4] = (byte) (bArr2[i4] ^ maskGeneratorFunction1[i3]);
        }
        byte[] maskGeneratorFunction12 = maskGeneratorFunction1(bArr2, 0, this.defHash.length, bArr2.length - this.defHash.length);
        for (int length = this.defHash.length; length != bArr2.length; length++) {
            int i5 = length;
            bArr2[i5] = (byte) (bArr2[i5] ^ maskGeneratorFunction12[length - this.defHash.length]);
        }
        boolean z2 = false;
        for (int i6 = 0; i6 != this.defHash.length; i6++) {
            if (this.defHash[i6] != bArr2[this.defHash.length + i6]) {
                z2 = true;
            }
        }
        int length2 = bArr2.length;
        for (int length3 = 2 * this.defHash.length; length3 != bArr2.length; length3++) {
            if ((bArr2[length3] != 0) & (length2 == bArr2.length)) {
                length2 = length3;
            }
        }
        boolean z3 = (length2 > bArr2.length - 1) | (bArr2[length2] != 1);
        int i7 = length2 + 1;
        if ((z2 | z) || z3) {
            Arrays.fill(bArr2, (byte) 0);
            throw new InvalidCipherTextException("data wrong");
        }
        byte[] bArr3 = new byte[bArr2.length - i7];
        System.arraycopy(bArr2, i7, bArr3, 0, bArr3.length);
        Arrays.fill(bArr2, (byte) 0);
        return bArr3;
    }

    private byte[] maskGeneratorFunction1(byte[] bArr, int i, int i2, int i3) {
        byte[] bArr2 = new byte[i3];
        byte[] bArr3 = new byte[this.mgf1Hash.getDigestSize()];
        byte[] bArr4 = new byte[4];
        int i4 = 0;
        this.mgf1Hash.reset();
        while (i4 < i3 / bArr3.length) {
            Pack.intToBigEndian(i4, bArr4, 0);
            this.mgf1Hash.update(bArr, i, i2);
            this.mgf1Hash.update(bArr4, 0, bArr4.length);
            this.mgf1Hash.doFinal(bArr3, 0);
            System.arraycopy(bArr3, 0, bArr2, i4 * bArr3.length, bArr3.length);
            i4++;
        }
        if (i4 * bArr3.length < i3) {
            Pack.intToBigEndian(i4, bArr4, 0);
            this.mgf1Hash.update(bArr, i, i2);
            this.mgf1Hash.update(bArr4, 0, bArr4.length);
            this.mgf1Hash.doFinal(bArr3, 0);
            System.arraycopy(bArr3, 0, bArr2, i4 * bArr3.length, bArr2.length - (i4 * bArr3.length));
        }
        return bArr2;
    }
}