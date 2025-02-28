package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RFC3211WrapEngine implements Wrapper {
    private CBCBlockCipher engine;
    private boolean forWrapping;
    private ParametersWithIV param;
    private SecureRandom rand;

    public RFC3211WrapEngine(BlockCipher blockCipher) {
        this.engine = new CBCBlockCipher(blockCipher);
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public String getAlgorithmName() {
        return this.engine.getUnderlyingCipher().getAlgorithmName() + "/RFC3211Wrap";
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forWrapping = z;
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.rand = parametersWithRandom.getRandom();
            if (!(parametersWithRandom.getParameters() instanceof ParametersWithIV)) {
                throw new IllegalArgumentException("RFC3211Wrap requires an IV");
            }
            this.param = (ParametersWithIV) parametersWithRandom.getParameters();
            return;
        }
        if (z) {
            this.rand = CryptoServicesRegistrar.getSecureRandom();
        }
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("RFC3211Wrap requires an IV");
        }
        this.param = (ParametersWithIV) cipherParameters;
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] unwrap(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (this.forWrapping) {
            throw new IllegalStateException("not set for unwrapping");
        }
        int blockSize = this.engine.getBlockSize();
        if (i2 >= blockSize * 2) {
            byte[] bArr2 = new byte[i2];
            byte[] bArr3 = new byte[blockSize];
            System.arraycopy(bArr, i, bArr2, 0, i2);
            System.arraycopy(bArr, i, bArr3, 0, blockSize);
            this.engine.init(false, new ParametersWithIV(this.param.getParameters(), bArr3));
            for (int i3 = blockSize; i3 < i2; i3 += blockSize) {
                this.engine.processBlock(bArr2, i3, bArr2, i3);
            }
            System.arraycopy(bArr2, i2 - blockSize, bArr3, 0, blockSize);
            this.engine.init(false, new ParametersWithIV(this.param.getParameters(), bArr3));
            this.engine.processBlock(bArr2, 0, bArr2, 0);
            this.engine.init(false, this.param);
            for (int i4 = 0; i4 < i2; i4 += blockSize) {
                this.engine.processBlock(bArr2, i4, bArr2, i4);
            }
            int i5 = bArr2[0];
            int i6 = i2 - 4;
            boolean z = (i5 & 255) > i6;
            byte[] bArr4 = z ? new byte[i6] : new byte[i5 & 255];
            System.arraycopy(bArr2, 4, bArr4, 0, bArr4.length);
            int i7 = 0;
            int i8 = 0;
            while (i7 != 3) {
                int i9 = i7 + 1;
                i8 |= bArr2[i7 + 4] ^ ((byte) (~bArr2[i9]));
                i7 = i9;
            }
            Arrays.clear(bArr2);
            if (!z && !(i8 != 0)) {
                return bArr4;
            }
            throw new InvalidCipherTextException("wrapped key corrupted");
        }
        throw new InvalidCipherTextException("input too short");
    }

    @Override // org.bouncycastle.crypto.Wrapper
    public byte[] wrap(byte[] bArr, int i, int i2) {
        if (this.forWrapping) {
            if (i2 > 255 || i2 < 0) {
                throw new IllegalArgumentException("input must be from 0 to 255 bytes");
            }
            this.engine.init(true, this.param);
            int blockSize = this.engine.getBlockSize();
            int i3 = i2 + 4;
            int i4 = blockSize * 2;
            if (i3 >= i4) {
                i4 = i3 % blockSize == 0 ? i3 : ((i3 / blockSize) + 1) * blockSize;
            }
            byte[] bArr2 = new byte[i4];
            bArr2[0] = (byte) i2;
            System.arraycopy(bArr, i, bArr2, 4, i2);
            int length = bArr2.length - i3;
            byte[] bArr3 = new byte[length];
            this.rand.nextBytes(bArr3);
            System.arraycopy(bArr3, 0, bArr2, i3, length);
            bArr2[1] = (byte) (~bArr2[4]);
            bArr2[2] = (byte) (~bArr2[5]);
            bArr2[3] = (byte) (~bArr2[6]);
            for (int i5 = 0; i5 < bArr2.length; i5 += blockSize) {
                this.engine.processBlock(bArr2, i5, bArr2, i5);
            }
            for (int i6 = 0; i6 < bArr2.length; i6 += blockSize) {
                this.engine.processBlock(bArr2, i6, bArr2, i6);
            }
            return bArr2;
        }
        throw new IllegalStateException("not set for wrapping");
    }
}