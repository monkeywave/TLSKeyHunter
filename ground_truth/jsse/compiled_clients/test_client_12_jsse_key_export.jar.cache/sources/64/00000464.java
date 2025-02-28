package org.bouncycastle.crypto.engines;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/EthereumIESEngine.class */
public class EthereumIESEngine {
    BasicAgreement agree;
    DerivationFunction kdf;
    Mac mac;
    BufferedBlockCipher cipher;
    byte[] macBuf;
    byte[] commonMac;
    boolean forEncryption;
    CipherParameters privParam;
    CipherParameters pubParam;
    IESParameters param;

    /* renamed from: V */
    byte[] f334V;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;

    /* renamed from: IV */
    private byte[] f335IV;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/EthereumIESEngine$HandshakeKDFFunction.class */
    public static class HandshakeKDFFunction implements DigestDerivationFunction {
        private int counterStart;
        private Digest digest;
        private byte[] shared;

        /* renamed from: iv */
        private byte[] f336iv;

        public HandshakeKDFFunction(int i, Digest digest) {
            this.counterStart = i;
            this.digest = digest;
        }

        @Override // org.bouncycastle.crypto.DerivationFunction
        public void init(DerivationParameters derivationParameters) {
            if (derivationParameters instanceof KDFParameters) {
                KDFParameters kDFParameters = (KDFParameters) derivationParameters;
                this.shared = kDFParameters.getSharedSecret();
                this.f336iv = kDFParameters.getIV();
            } else if (!(derivationParameters instanceof ISO18033KDFParameters)) {
                throw new IllegalArgumentException("KDF parameters required for generator");
            } else {
                this.shared = ((ISO18033KDFParameters) derivationParameters).getSeed();
                this.f336iv = null;
            }
        }

        @Override // org.bouncycastle.crypto.DigestDerivationFunction
        public Digest getDigest() {
            return this.digest;
        }

        @Override // org.bouncycastle.crypto.DerivationFunction
        public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
            if (bArr.length - i2 < i) {
                throw new OutputLengthException("output buffer too small");
            }
            long j = i2;
            int digestSize = this.digest.getDigestSize();
            if (j > 8589934591L) {
                throw new IllegalArgumentException("output length too large");
            }
            int i3 = (int) (((j + digestSize) - 1) / digestSize);
            byte[] bArr2 = new byte[this.digest.getDigestSize()];
            byte[] bArr3 = new byte[4];
            Pack.intToBigEndian(this.counterStart, bArr3, 0);
            int i4 = this.counterStart & (-256);
            for (int i5 = 0; i5 < i3; i5++) {
                this.digest.update(bArr3, 0, bArr3.length);
                this.digest.update(this.shared, 0, this.shared.length);
                if (this.f336iv != null) {
                    this.digest.update(this.f336iv, 0, this.f336iv.length);
                }
                this.digest.doFinal(bArr2, 0);
                if (i2 > digestSize) {
                    System.arraycopy(bArr2, 0, bArr, i, digestSize);
                    i += digestSize;
                    i2 -= digestSize;
                } else {
                    System.arraycopy(bArr2, 0, bArr, i, i2);
                }
                byte b = (byte) (bArr3[3] + 1);
                bArr3[3] = b;
                if (b == 0) {
                    i4 += 256;
                    Pack.intToBigEndian(i4, bArr3, 0);
                }
            }
            this.digest.reset();
            return (int) j;
        }
    }

    public EthereumIESEngine(BasicAgreement basicAgreement, DerivationFunction derivationFunction, Mac mac, byte[] bArr) {
        this.agree = basicAgreement;
        this.kdf = derivationFunction;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.commonMac = bArr;
        this.cipher = null;
    }

    public EthereumIESEngine(BasicAgreement basicAgreement, DerivationFunction derivationFunction, Mac mac, byte[] bArr, BufferedBlockCipher bufferedBlockCipher) {
        this.agree = basicAgreement;
        this.kdf = derivationFunction;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.commonMac = bArr;
        this.cipher = bufferedBlockCipher;
    }

    public void init(boolean z, CipherParameters cipherParameters, CipherParameters cipherParameters2, CipherParameters cipherParameters3) {
        this.forEncryption = z;
        this.privParam = cipherParameters;
        this.pubParam = cipherParameters2;
        this.f334V = new byte[0];
        extractParams(cipherParameters3);
    }

    public void init(AsymmetricKeyParameter asymmetricKeyParameter, CipherParameters cipherParameters, EphemeralKeyPairGenerator ephemeralKeyPairGenerator) {
        this.forEncryption = true;
        this.pubParam = asymmetricKeyParameter;
        this.keyPairGenerator = ephemeralKeyPairGenerator;
        extractParams(cipherParameters);
    }

    public void init(AsymmetricKeyParameter asymmetricKeyParameter, CipherParameters cipherParameters, KeyParser keyParser) {
        this.forEncryption = false;
        this.privParam = asymmetricKeyParameter;
        this.keyParser = keyParser;
        extractParams(cipherParameters);
    }

    private void extractParams(CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithIV) {
            this.f335IV = ((ParametersWithIV) cipherParameters).getIV();
            this.param = (IESParameters) ((ParametersWithIV) cipherParameters).getParameters();
            return;
        }
        this.f335IV = null;
        this.param = (IESParameters) cipherParameters;
    }

    public BufferedBlockCipher getCipher() {
        return this.cipher;
    }

    public Mac getMac() {
        return this.mac;
    }

    private byte[] encryptBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        byte[] bArr3;
        int doFinal;
        if (this.cipher == null) {
            byte[] bArr4 = new byte[i2];
            bArr2 = new byte[this.param.getMacKeySize() / 8];
            byte[] bArr5 = new byte[bArr4.length + bArr2.length];
            this.kdf.generateBytes(bArr5, 0, bArr5.length);
            if (this.f334V.length != 0) {
                System.arraycopy(bArr5, 0, bArr2, 0, bArr2.length);
                System.arraycopy(bArr5, bArr2.length, bArr4, 0, bArr4.length);
            } else {
                System.arraycopy(bArr5, 0, bArr4, 0, bArr4.length);
                System.arraycopy(bArr5, i2, bArr2, 0, bArr2.length);
            }
            bArr3 = new byte[i2];
            for (int i3 = 0; i3 != i2; i3++) {
                bArr3[i3] = (byte) (bArr[i + i3] ^ bArr4[i3]);
            }
            doFinal = i2;
        } else {
            byte[] bArr6 = new byte[((IESWithCipherParameters) this.param).getCipherKeySize() / 8];
            bArr2 = new byte[this.param.getMacKeySize() / 8];
            byte[] bArr7 = new byte[bArr6.length + bArr2.length];
            this.kdf.generateBytes(bArr7, 0, bArr7.length);
            System.arraycopy(bArr7, 0, bArr6, 0, bArr6.length);
            System.arraycopy(bArr7, bArr6.length, bArr2, 0, bArr2.length);
            if (this.f335IV != null) {
                this.cipher.init(true, new ParametersWithIV(new KeyParameter(bArr6), this.f335IV));
            } else {
                this.cipher.init(true, new KeyParameter(bArr6));
            }
            bArr3 = new byte[this.cipher.getOutputSize(i2)];
            int processBytes = this.cipher.processBytes(bArr, i, i2, bArr3, 0);
            doFinal = processBytes + this.cipher.doFinal(bArr3, processBytes);
        }
        byte[] encodingV = this.param.getEncodingV();
        byte[] lengthTag = this.f334V.length != 0 ? getLengthTag(encodingV) : null;
        byte[] bArr8 = new byte[this.mac.getMacSize()];
        SHA256Digest sHA256Digest = new SHA256Digest();
        byte[] bArr9 = new byte[sHA256Digest.getDigestSize()];
        sHA256Digest.reset();
        sHA256Digest.update(bArr2, 0, bArr2.length);
        sHA256Digest.doFinal(bArr9, 0);
        this.mac.init(new KeyParameter(bArr9));
        this.mac.update(this.f335IV, 0, this.f335IV.length);
        this.mac.update(bArr3, 0, bArr3.length);
        if (encodingV != null) {
            this.mac.update(encodingV, 0, encodingV.length);
        }
        if (this.f334V.length != 0) {
            this.mac.update(lengthTag, 0, lengthTag.length);
        }
        this.mac.update(this.commonMac, 0, this.commonMac.length);
        this.mac.doFinal(bArr8, 0);
        byte[] bArr10 = new byte[this.f334V.length + doFinal + bArr8.length];
        System.arraycopy(this.f334V, 0, bArr10, 0, this.f334V.length);
        System.arraycopy(bArr3, 0, bArr10, this.f334V.length, doFinal);
        System.arraycopy(bArr8, 0, bArr10, this.f334V.length + doFinal, bArr8.length);
        return bArr10;
    }

    private byte[] decryptBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        byte[] bArr3;
        int i3 = 0;
        if (i2 < this.f334V.length + this.mac.getMacSize()) {
            throw new InvalidCipherTextException("length of input must be greater than the MAC and V combined");
        }
        if (this.cipher == null) {
            byte[] bArr4 = new byte[(i2 - this.f334V.length) - this.mac.getMacSize()];
            bArr2 = new byte[this.param.getMacKeySize() / 8];
            byte[] bArr5 = new byte[bArr4.length + bArr2.length];
            this.kdf.generateBytes(bArr5, 0, bArr5.length);
            if (this.f334V.length != 0) {
                System.arraycopy(bArr5, 0, bArr2, 0, bArr2.length);
                System.arraycopy(bArr5, bArr2.length, bArr4, 0, bArr4.length);
            } else {
                System.arraycopy(bArr5, 0, bArr4, 0, bArr4.length);
                System.arraycopy(bArr5, bArr4.length, bArr2, 0, bArr2.length);
            }
            bArr3 = new byte[bArr4.length];
            for (int i4 = 0; i4 != bArr4.length; i4++) {
                bArr3[i4] = (byte) (bArr[(i + this.f334V.length) + i4] ^ bArr4[i4]);
            }
        } else {
            byte[] bArr6 = new byte[((IESWithCipherParameters) this.param).getCipherKeySize() / 8];
            bArr2 = new byte[this.param.getMacKeySize() / 8];
            byte[] bArr7 = new byte[bArr6.length + bArr2.length];
            this.kdf.generateBytes(bArr7, 0, bArr7.length);
            System.arraycopy(bArr7, 0, bArr6, 0, bArr6.length);
            System.arraycopy(bArr7, bArr6.length, bArr2, 0, bArr2.length);
            CipherParameters keyParameter = new KeyParameter(bArr6);
            if (this.f335IV != null) {
                keyParameter = new ParametersWithIV(keyParameter, this.f335IV);
            }
            this.cipher.init(false, keyParameter);
            bArr3 = new byte[this.cipher.getOutputSize((i2 - this.f334V.length) - this.mac.getMacSize())];
            i3 = this.cipher.processBytes(bArr, i + this.f334V.length, (i2 - this.f334V.length) - this.mac.getMacSize(), bArr3, 0);
        }
        byte[] encodingV = this.param.getEncodingV();
        byte[] lengthTag = this.f334V.length != 0 ? getLengthTag(encodingV) : null;
        int i5 = i + i2;
        byte[] copyOfRange = Arrays.copyOfRange(bArr, i5 - this.mac.getMacSize(), i5);
        byte[] bArr8 = new byte[copyOfRange.length];
        SHA256Digest sHA256Digest = new SHA256Digest();
        byte[] bArr9 = new byte[sHA256Digest.getDigestSize()];
        sHA256Digest.reset();
        sHA256Digest.update(bArr2, 0, bArr2.length);
        sHA256Digest.doFinal(bArr9, 0);
        this.mac.init(new KeyParameter(bArr9));
        this.mac.update(this.f335IV, 0, this.f335IV.length);
        this.mac.update(bArr, i + this.f334V.length, (i2 - this.f334V.length) - bArr8.length);
        if (encodingV != null) {
            this.mac.update(encodingV, 0, encodingV.length);
        }
        if (this.f334V.length != 0) {
            this.mac.update(lengthTag, 0, lengthTag.length);
        }
        this.mac.update(this.commonMac, 0, this.commonMac.length);
        this.mac.doFinal(bArr8, 0);
        if (Arrays.constantTimeAreEqual(copyOfRange, bArr8)) {
            if (this.cipher == null) {
                return bArr3;
            }
            return Arrays.copyOfRange(bArr3, 0, i3 + this.cipher.doFinal(bArr3, i3));
        }
        throw new InvalidCipherTextException("invalid MAC");
    }

    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (this.forEncryption) {
            if (this.keyPairGenerator != null) {
                EphemeralKeyPair generate = this.keyPairGenerator.generate();
                this.privParam = generate.getKeyPair().getPrivate();
                this.f334V = generate.getEncodedPublicKey();
            }
        } else if (this.keyParser != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr, i, i2);
            try {
                this.pubParam = this.keyParser.readKey(byteArrayInputStream);
                this.f334V = Arrays.copyOfRange(bArr, i, i + (i2 - byteArrayInputStream.available()));
            } catch (IOException e) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
            } catch (IllegalArgumentException e2) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e2.getMessage(), e2);
            }
        }
        this.agree.init(this.privParam);
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(this.agree.getFieldSize(), this.agree.calculateAgreement(this.pubParam));
        if (this.f334V.length != 0) {
            byte[] concatenate = Arrays.concatenate(this.f334V, asUnsignedByteArray);
            Arrays.fill(asUnsignedByteArray, (byte) 0);
            asUnsignedByteArray = concatenate;
        }
        try {
            this.kdf.init(new KDFParameters(asUnsignedByteArray, this.param.getDerivationV()));
            return this.forEncryption ? encryptBlock(bArr, i, i2) : decryptBlock(bArr, i, i2);
        } finally {
            Arrays.fill(asUnsignedByteArray, (byte) 0);
        }
    }

    protected byte[] getLengthTag(byte[] bArr) {
        byte[] bArr2 = new byte[8];
        if (bArr != null) {
            Pack.longToBigEndian(bArr.length * 8, bArr2, 0);
        }
        return bArr2;
    }
}