package org.bouncycastle.crypto.engines;

import androidx.core.view.InputDeviceCompat;
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
import org.bouncycastle.crypto.SavableDigest;
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

/* loaded from: classes2.dex */
public class EthereumIESEngine {

    /* renamed from: IV */
    private byte[] f624IV;

    /* renamed from: V */
    byte[] f625V;
    BasicAgreement agree;
    BufferedBlockCipher cipher;
    byte[] commonMac;
    boolean forEncryption;
    DerivationFunction kdf;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;
    Mac mac;
    byte[] macBuf;
    IESParameters param;
    CipherParameters privParam;
    CipherParameters pubParam;

    /* loaded from: classes2.dex */
    public static class HandshakeKDFFunction implements DigestDerivationFunction {
        private int counterStart;
        private Digest digest;

        /* renamed from: iv */
        private byte[] f626iv;
        private byte[] shared;

        public HandshakeKDFFunction(int i, Digest digest) {
            this.counterStart = i;
            this.digest = digest;
        }

        @Override // org.bouncycastle.crypto.DerivationFunction
        public int generateBytes(byte[] bArr, int i, int i2) throws DataLengthException, IllegalArgumentException {
            int i3 = i2;
            int i4 = i;
            if (bArr.length - i3 >= i4) {
                long j = i3;
                int digestSize = this.digest.getDigestSize();
                if (j <= 8589934591L) {
                    long j2 = digestSize;
                    int i5 = (int) (((j + j2) - 1) / j2);
                    byte[] bArr2 = new byte[this.digest.getDigestSize()];
                    int i6 = 4;
                    byte[] bArr3 = new byte[4];
                    Pack.intToBigEndian(this.counterStart, bArr3, 0);
                    int i7 = this.counterStart & InputDeviceCompat.SOURCE_ANY;
                    int i8 = 0;
                    while (i8 < i5) {
                        this.digest.update(bArr3, 0, i6);
                        Digest digest = this.digest;
                        byte[] bArr4 = this.shared;
                        digest.update(bArr4, 0, bArr4.length);
                        byte[] bArr5 = this.f626iv;
                        if (bArr5 != null) {
                            this.digest.update(bArr5, 0, bArr5.length);
                        }
                        this.digest.doFinal(bArr2, 0);
                        if (i3 > digestSize) {
                            System.arraycopy(bArr2, 0, bArr, i4, digestSize);
                            i4 += digestSize;
                            i3 -= digestSize;
                        } else {
                            System.arraycopy(bArr2, 0, bArr, i4, i3);
                        }
                        byte b = (byte) (bArr3[3] + 1);
                        bArr3[3] = b;
                        if (b == 0) {
                            i7 += 256;
                            Pack.intToBigEndian(i7, bArr3, 0);
                        }
                        i8++;
                        i6 = 4;
                    }
                    this.digest.reset();
                    return (int) j;
                }
                throw new IllegalArgumentException("output length too large");
            }
            throw new OutputLengthException("output buffer too small");
        }

        @Override // org.bouncycastle.crypto.DigestDerivationFunction
        public Digest getDigest() {
            return this.digest;
        }

        @Override // org.bouncycastle.crypto.DerivationFunction
        public void init(DerivationParameters derivationParameters) {
            if (derivationParameters instanceof KDFParameters) {
                KDFParameters kDFParameters = (KDFParameters) derivationParameters;
                this.shared = kDFParameters.getSharedSecret();
                this.f626iv = kDFParameters.getIV();
            } else if (!(derivationParameters instanceof ISO18033KDFParameters)) {
                throw new IllegalArgumentException("KDF parameters required for generator");
            } else {
                this.shared = ((ISO18033KDFParameters) derivationParameters).getSeed();
                this.f626iv = null;
            }
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

    private byte[] decryptBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        byte[] bArr3;
        int processBytes;
        if (i2 >= this.f625V.length + this.mac.getMacSize()) {
            if (this.cipher == null) {
                int length = (i2 - this.f625V.length) - this.mac.getMacSize();
                byte[] bArr4 = new byte[length];
                int macKeySize = this.param.getMacKeySize() / 8;
                bArr2 = new byte[macKeySize];
                int i3 = length + macKeySize;
                byte[] bArr5 = new byte[i3];
                this.kdf.generateBytes(bArr5, 0, i3);
                if (this.f625V.length != 0) {
                    System.arraycopy(bArr5, 0, bArr2, 0, macKeySize);
                    System.arraycopy(bArr5, macKeySize, bArr4, 0, length);
                } else {
                    System.arraycopy(bArr5, 0, bArr4, 0, length);
                    System.arraycopy(bArr5, length, bArr2, 0, macKeySize);
                }
                bArr3 = new byte[length];
                for (int i4 = 0; i4 != length; i4++) {
                    bArr3[i4] = (byte) (bArr[(this.f625V.length + i) + i4] ^ bArr4[i4]);
                }
                processBytes = 0;
            } else {
                int cipherKeySize = ((IESWithCipherParameters) this.param).getCipherKeySize() / 8;
                byte[] bArr6 = new byte[cipherKeySize];
                int macKeySize2 = this.param.getMacKeySize() / 8;
                bArr2 = new byte[macKeySize2];
                int i5 = cipherKeySize + macKeySize2;
                byte[] bArr7 = new byte[i5];
                this.kdf.generateBytes(bArr7, 0, i5);
                System.arraycopy(bArr7, 0, bArr6, 0, cipherKeySize);
                System.arraycopy(bArr7, cipherKeySize, bArr2, 0, macKeySize2);
                CipherParameters keyParameter = new KeyParameter(bArr6);
                if (this.f624IV != null) {
                    keyParameter = new ParametersWithIV(keyParameter, this.f624IV);
                }
                this.cipher.init(false, keyParameter);
                bArr3 = new byte[this.cipher.getOutputSize((i2 - this.f625V.length) - this.mac.getMacSize())];
                BufferedBlockCipher bufferedBlockCipher = this.cipher;
                byte[] bArr8 = this.f625V;
                processBytes = bufferedBlockCipher.processBytes(bArr, i + bArr8.length, (i2 - bArr8.length) - this.mac.getMacSize(), bArr3, 0);
            }
            byte[] encodingV = this.param.getEncodingV();
            byte[] lengthTag = this.f625V.length != 0 ? getLengthTag(encodingV) : null;
            int i6 = i + i2;
            byte[] copyOfRange = Arrays.copyOfRange(bArr, i6 - this.mac.getMacSize(), i6);
            int length2 = copyOfRange.length;
            byte[] bArr9 = new byte[length2];
            SavableDigest newInstance = SHA256Digest.newInstance();
            byte[] bArr10 = new byte[newInstance.getDigestSize()];
            newInstance.reset();
            newInstance.update(bArr2, 0, bArr2.length);
            newInstance.doFinal(bArr10, 0);
            this.mac.init(new KeyParameter(bArr10));
            Mac mac = this.mac;
            byte[] bArr11 = this.f624IV;
            mac.update(bArr11, 0, bArr11.length);
            Mac mac2 = this.mac;
            byte[] bArr12 = this.f625V;
            mac2.update(bArr, i + bArr12.length, (i2 - bArr12.length) - length2);
            if (encodingV != null) {
                this.mac.update(encodingV, 0, encodingV.length);
            }
            if (this.f625V.length != 0) {
                this.mac.update(lengthTag, 0, lengthTag.length);
            }
            Mac mac3 = this.mac;
            byte[] bArr13 = this.commonMac;
            mac3.update(bArr13, 0, bArr13.length);
            this.mac.doFinal(bArr9, 0);
            if (Arrays.constantTimeAreEqual(copyOfRange, bArr9)) {
                BufferedBlockCipher bufferedBlockCipher2 = this.cipher;
                return bufferedBlockCipher2 == null ? bArr3 : Arrays.copyOfRange(bArr3, 0, processBytes + bufferedBlockCipher2.doFinal(bArr3, processBytes));
            }
            throw new InvalidCipherTextException("invalid MAC");
        }
        throw new InvalidCipherTextException("length of input must be greater than the MAC and V combined");
    }

    private byte[] encryptBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        BufferedBlockCipher bufferedBlockCipher;
        CipherParameters keyParameter;
        byte[] bArr2;
        byte[] bArr3;
        if (this.cipher == null) {
            byte[] bArr4 = new byte[i2];
            int macKeySize = this.param.getMacKeySize() / 8;
            bArr3 = new byte[macKeySize];
            int i3 = i2 + macKeySize;
            byte[] bArr5 = new byte[i3];
            this.kdf.generateBytes(bArr5, 0, i3);
            if (this.f625V.length != 0) {
                System.arraycopy(bArr5, 0, bArr3, 0, macKeySize);
                System.arraycopy(bArr5, macKeySize, bArr4, 0, i2);
            } else {
                System.arraycopy(bArr5, 0, bArr4, 0, i2);
                System.arraycopy(bArr5, i2, bArr3, 0, macKeySize);
            }
            bArr2 = new byte[i2];
            for (int i4 = 0; i4 != i2; i4++) {
                bArr2[i4] = (byte) (bArr[i + i4] ^ bArr4[i4]);
            }
        } else {
            int cipherKeySize = ((IESWithCipherParameters) this.param).getCipherKeySize() / 8;
            byte[] bArr6 = new byte[cipherKeySize];
            int macKeySize2 = this.param.getMacKeySize() / 8;
            byte[] bArr7 = new byte[macKeySize2];
            int i5 = cipherKeySize + macKeySize2;
            byte[] bArr8 = new byte[i5];
            this.kdf.generateBytes(bArr8, 0, i5);
            System.arraycopy(bArr8, 0, bArr6, 0, cipherKeySize);
            System.arraycopy(bArr8, cipherKeySize, bArr7, 0, macKeySize2);
            if (this.f624IV != null) {
                bufferedBlockCipher = this.cipher;
                keyParameter = new ParametersWithIV(new KeyParameter(bArr6), this.f624IV);
            } else {
                bufferedBlockCipher = this.cipher;
                keyParameter = new KeyParameter(bArr6);
            }
            bufferedBlockCipher.init(true, keyParameter);
            bArr2 = new byte[this.cipher.getOutputSize(i2)];
            int processBytes = this.cipher.processBytes(bArr, i, i2, bArr2, 0);
            i2 = processBytes + this.cipher.doFinal(bArr2, processBytes);
            bArr3 = bArr7;
        }
        byte[] encodingV = this.param.getEncodingV();
        byte[] lengthTag = this.f625V.length != 0 ? getLengthTag(encodingV) : null;
        int macSize = this.mac.getMacSize();
        byte[] bArr9 = new byte[macSize];
        SavableDigest newInstance = SHA256Digest.newInstance();
        byte[] bArr10 = new byte[newInstance.getDigestSize()];
        newInstance.reset();
        newInstance.update(bArr3, 0, bArr3.length);
        newInstance.doFinal(bArr10, 0);
        this.mac.init(new KeyParameter(bArr10));
        Mac mac = this.mac;
        byte[] bArr11 = this.f624IV;
        mac.update(bArr11, 0, bArr11.length);
        this.mac.update(bArr2, 0, bArr2.length);
        if (encodingV != null) {
            this.mac.update(encodingV, 0, encodingV.length);
        }
        if (this.f625V.length != 0) {
            this.mac.update(lengthTag, 0, lengthTag.length);
        }
        Mac mac2 = this.mac;
        byte[] bArr12 = this.commonMac;
        mac2.update(bArr12, 0, bArr12.length);
        this.mac.doFinal(bArr9, 0);
        byte[] bArr13 = this.f625V;
        byte[] bArr14 = new byte[bArr13.length + i2 + macSize];
        System.arraycopy(bArr13, 0, bArr14, 0, bArr13.length);
        System.arraycopy(bArr2, 0, bArr14, this.f625V.length, i2);
        System.arraycopy(bArr9, 0, bArr14, this.f625V.length + i2, macSize);
        return bArr14;
    }

    private void extractParams(CipherParameters cipherParameters) {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            this.f624IV = parametersWithIV.getIV();
            cipherParameters = parametersWithIV.getParameters();
        } else {
            this.f624IV = null;
        }
        this.param = (IESParameters) cipherParameters;
    }

    public BufferedBlockCipher getCipher() {
        return this.cipher;
    }

    protected byte[] getLengthTag(byte[] bArr) {
        byte[] bArr2 = new byte[8];
        if (bArr != null) {
            Pack.longToBigEndian(bArr.length * 8, bArr2, 0);
        }
        return bArr2;
    }

    public Mac getMac() {
        return this.mac;
    }

    public void init(AsymmetricKeyParameter asymmetricKeyParameter, CipherParameters cipherParameters, KeyParser keyParser) {
        this.forEncryption = false;
        this.privParam = asymmetricKeyParameter;
        this.keyParser = keyParser;
        extractParams(cipherParameters);
    }

    public void init(AsymmetricKeyParameter asymmetricKeyParameter, CipherParameters cipherParameters, EphemeralKeyPairGenerator ephemeralKeyPairGenerator) {
        this.forEncryption = true;
        this.pubParam = asymmetricKeyParameter;
        this.keyPairGenerator = ephemeralKeyPairGenerator;
        extractParams(cipherParameters);
    }

    public void init(boolean z, CipherParameters cipherParameters, CipherParameters cipherParameters2, CipherParameters cipherParameters3) {
        this.forEncryption = z;
        this.privParam = cipherParameters;
        this.pubParam = cipherParameters2;
        this.f625V = new byte[0];
        extractParams(cipherParameters3);
    }

    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (this.forEncryption) {
            EphemeralKeyPairGenerator ephemeralKeyPairGenerator = this.keyPairGenerator;
            if (ephemeralKeyPairGenerator != null) {
                EphemeralKeyPair generate = ephemeralKeyPairGenerator.generate();
                this.privParam = generate.getKeyPair().getPrivate();
                this.f625V = generate.getEncodedPublicKey();
            }
        } else if (this.keyParser != null) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr, i, i2);
            try {
                this.pubParam = this.keyParser.readKey(byteArrayInputStream);
                this.f625V = Arrays.copyOfRange(bArr, i, (i2 - byteArrayInputStream.available()) + i);
            } catch (IOException e) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
            } catch (IllegalArgumentException e2) {
                throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e2.getMessage(), e2);
            }
        }
        this.agree.init(this.privParam);
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(this.agree.getFieldSize(), this.agree.calculateAgreement(this.pubParam));
        byte[] bArr2 = this.f625V;
        if (bArr2.length != 0) {
            byte[] concatenate = Arrays.concatenate(bArr2, asUnsignedByteArray);
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
}