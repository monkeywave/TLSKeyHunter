package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.util.WrapUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
class KyberCipherSpi extends CipherSpi {
    private final String algorithmName;
    private AlgorithmParameters engineParams;
    private MLKEMGenerator kemGen;
    private KTSParameterSpec kemParameterSpec;
    private MLKEMParameters kyberParameters;
    private BCKyberPrivateKey unwrapKey;
    private BCKyberPublicKey wrapKey;

    /* loaded from: classes2.dex */
    public static class Base extends KyberCipherSpi {
        public Base() throws NoSuchAlgorithmException {
            super("KYBER");
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber1024 extends KyberCipherSpi {
        public Kyber1024() {
            super(MLKEMParameters.ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber512 extends KyberCipherSpi {
        public Kyber512() {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber768 extends KyberCipherSpi {
        public Kyber768() {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    KyberCipherSpi(String str) {
        this.algorithmName = str;
        this.kyberParameters = null;
    }

    KyberCipherSpi(MLKEMParameters mLKEMParameters) {
        this.kyberParameters = mLKEMParameters;
        this.algorithmName = Strings.toUpperCase(mLKEMParameters.getName());
    }

    @Override // javax.crypto.CipherSpi
    protected int engineDoFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineDoFinal(byte[] bArr, int i, int i2) throws IllegalBlockSizeException, BadPaddingException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineGetIV() {
        return null;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetKeySize(Key key) {
        return 2048;
    }

    @Override // javax.crypto.CipherSpi
    protected int engineGetOutputSize(int i) {
        return -1;
    }

    @Override // javax.crypto.CipherSpi
    protected AlgorithmParameters engineGetParameters() {
        if (this.engineParams == null) {
            try {
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(this.algorithmName, "BCPQC");
                this.engineParams = algorithmParameters;
                algorithmParameters.init(this.kemParameterSpec);
            } catch (Exception e) {
                throw Exceptions.illegalStateException(e.toString(), e);
            }
        }
        return this.engineParams;
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec parameterSpec;
        if (algorithmParameters != null) {
            try {
                parameterSpec = algorithmParameters.getParameterSpec(KEMParameterSpec.class);
            } catch (Exception unused) {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        } else {
            parameterSpec = null;
        }
        engineInit(i, key, parameterSpec, secureRandom);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            AlgorithmParameterSpec algorithmParameterSpec = null;
            engineInit(i, key, (AlgorithmParameterSpec) null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw Exceptions.illegalArgumentException(e.getMessage(), e);
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        KTSParameterSpec kTSParameterSpec;
        if (algorithmParameterSpec == null) {
            kTSParameterSpec = new KEMParameterSpec("AES-KWP");
        } else if (!(algorithmParameterSpec instanceof KTSParameterSpec)) {
            throw new InvalidAlgorithmParameterException(this.algorithmName + " can only accept KTSParameterSpec");
        } else {
            kTSParameterSpec = (KTSParameterSpec) algorithmParameterSpec;
        }
        this.kemParameterSpec = kTSParameterSpec;
        if (i == 3) {
            if (!(key instanceof BCKyberPublicKey)) {
                throw new InvalidKeyException("Only a " + this.algorithmName + " public key can be used for wrapping");
            }
            this.wrapKey = (BCKyberPublicKey) key;
            this.kemGen = new MLKEMGenerator(CryptoServicesRegistrar.getSecureRandom(secureRandom));
        } else if (i != 4) {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        } else {
            if (!(key instanceof BCKyberPrivateKey)) {
                throw new InvalidKeyException("Only a " + this.algorithmName + " private key can be used for unwrapping");
            }
            this.unwrapKey = (BCKyberPrivateKey) key;
        }
        MLKEMParameters mLKEMParameters = this.kyberParameters;
        if (mLKEMParameters != null) {
            String upperCase = Strings.toUpperCase(mLKEMParameters.getName());
            if (!upperCase.equals(key.getAlgorithm())) {
                throw new InvalidKeyException("cipher locked to " + upperCase);
            }
        }
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetMode(String str) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cannot support mode " + str);
    }

    @Override // javax.crypto.CipherSpi
    protected void engineSetPadding(String str) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding " + str + " unknown");
    }

    @Override // javax.crypto.CipherSpi
    protected Key engineUnwrap(byte[] bArr, String str, int i) throws InvalidKeyException, NoSuchAlgorithmException {
        if (i == 3) {
            byte[] bArr2 = null;
            try {
                try {
                    MLKEMExtractor mLKEMExtractor = new MLKEMExtractor(this.unwrapKey.getKeyParams());
                    bArr2 = mLKEMExtractor.extractSecret(Arrays.copyOfRange(bArr, 0, mLKEMExtractor.getEncapsulationLength()));
                    Wrapper keyUnwrapper = WrapUtil.getKeyUnwrapper(this.kemParameterSpec, bArr2);
                    byte[] copyOfRange = Arrays.copyOfRange(bArr, mLKEMExtractor.getEncapsulationLength(), bArr.length);
                    return new SecretKeySpec(keyUnwrapper.unwrap(copyOfRange, 0, copyOfRange.length), str);
                } catch (IllegalArgumentException e) {
                    throw new NoSuchAlgorithmException("unable to extract KTS secret: " + e.getMessage());
                } catch (InvalidCipherTextException e2) {
                    throw new InvalidKeyException("unable to extract KTS secret: " + e2.getMessage());
                }
            } finally {
                if (bArr2 != null) {
                    Arrays.clear(bArr2);
                }
            }
        }
        throw new InvalidKeyException("only SECRET_KEY supported");
    }

    @Override // javax.crypto.CipherSpi
    protected int engineUpdate(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws ShortBufferException {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineUpdate(byte[] bArr, int i, int i2) {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    @Override // javax.crypto.CipherSpi
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key.getEncoded() != null) {
            SecretWithEncapsulation secretWithEncapsulation = null;
            try {
                try {
                    secretWithEncapsulation = this.kemGen.generateEncapsulated(this.wrapKey.getKeyParams());
                    Wrapper keyWrapper = WrapUtil.getKeyWrapper(this.kemParameterSpec, secretWithEncapsulation.getSecret());
                    byte[] encapsulation = secretWithEncapsulation.getEncapsulation();
                    byte[] encoded = key.getEncoded();
                    byte[] concatenate = Arrays.concatenate(encapsulation, keyWrapper.wrap(encoded, 0, encoded.length));
                    Arrays.clear(encoded);
                    if (secretWithEncapsulation != null) {
                        try {
                            secretWithEncapsulation.destroy();
                        } catch (DestroyFailedException e) {
                            throw new IllegalBlockSizeException("unable to destroy interim values: " + e.getMessage());
                        }
                    }
                    return concatenate;
                } catch (IllegalArgumentException e2) {
                    throw new IllegalBlockSizeException("unable to generate KTS secret: " + e2.getMessage());
                }
            } catch (Throwable th) {
                if (secretWithEncapsulation != null) {
                    try {
                        secretWithEncapsulation.destroy();
                    } catch (DestroyFailedException e3) {
                        throw new IllegalBlockSizeException("unable to destroy interim values: " + e3.getMessage());
                    }
                }
                throw th;
            }
        }
        throw new InvalidKeyException("Cannot wrap key, null encoding.");
    }
}