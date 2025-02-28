package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class KyberKeyGeneratorSpi extends KeyGeneratorSpi {
    private KEMExtractSpec extSpec;
    private KEMGenerateSpec genSpec;
    private MLKEMParameters kyberParameters;
    private SecureRandom random;

    /* loaded from: classes2.dex */
    public static class Kyber1024 extends KyberKeyGeneratorSpi {
        public Kyber1024() {
            super(MLKEMParameters.ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber512 extends KyberKeyGeneratorSpi {
        public Kyber512() {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber768 extends KyberKeyGeneratorSpi {
        public Kyber768() {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    public KyberKeyGeneratorSpi() {
        this(null);
    }

    protected KyberKeyGeneratorSpi(MLKEMParameters mLKEMParameters) {
        this.kyberParameters = mLKEMParameters;
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected SecretKey engineGenerateKey() {
        KEMGenerateSpec kEMGenerateSpec = this.genSpec;
        if (kEMGenerateSpec != null) {
            SecretWithEncapsulation generateEncapsulated = new MLKEMGenerator(this.random).generateEncapsulated(((BCKyberPublicKey) kEMGenerateSpec.getPublicKey()).getKeyParams());
            byte[] secret = generateEncapsulated.getSecret();
            byte[] copyOfRange = Arrays.copyOfRange(secret, 0, (this.genSpec.getKeySize() + 7) / 8);
            Arrays.clear(secret);
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = new SecretKeyWithEncapsulation(new SecretKeySpec(copyOfRange, this.genSpec.getKeyAlgorithmName()), generateEncapsulated.getEncapsulation());
            try {
                generateEncapsulated.destroy();
                return secretKeyWithEncapsulation;
            } catch (DestroyFailedException unused) {
                throw new IllegalStateException("key cleanup failed");
            }
        }
        MLKEMExtractor mLKEMExtractor = new MLKEMExtractor(((BCKyberPrivateKey) this.extSpec.getPrivateKey()).getKeyParams());
        byte[] encapsulation = this.extSpec.getEncapsulation();
        byte[] extractSecret = mLKEMExtractor.extractSecret(encapsulation);
        byte[] copyOfRange2 = Arrays.copyOfRange(extractSecret, 0, (this.extSpec.getKeySize() + 7) / 8);
        Arrays.clear(extractSecret);
        SecretKeyWithEncapsulation secretKeyWithEncapsulation2 = new SecretKeyWithEncapsulation(new SecretKeySpec(copyOfRange2, this.extSpec.getKeyAlgorithmName()), encapsulation);
        Arrays.clear(copyOfRange2);
        return secretKeyWithEncapsulation2;
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(int i, SecureRandom secureRandom) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom secureRandom) {
        throw new UnsupportedOperationException("Operation not supported");
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec) {
            this.genSpec = (KEMGenerateSpec) algorithmParameterSpec;
            this.extSpec = null;
            MLKEMParameters mLKEMParameters = this.kyberParameters;
            if (mLKEMParameters != null) {
                String upperCase = Strings.toUpperCase(mLKEMParameters.getName());
                if (!upperCase.equals(this.genSpec.getPublicKey().getAlgorithm())) {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + upperCase);
                }
            }
        } else if (!(algorithmParameterSpec instanceof KEMExtractSpec)) {
            throw new InvalidAlgorithmParameterException("unknown spec");
        } else {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec) algorithmParameterSpec;
            MLKEMParameters mLKEMParameters2 = this.kyberParameters;
            if (mLKEMParameters2 != null) {
                String upperCase2 = Strings.toUpperCase(mLKEMParameters2.getName());
                if (!upperCase2.equals(this.extSpec.getPrivateKey().getAlgorithm())) {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + upperCase2);
                }
            }
        }
    }
}