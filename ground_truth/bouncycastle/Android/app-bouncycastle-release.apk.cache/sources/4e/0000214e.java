package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

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
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class MLKEMKeyGeneratorSpi extends KeyGeneratorSpi {
    private KEMExtractSpec extSpec;
    private KEMGenerateSpec genSpec;
    private MLKEMParameters kyberParameters;
    private SecureRandom random;

    /* loaded from: classes2.dex */
    public static class MLKEM1024 extends MLKEMKeyGeneratorSpi {
        public MLKEM1024() {
            super(MLKEMParameters.ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM512 extends MLKEMKeyGeneratorSpi {
        public MLKEM512() {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM768 extends MLKEMKeyGeneratorSpi {
        public MLKEM768() {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    public MLKEMKeyGeneratorSpi() {
        this(null);
    }

    protected MLKEMKeyGeneratorSpi(MLKEMParameters mLKEMParameters) {
        this.kyberParameters = mLKEMParameters;
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected SecretKey engineGenerateKey() {
        KEMGenerateSpec kEMGenerateSpec = this.genSpec;
        if (kEMGenerateSpec != null) {
            SecretWithEncapsulation generateEncapsulated = new MLKEMGenerator(this.random).generateEncapsulated(((BCMLKEMPublicKey) kEMGenerateSpec.getPublicKey()).getKeyParams());
            byte[] secret = generateEncapsulated.getSecret();
            byte[] makeKeyBytes = KdfUtil.makeKeyBytes(this.genSpec, secret);
            Arrays.clear(secret);
            SecretKeyWithEncapsulation secretKeyWithEncapsulation = new SecretKeyWithEncapsulation(new SecretKeySpec(makeKeyBytes, this.genSpec.getKeyAlgorithmName()), generateEncapsulated.getEncapsulation());
            try {
                generateEncapsulated.destroy();
                return secretKeyWithEncapsulation;
            } catch (DestroyFailedException unused) {
                throw new IllegalStateException("key cleanup failed");
            }
        }
        MLKEMExtractor mLKEMExtractor = new MLKEMExtractor(((BCMLKEMPrivateKey) this.extSpec.getPrivateKey()).getKeyParams());
        byte[] encapsulation = this.extSpec.getEncapsulation();
        byte[] extractSecret = mLKEMExtractor.extractSecret(encapsulation);
        byte[] makeKeyBytes2 = KdfUtil.makeKeyBytes(this.extSpec, extractSecret);
        Arrays.clear(extractSecret);
        SecretKeyWithEncapsulation secretKeyWithEncapsulation2 = new SecretKeyWithEncapsulation(new SecretKeySpec(makeKeyBytes2, this.extSpec.getKeyAlgorithmName()), encapsulation);
        Arrays.clear(makeKeyBytes2);
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
                String name = MLKEMParameterSpec.fromName(mLKEMParameters.getName()).getName();
                if (!name.equals(this.genSpec.getPublicKey().getAlgorithm())) {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + name);
                }
            }
        } else if (!(algorithmParameterSpec instanceof KEMExtractSpec)) {
            throw new InvalidAlgorithmParameterException("unknown spec");
        } else {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec) algorithmParameterSpec;
            MLKEMParameters mLKEMParameters2 = this.kyberParameters;
            if (mLKEMParameters2 != null) {
                String name2 = MLKEMParameterSpec.fromName(mLKEMParameters2.getName()).getName();
                if (!name2.equals(this.extSpec.getPrivateKey().getAlgorithm())) {
                    throw new InvalidAlgorithmParameterException("key generator locked to " + name2);
                }
            }
        }
    }
}