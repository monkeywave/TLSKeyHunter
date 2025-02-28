package org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/SCRYPT.class */
public class SCRYPT {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/SCRYPT$BasePBKDF2.class */
    public static class BasePBKDF2 extends BaseSecretKeyFactory {
        private int scheme;

        public BasePBKDF2(String str, int i) {
            super(str, MiscObjectIdentifiers.id_scrypt);
            this.scheme = i;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory, javax.crypto.SecretKeyFactorySpi
        public SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof ScryptKeySpec) {
                ScryptKeySpec scryptKeySpec = (ScryptKeySpec) keySpec;
                if (scryptKeySpec.getSalt() == null) {
                    throw new IllegalArgumentException("Salt S must be provided.");
                }
                if (scryptKeySpec.getCostParameter() <= 1) {
                    throw new IllegalArgumentException("Cost parameter N must be > 1.");
                }
                if (scryptKeySpec.getKeyLength() <= 0) {
                    throw new InvalidKeySpecException("positive key length required: " + scryptKeySpec.getKeyLength());
                }
                if (scryptKeySpec.getPassword().length == 0) {
                    throw new IllegalArgumentException("password empty");
                }
                return new BCPBEKey(this.algName, new KeyParameter(SCrypt.generate(PasswordConverter.UTF8.convert(scryptKeySpec.getPassword()), scryptKeySpec.getSalt(), scryptKeySpec.getCostParameter(), scryptKeySpec.getBlockSize(), scryptKeySpec.getParallelizationParameter(), scryptKeySpec.getKeyLength() / 8)));
            }
            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/SCRYPT$Mappings.class */
    public static class Mappings extends AlgorithmProvider {
        private static final String PREFIX = SCRYPT.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("SecretKeyFactory.SCRYPT", PREFIX + "$ScryptWithUTF8");
            configurableProvider.addAlgorithm("SecretKeyFactory", MiscObjectIdentifiers.id_scrypt, PREFIX + "$ScryptWithUTF8");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/SCRYPT$ScryptWithUTF8.class */
    public static class ScryptWithUTF8 extends BasePBKDF2 {
        public ScryptWithUTF8() {
            super("SCRYPT", 5);
        }
    }

    private SCRYPT() {
    }
}