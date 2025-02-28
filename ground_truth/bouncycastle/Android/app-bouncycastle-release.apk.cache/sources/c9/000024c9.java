package org.bouncycastle.jcajce.provider.symmetric;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;

/* loaded from: classes2.dex */
public class SCRYPT {

    /* loaded from: classes2.dex */
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
                if (scryptKeySpec.getSalt() != null) {
                    if (scryptKeySpec.getCostParameter() > 1) {
                        if (scryptKeySpec.getKeyLength() > 0) {
                            if (scryptKeySpec.getPassword().length != 0) {
                                return new BCPBEKey(this.algName, new KeyParameter(SCrypt.generate(PasswordConverter.UTF8.convert(scryptKeySpec.getPassword()), scryptKeySpec.getSalt(), scryptKeySpec.getCostParameter(), scryptKeySpec.getBlockSize(), scryptKeySpec.getParallelizationParameter(), scryptKeySpec.getKeyLength() / 8)));
                            }
                            throw new IllegalArgumentException("password empty");
                        }
                        throw new InvalidKeySpecException("positive key length required: " + scryptKeySpec.getKeyLength());
                    }
                    throw new IllegalArgumentException("Cost parameter N must be > 1.");
                }
                throw new IllegalArgumentException("Salt S must be provided.");
            }
            throw new InvalidKeySpecException("Invalid KeySpec");
        }
    }

    /* loaded from: classes2.dex */
    public static class Mappings extends AlgorithmProvider {
        private static final String PREFIX = SCRYPT.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            StringBuilder sb = new StringBuilder();
            String str = PREFIX;
            configurableProvider.addAlgorithm("SecretKeyFactory.SCRYPT", sb.append(str).append("$ScryptWithUTF8").toString());
            configurableProvider.addAlgorithm("SecretKeyFactory", MiscObjectIdentifiers.id_scrypt, str + "$ScryptWithUTF8");
        }
    }

    /* loaded from: classes2.dex */
    public static class ScryptWithUTF8 extends BasePBKDF2 {
        public ScryptWithUTF8() {
            super("SCRYPT", 5);
        }
    }

    private SCRYPT() {
    }
}