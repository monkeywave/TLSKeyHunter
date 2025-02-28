package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

/* loaded from: classes2.dex */
public class MLKEMKeyFactorySpi extends BaseKeyFactorySpi {
    private static final Set<ASN1ObjectIdentifier> keyOids;

    /* loaded from: classes2.dex */
    public static class MLKEM1024 extends MLKEMKeyFactorySpi {
        public MLKEM1024() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM512 extends MLKEMKeyFactorySpi {
        public MLKEM512() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM768 extends MLKEMKeyFactorySpi {
        public MLKEM768() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_768);
        }
    }

    static {
        HashSet hashSet = new HashSet();
        keyOids = hashSet;
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_512);
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_768);
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_1024);
    }

    public MLKEMKeyFactorySpi() {
        super(keyOids);
    }

    public MLKEMKeyFactorySpi(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        super(aSN1ObjectIdentifier);
    }

    @Override // java.security.KeyFactorySpi
    public final KeySpec engineGetKeySpec(Key key, Class cls) throws InvalidKeySpecException {
        if (key instanceof BCMLKEMPrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(cls)) {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        } else if (!(key instanceof BCMLKEMPublicKey)) {
            throw new InvalidKeySpecException("Unsupported key type: " + key.getClass() + ".");
        } else {
            if (X509EncodedKeySpec.class.isAssignableFrom(cls)) {
                return new X509EncodedKeySpec(key.getEncoded());
            }
        }
        throw new InvalidKeySpecException("Unknown key specification: " + cls + ".");
    }

    @Override // java.security.KeyFactorySpi
    public final Key engineTranslateKey(Key key) throws InvalidKeyException {
        if ((key instanceof BCMLKEMPrivateKey) || (key instanceof BCMLKEMPublicKey)) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo privateKeyInfo) throws IOException {
        return new BCMLKEMPrivateKey(privateKeyInfo);
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        return new BCMLKEMPublicKey(subjectPublicKeyInfo);
    }
}