package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

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
public class MLDSAKeyFactorySpi extends BaseKeyFactorySpi {
    private static final Set<ASN1ObjectIdentifier> hashKeyOids;
    private static final Set<ASN1ObjectIdentifier> pureKeyOids;

    /* loaded from: classes2.dex */
    public static class Hash extends MLDSAKeyFactorySpi {
        public Hash() {
            super(MLDSAKeyFactorySpi.hashKeyOids);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashMLDSA44 extends MLDSAKeyFactorySpi {
        public HashMLDSA44() {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashMLDSA65 extends MLDSAKeyFactorySpi {
        public HashMLDSA65() {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashMLDSA87 extends MLDSAKeyFactorySpi {
        public HashMLDSA87() {
            super(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA44 extends MLDSAKeyFactorySpi {
        public MLDSA44() {
            super(NISTObjectIdentifiers.id_ml_dsa_44);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA65 extends MLDSAKeyFactorySpi {
        public MLDSA65() {
            super(NISTObjectIdentifiers.id_ml_dsa_65);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA87 extends MLDSAKeyFactorySpi {
        public MLDSA87() {
            super(NISTObjectIdentifiers.id_ml_dsa_87);
        }
    }

    /* loaded from: classes2.dex */
    public static class Pure extends MLDSAKeyFactorySpi {
        public Pure() {
            super(MLDSAKeyFactorySpi.pureKeyOids);
        }
    }

    static {
        HashSet hashSet = new HashSet();
        pureKeyOids = hashSet;
        HashSet hashSet2 = new HashSet();
        hashKeyOids = hashSet2;
        hashSet.add(NISTObjectIdentifiers.id_ml_dsa_44);
        hashSet.add(NISTObjectIdentifiers.id_ml_dsa_65);
        hashSet.add(NISTObjectIdentifiers.id_ml_dsa_87);
        hashSet2.add(NISTObjectIdentifiers.id_ml_dsa_44);
        hashSet2.add(NISTObjectIdentifiers.id_ml_dsa_65);
        hashSet2.add(NISTObjectIdentifiers.id_ml_dsa_87);
        hashSet2.add(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
    }

    public MLDSAKeyFactorySpi(Set<ASN1ObjectIdentifier> set) {
        super(set);
    }

    public MLDSAKeyFactorySpi(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        super(aSN1ObjectIdentifier);
    }

    @Override // java.security.KeyFactorySpi
    public final KeySpec engineGetKeySpec(Key key, Class cls) throws InvalidKeySpecException {
        if (key instanceof BCMLDSAPrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(cls)) {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        } else if (!(key instanceof BCMLDSAPublicKey)) {
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
        if ((key instanceof BCMLDSAPrivateKey) || (key instanceof BCMLDSAPublicKey)) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo privateKeyInfo) throws IOException {
        return new BCMLDSAPrivateKey(privateKeyInfo);
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        return new BCMLDSAPublicKey(subjectPublicKeyInfo);
    }
}