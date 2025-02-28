package org.bouncycastle.pqc.jcajce.provider.kyber;

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
import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.jcajce.provider.util.BaseKeyFactorySpi;

/* loaded from: classes2.dex */
public class KyberKeyFactorySpi extends BaseKeyFactorySpi {
    private static final Set<ASN1ObjectIdentifier> keyOids;

    /* loaded from: classes2.dex */
    public static class Kyber1024 extends KyberKeyFactorySpi {
        public Kyber1024() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber1024_AES extends KyberKeyFactorySpi {
        public Kyber1024_AES() {
            super(BCObjectIdentifiers.kyber1024_aes);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber512 extends KyberKeyFactorySpi {
        public Kyber512() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber512_AES extends KyberKeyFactorySpi {
        public Kyber512_AES() {
            super(BCObjectIdentifiers.kyber512_aes);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber768 extends KyberKeyFactorySpi {
        public Kyber768() {
            super(NISTObjectIdentifiers.id_alg_ml_kem_768);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber768_AES extends KyberKeyFactorySpi {
        public Kyber768_AES() {
            super(BCObjectIdentifiers.kyber768_aes);
        }
    }

    static {
        HashSet hashSet = new HashSet();
        keyOids = hashSet;
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_512);
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_768);
        hashSet.add(NISTObjectIdentifiers.id_alg_ml_kem_1024);
        hashSet.add(BCObjectIdentifiers.kyber512_aes);
        hashSet.add(BCObjectIdentifiers.kyber768_aes);
        hashSet.add(BCObjectIdentifiers.kyber1024_aes);
    }

    public KyberKeyFactorySpi() {
        super(keyOids);
    }

    public KyberKeyFactorySpi(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        super(aSN1ObjectIdentifier);
    }

    @Override // java.security.KeyFactorySpi
    public final KeySpec engineGetKeySpec(Key key, Class cls) throws InvalidKeySpecException {
        if (key instanceof BCKyberPrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(cls)) {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        } else if (!(key instanceof BCKyberPublicKey)) {
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
        if ((key instanceof BCKyberPrivateKey) || (key instanceof BCKyberPublicKey)) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo privateKeyInfo) throws IOException {
        return new BCKyberPrivateKey(privateKeyInfo);
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        return new BCKyberPublicKey(subjectPublicKeyInfo);
    }
}