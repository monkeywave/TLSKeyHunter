package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

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
public class SLHDSAKeyFactorySpi extends BaseKeyFactorySpi {
    private static final Set<ASN1ObjectIdentifier> hashKeyOids;
    private static final Set<ASN1ObjectIdentifier> pureKeyOids;

    /* loaded from: classes2.dex */
    public static class Hash extends SLHDSAKeyFactorySpi {
        public Hash() {
            super(SLHDSAKeyFactorySpi.hashKeyOids);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_128f extends SLHDSAKeyFactorySpi {
        public HashSha2_128f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_128s extends SLHDSAKeyFactorySpi {
        public HashSha2_128s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_192f extends SLHDSAKeyFactorySpi {
        public HashSha2_192f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_192s extends SLHDSAKeyFactorySpi {
        public HashSha2_192s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_256f extends SLHDSAKeyFactorySpi {
        public HashSha2_256f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashSha2_256s extends SLHDSAKeyFactorySpi {
        public HashSha2_256s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_128f extends SLHDSAKeyFactorySpi {
        public HashShake_128f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_128s extends SLHDSAKeyFactorySpi {
        public HashShake_128s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_192f extends SLHDSAKeyFactorySpi {
        public HashShake_192f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_192s extends SLHDSAKeyFactorySpi {
        public HashShake_192s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_256f extends SLHDSAKeyFactorySpi {
        public HashShake_256f() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);
        }
    }

    /* loaded from: classes2.dex */
    public static class HashShake_256s extends SLHDSAKeyFactorySpi {
        public HashShake_256s() {
            super(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        }
    }

    /* loaded from: classes2.dex */
    public static class Pure extends SLHDSAKeyFactorySpi {
        public Pure() {
            super(SLHDSAKeyFactorySpi.pureKeyOids);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_128f extends SLHDSAKeyFactorySpi {
        public Sha2_128f() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_128s extends SLHDSAKeyFactorySpi {
        public Sha2_128s() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_192f extends SLHDSAKeyFactorySpi {
        public Sha2_192f() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_192s extends SLHDSAKeyFactorySpi {
        public Sha2_192s() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_256f extends SLHDSAKeyFactorySpi {
        public Sha2_256f() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_256s extends SLHDSAKeyFactorySpi {
        public Sha2_256s() {
            super(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_128f extends SLHDSAKeyFactorySpi {
        public Shake_128f() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_128s extends SLHDSAKeyFactorySpi {
        public Shake_128s() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_192f extends SLHDSAKeyFactorySpi {
        public Shake_192f() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_192s extends SLHDSAKeyFactorySpi {
        public Shake_192s() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_256f extends SLHDSAKeyFactorySpi {
        public Shake_256f() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_256s extends SLHDSAKeyFactorySpi {
        public Shake_256s() {
            super(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        }
    }

    static {
        HashSet hashSet = new HashSet();
        pureKeyOids = hashSet;
        HashSet hashSet2 = new HashSet();
        hashKeyOids = hashSet2;
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        hashSet.add(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        hashSet2.add(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);
        hashSet2.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
    }

    public SLHDSAKeyFactorySpi(Set<ASN1ObjectIdentifier> set) {
        super(set);
    }

    public SLHDSAKeyFactorySpi(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        super(aSN1ObjectIdentifier);
    }

    @Override // java.security.KeyFactorySpi
    public final KeySpec engineGetKeySpec(Key key, Class cls) throws InvalidKeySpecException {
        if (key instanceof BCSLHDSAPrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(cls)) {
                return new PKCS8EncodedKeySpec(key.getEncoded());
            }
        } else if (!(key instanceof BCSLHDSAPublicKey)) {
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
        if ((key instanceof BCSLHDSAPrivateKey) || (key instanceof BCSLHDSAPublicKey)) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type");
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PrivateKey generatePrivate(PrivateKeyInfo privateKeyInfo) throws IOException {
        return new BCSLHDSAPrivateKey(privateKeyInfo);
    }

    @Override // org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter
    public PublicKey generatePublic(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        return new BCSLHDSAPublicKey(subjectPublicKeyInfo);
    }
}