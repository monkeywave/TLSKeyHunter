package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/util/DigestFactory.class */
public final class DigestFactory {
    private static final Map cloneMap = new HashMap();

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/util/DigestFactory$Cloner.class */
    private interface Cloner {
        Digest createClone(Digest digest);
    }

    public static Digest createMD5() {
        return new MD5Digest();
    }

    public static Digest createSHA1() {
        return new SHA1Digest();
    }

    public static Digest createSHA224() {
        return new SHA224Digest();
    }

    public static Digest createSHA256() {
        return new SHA256Digest();
    }

    public static Digest createSHA384() {
        return new SHA384Digest();
    }

    public static Digest createSHA512() {
        return new SHA512Digest();
    }

    public static Digest createSHA512_224() {
        return new SHA512tDigest((int) BERTags.FLAGS);
    }

    public static Digest createSHA512_256() {
        return new SHA512tDigest(256);
    }

    public static Digest createSHA3_224() {
        return new SHA3Digest((int) BERTags.FLAGS);
    }

    public static Digest createSHA3_256() {
        return new SHA3Digest(256);
    }

    public static Digest createSHA3_384() {
        return new SHA3Digest(384);
    }

    public static Digest createSHA3_512() {
        return new SHA3Digest(512);
    }

    public static Digest createSHAKE128() {
        return new SHAKEDigest(128);
    }

    public static Digest createSHAKE256() {
        return new SHAKEDigest(256);
    }

    public static Digest cloneDigest(Digest digest) {
        return ((Cloner) cloneMap.get(digest.getAlgorithmName())).createClone(digest);
    }

    static {
        cloneMap.put(createMD5().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.1
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new MD5Digest((MD5Digest) digest);
            }
        });
        cloneMap.put(createSHA1().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.2
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new MD5Digest((MD5Digest) digest);
            }
        });
        cloneMap.put(createSHA224().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.3
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA224Digest((SHA224Digest) digest);
            }
        });
        cloneMap.put(createSHA256().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.4
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA256Digest((SHA256Digest) digest);
            }
        });
        cloneMap.put(createSHA384().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.5
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA384Digest((SHA384Digest) digest);
            }
        });
        cloneMap.put(createSHA512().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.6
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA512Digest((SHA512Digest) digest);
            }
        });
        cloneMap.put(createSHA3_224().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.7
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA3Digest((SHA3Digest) digest);
            }
        });
        cloneMap.put(createSHA3_256().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.8
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA3Digest((SHA3Digest) digest);
            }
        });
        cloneMap.put(createSHA3_384().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.9
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA3Digest((SHA3Digest) digest);
            }
        });
        cloneMap.put(createSHA3_512().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.10
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHA3Digest((SHA3Digest) digest);
            }
        });
        cloneMap.put(createSHAKE128().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.11
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHAKEDigest((SHAKEDigest) digest);
            }
        });
        cloneMap.put(createSHAKE256().getAlgorithmName(), new Cloner() { // from class: org.bouncycastle.crypto.util.DigestFactory.12
            @Override // org.bouncycastle.crypto.util.DigestFactory.Cloner
            public Digest createClone(Digest digest) {
                return new SHAKEDigest((SHAKEDigest) digest);
            }
        });
    }
}