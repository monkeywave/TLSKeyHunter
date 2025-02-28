package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.ParameterUtil;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.BCKeyStore;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi.class */
public class PKCS12KeyStoreSpi extends KeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore {
    static final String PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";
    private static final int SALT_SIZE = 20;
    private static final int MIN_ITERATIONS = 51200;
    private static final DefaultSecretKeyProvider keySizeProvider = new DefaultSecretKeyProvider();
    static final int NULL = 0;
    static final int CERTIFICATE = 1;
    static final int KEY = 2;
    static final int SECRET = 3;
    static final int SEALED = 4;
    static final int KEY_PRIVATE = 0;
    static final int KEY_PUBLIC = 1;
    static final int KEY_SECRET = 2;
    private CertificateFactory certFact;
    private ASN1ObjectIdentifier keyAlgorithm;
    private ASN1ObjectIdentifier certAlgorithm;
    private final JcaJceHelper helper = new BCJcaJceHelper();
    private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
    private IgnoresCaseHashtable localIds = new IgnoresCaseHashtable();
    private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
    private Hashtable chainCerts = new Hashtable();
    private Hashtable keyCerts = new Hashtable();
    protected SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
    private int itCount = 102400;
    private int saltLength = 20;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$BCPKCS12KeyStore.class */
    public static class BCPKCS12KeyStore extends AdaptingKeyStoreSpi {
        public BCPKCS12KeyStore() {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$BCPKCS12KeyStore3DES.class */
    public static class BCPKCS12KeyStore3DES extends AdaptingKeyStoreSpi {
        public BCPKCS12KeyStore3DES() {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$CertId.class */
    public class CertId {

        /* renamed from: id */
        byte[] f612id;

        CertId(PublicKey publicKey) {
            this.f612id = PKCS12KeyStoreSpi.this.createSubjectKeyId(publicKey).getKeyIdentifier();
        }

        CertId(byte[] bArr) {
            this.f612id = bArr;
        }

        public int hashCode() {
            return Arrays.hashCode(this.f612id);
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof CertId) {
                return Arrays.areEqual(this.f612id, ((CertId) obj).f612id);
            }
            return false;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$DefPKCS12KeyStore.class */
    public static class DefPKCS12KeyStore extends AdaptingKeyStoreSpi {
        public DefPKCS12KeyStore() {
            super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$DefPKCS12KeyStore3DES.class */
    public static class DefPKCS12KeyStore3DES extends AdaptingKeyStoreSpi {
        public DefPKCS12KeyStore3DES() {
            super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$DefaultSecretKeyProvider.class */
    public static class DefaultSecretKeyProvider {
        private final Map KEY_SIZES;

        DefaultSecretKeyProvider() {
            HashMap hashMap = new HashMap();
            hashMap.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));
            hashMap.put(PKCSObjectIdentifiers.des_EDE3_CBC, Integers.valueOf(192));
            hashMap.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
            hashMap.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
            hashMap.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));
            hashMap.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
            hashMap.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
            hashMap.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));
            hashMap.put(CryptoProObjectIdentifiers.gostR28147_gcfb, Integers.valueOf(256));
            this.KEY_SIZES = Collections.unmodifiableMap(hashMap);
        }

        public int getKeySize(AlgorithmIdentifier algorithmIdentifier) {
            Integer num = (Integer) this.KEY_SIZES.get(algorithmIdentifier.getAlgorithm());
            if (num != null) {
                return num.intValue();
            }
            return -1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/keystore/pkcs12/PKCS12KeyStoreSpi$IgnoresCaseHashtable.class */
    public static class IgnoresCaseHashtable {
        private Hashtable orig;
        private Hashtable keys;

        private IgnoresCaseHashtable() {
            this.orig = new Hashtable();
            this.keys = new Hashtable();
        }

        public void put(String str, Object obj) {
            String lowerCase = str == null ? null : Strings.toLowerCase(str);
            String str2 = (String) this.keys.get(lowerCase);
            if (str2 != null) {
                this.orig.remove(str2);
            }
            this.keys.put(lowerCase, str);
            this.orig.put(str, obj);
        }

        public Enumeration keys() {
            return this.orig.keys();
        }

        public Object remove(String str) {
            String str2 = (String) this.keys.remove(str == null ? null : Strings.toLowerCase(str));
            if (str2 == null) {
                return null;
            }
            return this.orig.remove(str2);
        }

        public Object get(String str) {
            String str2 = (String) this.keys.get(str == null ? null : Strings.toLowerCase(str));
            if (str2 == null) {
                return null;
            }
            return this.orig.get(str2);
        }

        public Enumeration elements() {
            return this.orig.elements();
        }

        public int size() {
            return this.orig.size();
        }
    }

    public PKCS12KeyStoreSpi(JcaJceHelper jcaJceHelper, ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1ObjectIdentifier aSN1ObjectIdentifier2) {
        this.keyAlgorithm = aSN1ObjectIdentifier;
        this.certAlgorithm = aSN1ObjectIdentifier2;
        try {
            this.certFact = jcaJceHelper.createCertificateFactory("X.509");
        } catch (Exception e) {
            throw new IllegalArgumentException("can't create cert factory - " + e.toString());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey) {
        try {
            return new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())));
        } catch (Exception e) {
            throw new RuntimeException("error creating key");
        }
    }

    private static byte[] getDigest(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        Digest createSHA1 = DigestFactory.createSHA1();
        byte[] bArr = new byte[createSHA1.getDigestSize()];
        byte[] bytes = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        createSHA1.update(bytes, 0, bytes.length);
        createSHA1.doFinal(bArr, 0);
        return bArr;
    }

    @Override // org.bouncycastle.jce.interfaces.BCKeyStore
    public void setRandom(SecureRandom secureRandom) {
        this.random = secureRandom;
    }

    public boolean engineProbe(InputStream inputStream) throws IOException {
        return false;
    }

    @Override // java.security.KeyStoreSpi
    public Enumeration engineAliases() {
        Hashtable hashtable = new Hashtable();
        Enumeration keys = this.certs.keys();
        while (keys.hasMoreElements()) {
            hashtable.put(keys.nextElement(), "cert");
        }
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            String str = (String) keys2.nextElement();
            if (hashtable.get(str) == null) {
                hashtable.put(str, "key");
            }
        }
        return hashtable.keys();
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineContainsAlias(String str) {
        return (this.certs.get(str) == null && this.keys.get(str) == null) ? false : true;
    }

    @Override // java.security.KeyStoreSpi
    public void engineDeleteEntry(String str) throws KeyStoreException {
        Key key = (Key) this.keys.remove(str);
        Certificate certificate = (Certificate) this.certs.remove(str);
        if (certificate != null) {
            this.chainCerts.remove(new CertId(certificate.getPublicKey()));
        }
        if (key != null) {
            String str2 = (String) this.localIds.remove(str);
            if (str2 != null) {
                certificate = (Certificate) this.keyCerts.remove(str2);
            }
            if (certificate != null) {
                this.chainCerts.remove(new CertId(certificate.getPublicKey()));
            }
        }
    }

    @Override // java.security.KeyStoreSpi
    public Certificate engineGetCertificate(String str) {
        if (str == null) {
            throw new IllegalArgumentException("null alias passed to getCertificate.");
        }
        Certificate certificate = (Certificate) this.certs.get(str);
        if (certificate == null) {
            String str2 = (String) this.localIds.get(str);
            certificate = str2 != null ? (Certificate) this.keyCerts.get(str2) : (Certificate) this.keyCerts.get(str);
        }
        return certificate;
    }

    @Override // java.security.KeyStoreSpi
    public String engineGetCertificateAlias(Certificate certificate) {
        Enumeration elements = this.certs.elements();
        Enumeration keys = this.certs.keys();
        while (elements.hasMoreElements()) {
            Certificate certificate2 = (Certificate) elements.nextElement();
            String str = (String) keys.nextElement();
            if (certificate2.equals(certificate)) {
                return str;
            }
        }
        Enumeration elements2 = this.keyCerts.elements();
        Enumeration keys2 = this.keyCerts.keys();
        while (elements2.hasMoreElements()) {
            Certificate certificate3 = (Certificate) elements2.nextElement();
            String str2 = (String) keys2.nextElement();
            if (certificate3.equals(certificate)) {
                return str2;
            }
        }
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public Certificate[] engineGetCertificateChain(String str) {
        byte[] keyIdentifier;
        if (str == null) {
            throw new IllegalArgumentException("null alias passed to getCertificateChain.");
        }
        if (engineIsKeyEntry(str)) {
            X509Certificate engineGetCertificate = engineGetCertificate(str);
            if (engineGetCertificate != null) {
                Vector vector = new Vector();
                while (engineGetCertificate != null) {
                    X509Certificate x509Certificate = (X509Certificate) engineGetCertificate;
                    X509Certificate x509Certificate2 = null;
                    byte[] extensionValue = x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                    if (extensionValue != null && null != (keyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(extensionValue).getOctets()).getKeyIdentifier())) {
                        x509Certificate2 = (Certificate) this.chainCerts.get(new CertId(keyIdentifier));
                    }
                    if (x509Certificate2 == null) {
                        Principal issuerDN = x509Certificate.getIssuerDN();
                        if (!issuerDN.equals(x509Certificate.getSubjectDN())) {
                            Enumeration keys = this.chainCerts.keys();
                            while (keys.hasMoreElements()) {
                                X509Certificate x509Certificate3 = (X509Certificate) this.chainCerts.get(keys.nextElement());
                                if (x509Certificate3.getSubjectDN().equals(issuerDN)) {
                                    try {
                                        x509Certificate.verify(x509Certificate3.getPublicKey());
                                        x509Certificate2 = x509Certificate3;
                                        break;
                                    } catch (Exception e) {
                                    }
                                }
                            }
                        }
                    }
                    if (vector.contains(engineGetCertificate)) {
                        engineGetCertificate = null;
                    } else {
                        vector.addElement(engineGetCertificate);
                        engineGetCertificate = x509Certificate2 != engineGetCertificate ? x509Certificate2 : null;
                    }
                }
                Certificate[] certificateArr = new Certificate[vector.size()];
                for (int i = 0; i != certificateArr.length; i++) {
                    certificateArr[i] = (Certificate) vector.elementAt(i);
                }
                return certificateArr;
            }
            return null;
        }
        return null;
    }

    @Override // java.security.KeyStoreSpi
    public Date engineGetCreationDate(String str) {
        if (str == null) {
            throw new NullPointerException("alias == null");
        }
        if (this.keys.get(str) == null && this.certs.get(str) == null) {
            return null;
        }
        return new Date();
    }

    @Override // java.security.KeyStoreSpi
    public Key engineGetKey(String str, char[] cArr) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (str == null) {
            throw new IllegalArgumentException("null alias passed to getKey.");
        }
        return (Key) this.keys.get(str);
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineIsCertificateEntry(String str) {
        return this.certs.get(str) != null && this.keys.get(str) == null;
    }

    @Override // java.security.KeyStoreSpi
    public boolean engineIsKeyEntry(String str) {
        return this.keys.get(str) != null;
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetCertificateEntry(String str, Certificate certificate) throws KeyStoreException {
        if (this.keys.get(str) != null) {
            throw new KeyStoreException("There is a key entry with the name " + str + ".");
        }
        this.certs.put(str, certificate);
        this.chainCerts.put(new CertId(certificate.getPublicKey()), certificate);
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String str, byte[] bArr, Certificate[] certificateArr) throws KeyStoreException {
        throw new RuntimeException("operation not supported");
    }

    @Override // java.security.KeyStoreSpi
    public void engineSetKeyEntry(String str, Key key, char[] cArr, Certificate[] certificateArr) throws KeyStoreException {
        if (!(key instanceof PrivateKey)) {
            throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
        }
        if ((key instanceof PrivateKey) && certificateArr == null) {
            throw new KeyStoreException("no certificate chain for private key");
        }
        if (this.keys.get(str) != null) {
            engineDeleteEntry(str);
        }
        this.keys.put(str, key);
        if (certificateArr != null) {
            this.certs.put(str, certificateArr[0]);
            for (int i = 0; i != certificateArr.length; i++) {
                this.chainCerts.put(new CertId(certificateArr[i].getPublicKey()), certificateArr[i]);
            }
        }
    }

    @Override // java.security.KeyStoreSpi
    public int engineSize() {
        Hashtable hashtable = new Hashtable();
        Enumeration keys = this.certs.keys();
        while (keys.hasMoreElements()) {
            hashtable.put(keys.nextElement(), "cert");
        }
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            String str = (String) keys2.nextElement();
            if (hashtable.get(str) == null) {
                hashtable.put(str, "key");
            }
        }
        return hashtable.size();
    }

    protected PrivateKey unwrapKey(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, char[] cArr, boolean z) throws IOException {
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        try {
            if (!algorithm.m125on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
                if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.id_PBES2)) {
                    return (PrivateKey) createCipher(4, cArr, algorithmIdentifier).unwrap(bArr, "", 2);
                }
                throw new IOException("exception unwrapping private key - cannot recognise: " + algorithm);
            }
            PKCS12PBEParams pKCS12PBEParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
            PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), validateIterationCount(pKCS12PBEParams.getIterations()));
            Cipher createCipher = this.helper.createCipher(algorithm.getId());
            createCipher.init(4, new PKCS12Key(cArr, z), pBEParameterSpec);
            return (PrivateKey) createCipher.unwrap(bArr, "", 2);
        } catch (Exception e) {
            throw new IOException("exception unwrapping private key - " + e.toString());
        }
    }

    protected byte[] wrapKey(String str, Key key, PKCS12PBEParams pKCS12PBEParams, char[] cArr) throws IOException {
        PBEKeySpec pBEKeySpec = new PBEKeySpec(cArr);
        try {
            SecretKeyFactory createSecretKeyFactory = this.helper.createSecretKeyFactory(str);
            PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), pKCS12PBEParams.getIterations().intValue());
            Cipher createCipher = this.helper.createCipher(str);
            createCipher.init(3, createSecretKeyFactory.generateSecret(pBEKeySpec), pBEParameterSpec);
            return createCipher.wrap(key);
        } catch (Exception e) {
            throw new IOException("exception encrypting data - " + e.toString());
        }
    }

    protected byte[] cryptData(boolean z, AlgorithmIdentifier algorithmIdentifier, char[] cArr, boolean z2, byte[] bArr) throws IOException {
        ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();
        int i = z ? 1 : 2;
        if (!algorithm.m125on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
            if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.id_PBES2)) {
                try {
                    return createCipher(i, cArr, algorithmIdentifier).doFinal(bArr);
                } catch (Exception e) {
                    throw new IOException("exception decrypting data - " + e.toString());
                }
            }
            throw new IOException("unknown PBE algorithm: " + algorithm);
        }
        PKCS12PBEParams pKCS12PBEParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());
        try {
            PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), pKCS12PBEParams.getIterations().intValue());
            PKCS12Key pKCS12Key = new PKCS12Key(cArr, z2);
            Cipher createCipher = this.helper.createCipher(algorithm.getId());
            createCipher.init(i, pKCS12Key, pBEParameterSpec);
            return createCipher.doFinal(bArr);
        } catch (Exception e2) {
            throw new IOException("exception decrypting data - " + e2.toString());
        }
    }

    private Cipher createCipher(int i, char[] cArr, AlgorithmIdentifier algorithmIdentifier) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        PBES2Parameters pBES2Parameters = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());
        PBKDF2Params pBKDF2Params = PBKDF2Params.getInstance(pBES2Parameters.getKeyDerivationFunc().getParameters());
        AlgorithmIdentifier algorithmIdentifier2 = AlgorithmIdentifier.getInstance(pBES2Parameters.getEncryptionScheme());
        SecretKeyFactory createSecretKeyFactory = this.helper.createSecretKeyFactory(pBES2Parameters.getKeyDerivationFunc().getAlgorithm().getId());
        SecretKey generateSecret = pBKDF2Params.isDefaultPrf() ? createSecretKeyFactory.generateSecret(new PBEKeySpec(cArr, pBKDF2Params.getSalt(), validateIterationCount(pBKDF2Params.getIterationCount()), keySizeProvider.getKeySize(algorithmIdentifier2))) : createSecretKeyFactory.generateSecret(new PBKDF2KeySpec(cArr, pBKDF2Params.getSalt(), validateIterationCount(pBKDF2Params.getIterationCount()), keySizeProvider.getKeySize(algorithmIdentifier2), pBKDF2Params.getPrf()));
        Cipher createCipher = this.helper.createCipher(pBES2Parameters.getEncryptionScheme().getAlgorithm().getId());
        ASN1Encodable parameters = pBES2Parameters.getEncryptionScheme().getParameters();
        if (parameters instanceof ASN1OctetString) {
            createCipher.init(i, generateSecret, new IvParameterSpec(ASN1OctetString.getInstance(parameters).getOctets()));
        } else {
            GOST28147Parameters gOST28147Parameters = GOST28147Parameters.getInstance(parameters);
            createCipher.init(i, generateSecret, new GOST28147ParameterSpec(gOST28147Parameters.getEncryptionParamSet(), gOST28147Parameters.getIV()));
        }
        return createCipher;
    }

    @Override // java.security.KeyStoreSpi
    public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (loadStoreParameter == null) {
            engineLoad(null, null);
        } else if (!(loadStoreParameter instanceof BCLoadStoreParameter)) {
            throw new IllegalArgumentException("no support for 'param' of type " + loadStoreParameter.getClass().getName());
        } else {
            engineLoad(((BCLoadStoreParameter) loadStoreParameter).getInputStream(), ParameterUtil.extractPassword(loadStoreParameter));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v274, types: [org.bouncycastle.asn1.ASN1Primitive] */
    /* JADX WARN: Type inference failed for: r0v354, types: [org.bouncycastle.asn1.ASN1Primitive] */
    @Override // java.security.KeyStoreSpi
    public void engineLoad(InputStream inputStream, char[] cArr) throws IOException {
        if (inputStream == null) {
            return;
        }
        BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        bufferedInputStream.mark(10);
        int read = bufferedInputStream.read();
        if (read < 0) {
            throw new EOFException("no data in keystore stream");
        }
        if (read != 48) {
            throw new IOException("stream does not represent a PKCS12 key store");
        }
        bufferedInputStream.reset();
        try {
            Pfx pfx = Pfx.getInstance(new ASN1InputStream(bufferedInputStream).readObject());
            ContentInfo authSafe = pfx.getAuthSafe();
            Vector vector = new Vector();
            boolean z = false;
            boolean z2 = false;
            if (pfx.getMacData() != null) {
                if (cArr == null) {
                    throw new NullPointerException("no password supplied when one expected");
                }
                MacData macData = pfx.getMacData();
                DigestInfo mac = macData.getMac();
                this.macAlgorithm = mac.getAlgorithmId();
                byte[] salt = macData.getSalt();
                this.itCount = validateIterationCount(macData.getIterationCount());
                this.saltLength = salt.length;
                byte[] octets = ((ASN1OctetString) authSafe.getContent()).getOctets();
                try {
                    byte[] calculatePbeMac = calculatePbeMac(this.macAlgorithm.getAlgorithm(), salt, this.itCount, cArr, false, octets);
                    byte[] digest = mac.getDigest();
                    if (!Arrays.constantTimeAreEqual(calculatePbeMac, digest)) {
                        if (cArr.length > 0) {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }
                        if (!Arrays.constantTimeAreEqual(calculatePbeMac(this.macAlgorithm.getAlgorithm(), salt, this.itCount, cArr, true, octets), digest)) {
                            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                        }
                        z2 = true;
                    }
                } catch (IOException e) {
                    throw e;
                } catch (Exception e2) {
                    throw new IOException("error constructing MAC: " + e2.toString());
                }
            } else if (cArr != null && cArr.length != 0 && !Properties.isOverrideSet("org.bouncycastle.pkcs12.ignore_useless_passwd")) {
                throw new IOException("password supplied for keystore that does not require one");
            }
            this.keys = new IgnoresCaseHashtable();
            this.localIds = new IgnoresCaseHashtable();
            if (authSafe.getContentType().equals((ASN1Primitive) data)) {
                ContentInfo[] contentInfo = AuthenticatedSafe.getInstance(ASN1OctetString.getInstance(authSafe.getContent()).getOctets()).getContentInfo();
                for (int i = 0; i != contentInfo.length; i++) {
                    if (contentInfo[i].getContentType().equals((ASN1Primitive) data)) {
                        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(ASN1OctetString.getInstance(contentInfo[i].getContent()).getOctets());
                        for (int i2 = 0; i2 != aSN1Sequence.size(); i2++) {
                            SafeBag safeBag = SafeBag.getInstance(aSN1Sequence.getObjectAt(i2));
                            if (safeBag.getBagId().equals((ASN1Primitive) pkcs8ShroudedKeyBag)) {
                                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue());
                                PrivateKey unwrapKey = unwrapKey(encryptedPrivateKeyInfo.getEncryptionAlgorithm(), encryptedPrivateKeyInfo.getEncryptedData(), cArr, z2);
                                String str = null;
                                ASN1OctetString aSN1OctetString = null;
                                if (safeBag.getBagAttributes() != null) {
                                    Enumeration objects = safeBag.getBagAttributes().getObjects();
                                    while (objects.hasMoreElements()) {
                                        ASN1Sequence aSN1Sequence2 = (ASN1Sequence) objects.nextElement();
                                        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) aSN1Sequence2.getObjectAt(0);
                                        ASN1Set aSN1Set = (ASN1Set) aSN1Sequence2.getObjectAt(1);
                                        ASN1OctetString aSN1OctetString2 = null;
                                        if (aSN1Set.size() > 0) {
                                            aSN1OctetString2 = (ASN1Primitive) aSN1Set.getObjectAt(0);
                                            if (unwrapKey instanceof PKCS12BagAttributeCarrier) {
                                                PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) unwrapKey;
                                                ASN1Encodable bagAttribute = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                                                if (bagAttribute == null) {
                                                    pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1OctetString2);
                                                } else if (!bagAttribute.toASN1Primitive().equals((ASN1Primitive) aSN1OctetString2)) {
                                                    throw new IOException("attempt to add existing attribute with different value");
                                                }
                                            }
                                        }
                                        if (aSN1ObjectIdentifier.equals((ASN1Primitive) pkcs_9_at_friendlyName)) {
                                            str = aSN1OctetString2.getString();
                                            this.keys.put(str, unwrapKey);
                                        } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) pkcs_9_at_localKeyId)) {
                                            aSN1OctetString = aSN1OctetString2;
                                        }
                                    }
                                }
                                if (aSN1OctetString != null) {
                                    String str2 = new String(Hex.encode(aSN1OctetString.getOctets()));
                                    if (str == null) {
                                        this.keys.put(str2, unwrapKey);
                                    } else {
                                        this.localIds.put(str, str2);
                                    }
                                } else {
                                    z = true;
                                    this.keys.put("unmarked", unwrapKey);
                                }
                            } else if (safeBag.getBagId().equals((ASN1Primitive) certBag)) {
                                vector.addElement(safeBag);
                            } else {
                                System.out.println("extra in data " + safeBag.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(safeBag));
                            }
                        }
                        continue;
                    } else if (contentInfo[i].getContentType().equals((ASN1Primitive) encryptedData)) {
                        EncryptedData encryptedData = EncryptedData.getInstance(contentInfo[i].getContent());
                        ASN1Sequence aSN1Sequence3 = ASN1Sequence.getInstance(cryptData(false, encryptedData.getEncryptionAlgorithm(), cArr, z2, encryptedData.getContent().getOctets()));
                        for (int i3 = 0; i3 != aSN1Sequence3.size(); i3++) {
                            SafeBag safeBag2 = SafeBag.getInstance(aSN1Sequence3.getObjectAt(i3));
                            if (safeBag2.getBagId().equals((ASN1Primitive) certBag)) {
                                vector.addElement(safeBag2);
                            } else if (safeBag2.getBagId().equals((ASN1Primitive) pkcs8ShroudedKeyBag)) {
                                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo2 = EncryptedPrivateKeyInfo.getInstance(safeBag2.getBagValue());
                                PrivateKey unwrapKey2 = unwrapKey(encryptedPrivateKeyInfo2.getEncryptionAlgorithm(), encryptedPrivateKeyInfo2.getEncryptedData(), cArr, z2);
                                PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier2 = (PKCS12BagAttributeCarrier) unwrapKey2;
                                String str3 = null;
                                ASN1OctetString aSN1OctetString3 = null;
                                Enumeration objects2 = safeBag2.getBagAttributes().getObjects();
                                while (objects2.hasMoreElements()) {
                                    ASN1Sequence aSN1Sequence4 = (ASN1Sequence) objects2.nextElement();
                                    ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) aSN1Sequence4.getObjectAt(0);
                                    ASN1Set aSN1Set2 = (ASN1Set) aSN1Sequence4.getObjectAt(1);
                                    ASN1OctetString aSN1OctetString4 = null;
                                    if (aSN1Set2.size() > 0) {
                                        aSN1OctetString4 = (ASN1Primitive) aSN1Set2.getObjectAt(0);
                                        ASN1Encodable bagAttribute2 = pKCS12BagAttributeCarrier2.getBagAttribute(aSN1ObjectIdentifier2);
                                        if (bagAttribute2 == null) {
                                            pKCS12BagAttributeCarrier2.setBagAttribute(aSN1ObjectIdentifier2, aSN1OctetString4);
                                        } else if (!bagAttribute2.toASN1Primitive().equals((ASN1Primitive) aSN1OctetString4)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    }
                                    if (aSN1ObjectIdentifier2.equals((ASN1Primitive) pkcs_9_at_friendlyName)) {
                                        str3 = aSN1OctetString4.getString();
                                        this.keys.put(str3, unwrapKey2);
                                    } else if (aSN1ObjectIdentifier2.equals((ASN1Primitive) pkcs_9_at_localKeyId)) {
                                        aSN1OctetString3 = aSN1OctetString4;
                                    }
                                }
                                String str4 = new String(Hex.encode(aSN1OctetString3.getOctets()));
                                if (str3 == null) {
                                    this.keys.put(str4, unwrapKey2);
                                } else {
                                    this.localIds.put(str3, str4);
                                }
                            } else if (safeBag2.getBagId().equals((ASN1Primitive) keyBag)) {
                                PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(safeBag2.getBagValue()));
                                PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier3 = (PKCS12BagAttributeCarrier) privateKey;
                                String str5 = null;
                                ASN1OctetString aSN1OctetString5 = null;
                                Enumeration objects3 = safeBag2.getBagAttributes().getObjects();
                                while (objects3.hasMoreElements()) {
                                    ASN1Sequence aSN1Sequence5 = ASN1Sequence.getInstance(objects3.nextElement());
                                    ASN1ObjectIdentifier aSN1ObjectIdentifier3 = ASN1ObjectIdentifier.getInstance(aSN1Sequence5.getObjectAt(0));
                                    ASN1Set aSN1Set3 = ASN1Set.getInstance(aSN1Sequence5.getObjectAt(1));
                                    if (aSN1Set3.size() > 0) {
                                        ASN1Primitive aSN1Primitive = (ASN1Primitive) aSN1Set3.getObjectAt(0);
                                        ASN1Encodable bagAttribute3 = pKCS12BagAttributeCarrier3.getBagAttribute(aSN1ObjectIdentifier3);
                                        if (bagAttribute3 == null) {
                                            pKCS12BagAttributeCarrier3.setBagAttribute(aSN1ObjectIdentifier3, aSN1Primitive);
                                        } else if (!bagAttribute3.toASN1Primitive().equals(aSN1Primitive)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                        if (aSN1ObjectIdentifier3.equals((ASN1Primitive) pkcs_9_at_friendlyName)) {
                                            str5 = ((ASN1BMPString) aSN1Primitive).getString();
                                            this.keys.put(str5, privateKey);
                                        } else if (aSN1ObjectIdentifier3.equals((ASN1Primitive) pkcs_9_at_localKeyId)) {
                                            aSN1OctetString5 = (ASN1OctetString) aSN1Primitive;
                                        }
                                    }
                                }
                                String str6 = new String(Hex.encode(aSN1OctetString5.getOctets()));
                                if (str5 == null) {
                                    this.keys.put(str6, privateKey);
                                } else {
                                    this.localIds.put(str5, str6);
                                }
                            } else {
                                System.out.println("extra in encryptedData " + safeBag2.getBagId());
                                System.out.println(ASN1Dump.dumpAsString(safeBag2));
                            }
                        }
                        continue;
                    } else {
                        System.out.println("extra " + contentInfo[i].getContentType().getId());
                        System.out.println("extra " + ASN1Dump.dumpAsString(contentInfo[i].getContent()));
                    }
                }
            }
            this.certs = new IgnoresCaseHashtable();
            this.chainCerts = new Hashtable();
            this.keyCerts = new Hashtable();
            for (int i4 = 0; i4 != vector.size(); i4++) {
                SafeBag safeBag3 = (SafeBag) vector.elementAt(i4);
                CertBag certBag = CertBag.getInstance(safeBag3.getBagValue());
                if (!certBag.getCertId().equals((ASN1Primitive) x509Certificate)) {
                    throw new RuntimeException("Unsupported certificate type: " + certBag.getCertId());
                }
                try {
                    Certificate generateCertificate = this.certFact.generateCertificate(new ByteArrayInputStream(((ASN1OctetString) certBag.getCertValue()).getOctets()));
                    ASN1OctetString aSN1OctetString6 = null;
                    String str7 = null;
                    if (safeBag3.getBagAttributes() != null) {
                        Enumeration objects4 = safeBag3.getBagAttributes().getObjects();
                        while (objects4.hasMoreElements()) {
                            ASN1Sequence aSN1Sequence6 = ASN1Sequence.getInstance(objects4.nextElement());
                            ASN1ObjectIdentifier aSN1ObjectIdentifier4 = ASN1ObjectIdentifier.getInstance(aSN1Sequence6.getObjectAt(0));
                            ASN1Set aSN1Set4 = ASN1Set.getInstance(aSN1Sequence6.getObjectAt(1));
                            if (aSN1Set4.size() > 0) {
                                ASN1Primitive aSN1Primitive2 = (ASN1Primitive) aSN1Set4.getObjectAt(0);
                                if (generateCertificate instanceof PKCS12BagAttributeCarrier) {
                                    PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier4 = (PKCS12BagAttributeCarrier) generateCertificate;
                                    ASN1Encodable bagAttribute4 = pKCS12BagAttributeCarrier4.getBagAttribute(aSN1ObjectIdentifier4);
                                    if (bagAttribute4 != null) {
                                        if (aSN1ObjectIdentifier4.equals((ASN1Primitive) pkcs_9_at_localKeyId)) {
                                            String hexString = Hex.toHexString(((ASN1OctetString) aSN1Primitive2).getOctets());
                                            if (!this.keys.keys.containsKey(hexString) && !this.localIds.keys.containsKey(hexString)) {
                                            }
                                        }
                                        if (!bagAttribute4.toASN1Primitive().equals(aSN1Primitive2)) {
                                            throw new IOException("attempt to add existing attribute with different value");
                                        }
                                    } else {
                                        pKCS12BagAttributeCarrier4.setBagAttribute(aSN1ObjectIdentifier4, aSN1Primitive2);
                                    }
                                }
                                if (aSN1ObjectIdentifier4.equals((ASN1Primitive) pkcs_9_at_friendlyName)) {
                                    str7 = ((ASN1BMPString) aSN1Primitive2).getString();
                                } else if (aSN1ObjectIdentifier4.equals((ASN1Primitive) pkcs_9_at_localKeyId)) {
                                    aSN1OctetString6 = (ASN1OctetString) aSN1Primitive2;
                                }
                            }
                        }
                    }
                    this.chainCerts.put(new CertId(generateCertificate.getPublicKey()), generateCertificate);
                    if (!z) {
                        if (aSN1OctetString6 != null) {
                            this.keyCerts.put(new String(Hex.encode(aSN1OctetString6.getOctets())), generateCertificate);
                        }
                        if (str7 != null) {
                            this.certs.put(str7, generateCertificate);
                        }
                    } else if (this.keyCerts.isEmpty()) {
                        String str8 = new String(Hex.encode(createSubjectKeyId(generateCertificate.getPublicKey()).getKeyIdentifier()));
                        this.keyCerts.put(str8, generateCertificate);
                        this.keys.put(str8, this.keys.remove("unmarked"));
                    }
                } catch (Exception e3) {
                    throw new RuntimeException(e3.toString());
                }
            }
        } catch (Exception e4) {
            throw new IOException(e4.getMessage());
        }
    }

    private int validateIterationCount(BigInteger bigInteger) {
        int intValue = bigInteger.intValue();
        if (intValue < 0) {
            throw new IllegalStateException("negative iteration count found");
        }
        BigInteger asBigInteger = Properties.asBigInteger(PKCS12_MAX_IT_COUNT_PROPERTY);
        if (asBigInteger == null || asBigInteger.intValue() >= intValue) {
            return intValue;
        }
        throw new IllegalStateException("iteration count " + intValue + " greater than " + asBigInteger.intValue());
    }

    @Override // java.security.KeyStoreSpi
    public void engineStore(KeyStore.LoadStoreParameter loadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
        char[] password;
        if (loadStoreParameter == null) {
            throw new IllegalArgumentException("'param' arg cannot be null");
        }
        if (!(loadStoreParameter instanceof PKCS12StoreParameter) && !(loadStoreParameter instanceof JDKPKCS12StoreParameter)) {
            throw new IllegalArgumentException("No support for 'param' of type " + loadStoreParameter.getClass().getName());
        }
        PKCS12StoreParameter pKCS12StoreParameter = loadStoreParameter instanceof PKCS12StoreParameter ? (PKCS12StoreParameter) loadStoreParameter : new PKCS12StoreParameter(((JDKPKCS12StoreParameter) loadStoreParameter).getOutputStream(), loadStoreParameter.getProtectionParameter(), ((JDKPKCS12StoreParameter) loadStoreParameter).isUseDEREncoding());
        KeyStore.ProtectionParameter protectionParameter = loadStoreParameter.getProtectionParameter();
        if (protectionParameter == null) {
            password = null;
        } else if (!(protectionParameter instanceof KeyStore.PasswordProtection)) {
            throw new IllegalArgumentException("No support for protection parameter of type " + protectionParameter.getClass().getName());
        } else {
            password = ((KeyStore.PasswordProtection) protectionParameter).getPassword();
        }
        doStore(pKCS12StoreParameter.getOutputStream(), password, pKCS12StoreParameter.isForDEREncoding());
    }

    @Override // java.security.KeyStoreSpi
    public void engineStore(OutputStream outputStream, char[] cArr) throws IOException {
        doStore(outputStream, cArr, false);
    }

    private void doStore(OutputStream outputStream, char[] cArr, boolean z) throws IOException {
        if (this.keys.size() == 0) {
            if (cArr == null) {
                Enumeration keys = this.certs.keys();
                ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
                while (keys.hasMoreElements()) {
                    try {
                        String str = (String) keys.nextElement();
                        aSN1EncodableVector.add(createSafeBag(str, (Certificate) this.certs.get(str)));
                    } catch (CertificateEncodingException e) {
                        throw new IOException("Error encoding certificate: " + e.toString());
                    }
                }
                if (z) {
                    new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new DERSequence(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new DERSequence(aSN1EncodableVector).getEncoded()))).getEncoded())), null).encodeTo(outputStream, ASN1Encoding.DER);
                    return;
                } else {
                    new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString(new BERSequence(new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString(new BERSequence(aSN1EncodableVector).getEncoded()))).getEncoded())), null).encodeTo(outputStream, ASN1Encoding.BER);
                    return;
                }
            }
        } else if (cArr == null) {
            throw new NullPointerException("no password supplied for PKCS#12 KeyStore");
        }
        ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
        Enumeration keys2 = this.keys.keys();
        while (keys2.hasMoreElements()) {
            byte[] bArr = new byte[20];
            this.random.nextBytes(bArr);
            String str2 = (String) keys2.nextElement();
            PrivateKey privateKey = (PrivateKey) this.keys.get(str2);
            PKCS12PBEParams pKCS12PBEParams = new PKCS12PBEParams(bArr, MIN_ITERATIONS);
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(this.keyAlgorithm, pKCS12PBEParams.toASN1Primitive()), wrapKey(this.keyAlgorithm.getId(), privateKey, pKCS12PBEParams, cArr));
            boolean z2 = false;
            ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
            if (privateKey instanceof PKCS12BagAttributeCarrier) {
                PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) privateKey;
                ASN1BMPString aSN1BMPString = (ASN1BMPString) pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
                if (aSN1BMPString == null || !aSN1BMPString.getString().equals(str2)) {
                    pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str2));
                }
                if (pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                    pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(engineGetCertificate(str2).getPublicKey()));
                }
                Enumeration bagAttributeKeys = pKCS12BagAttributeCarrier.getBagAttributeKeys();
                while (bagAttributeKeys.hasMoreElements()) {
                    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) bagAttributeKeys.nextElement();
                    ASN1EncodableVector aSN1EncodableVector4 = new ASN1EncodableVector();
                    aSN1EncodableVector4.add(aSN1ObjectIdentifier);
                    aSN1EncodableVector4.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
                    z2 = true;
                    aSN1EncodableVector3.add(new DERSequence(aSN1EncodableVector4));
                }
            }
            if (!z2) {
                ASN1EncodableVector aSN1EncodableVector5 = new ASN1EncodableVector();
                Certificate engineGetCertificate = engineGetCertificate(str2);
                aSN1EncodableVector5.add(pkcs_9_at_localKeyId);
                aSN1EncodableVector5.add(new DERSet(createSubjectKeyId(engineGetCertificate.getPublicKey())));
                aSN1EncodableVector3.add(new DERSequence(aSN1EncodableVector5));
                ASN1EncodableVector aSN1EncodableVector6 = new ASN1EncodableVector();
                aSN1EncodableVector6.add(pkcs_9_at_friendlyName);
                aSN1EncodableVector6.add(new DERSet(new DERBMPString(str2)));
                aSN1EncodableVector3.add(new DERSequence(aSN1EncodableVector6));
            }
            aSN1EncodableVector2.add(new SafeBag(pkcs8ShroudedKeyBag, encryptedPrivateKeyInfo.toASN1Primitive(), new DERSet(aSN1EncodableVector3)));
        }
        BEROctetString bEROctetString = new BEROctetString(new DERSequence(aSN1EncodableVector2).getEncoded(ASN1Encoding.DER));
        byte[] bArr2 = new byte[20];
        this.random.nextBytes(bArr2);
        ASN1EncodableVector aSN1EncodableVector7 = new ASN1EncodableVector();
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(this.certAlgorithm, new PKCS12PBEParams(bArr2, MIN_ITERATIONS).toASN1Primitive());
        Hashtable hashtable = new Hashtable();
        Enumeration keys3 = this.keys.keys();
        while (keys3.hasMoreElements()) {
            try {
                String str3 = (String) keys3.nextElement();
                Certificate engineGetCertificate2 = engineGetCertificate(str3);
                boolean z3 = false;
                CertBag certBag = new CertBag(x509Certificate, new DEROctetString(engineGetCertificate2.getEncoded()));
                ASN1EncodableVector aSN1EncodableVector8 = new ASN1EncodableVector();
                if (engineGetCertificate2 instanceof PKCS12BagAttributeCarrier) {
                    PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier2 = (PKCS12BagAttributeCarrier) engineGetCertificate2;
                    ASN1BMPString aSN1BMPString2 = (ASN1BMPString) pKCS12BagAttributeCarrier2.getBagAttribute(pkcs_9_at_friendlyName);
                    if (aSN1BMPString2 == null || !aSN1BMPString2.getString().equals(str3)) {
                        pKCS12BagAttributeCarrier2.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str3));
                    }
                    if (pKCS12BagAttributeCarrier2.getBagAttribute(pkcs_9_at_localKeyId) == null) {
                        pKCS12BagAttributeCarrier2.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(engineGetCertificate2.getPublicKey()));
                    }
                    Enumeration bagAttributeKeys2 = pKCS12BagAttributeCarrier2.getBagAttributeKeys();
                    while (bagAttributeKeys2.hasMoreElements()) {
                        ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) bagAttributeKeys2.nextElement();
                        ASN1EncodableVector aSN1EncodableVector9 = new ASN1EncodableVector();
                        aSN1EncodableVector9.add(aSN1ObjectIdentifier2);
                        aSN1EncodableVector9.add(new DERSet(pKCS12BagAttributeCarrier2.getBagAttribute(aSN1ObjectIdentifier2)));
                        aSN1EncodableVector8.add(new DERSequence(aSN1EncodableVector9));
                        z3 = true;
                    }
                }
                if (!z3) {
                    ASN1EncodableVector aSN1EncodableVector10 = new ASN1EncodableVector();
                    aSN1EncodableVector10.add(pkcs_9_at_localKeyId);
                    aSN1EncodableVector10.add(new DERSet(createSubjectKeyId(engineGetCertificate2.getPublicKey())));
                    aSN1EncodableVector8.add(new DERSequence(aSN1EncodableVector10));
                    ASN1EncodableVector aSN1EncodableVector11 = new ASN1EncodableVector();
                    aSN1EncodableVector11.add(pkcs_9_at_friendlyName);
                    aSN1EncodableVector11.add(new DERSet(new DERBMPString(str3)));
                    aSN1EncodableVector8.add(new DERSequence(aSN1EncodableVector11));
                }
                aSN1EncodableVector7.add(new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector8)));
                hashtable.put(engineGetCertificate2, engineGetCertificate2);
            } catch (CertificateEncodingException e2) {
                throw new IOException("Error encoding certificate: " + e2.toString());
            }
        }
        Enumeration keys4 = this.certs.keys();
        while (keys4.hasMoreElements()) {
            try {
                String str4 = (String) keys4.nextElement();
                Certificate certificate = (Certificate) this.certs.get(str4);
                if (this.keys.get(str4) == null) {
                    aSN1EncodableVector7.add(createSafeBag(str4, certificate));
                    hashtable.put(certificate, certificate);
                }
            } catch (CertificateEncodingException e3) {
                throw new IOException("Error encoding certificate: " + e3.toString());
            }
        }
        Set usedCertificateSet = getUsedCertificateSet();
        Enumeration keys5 = this.chainCerts.keys();
        while (keys5.hasMoreElements()) {
            try {
                Certificate certificate2 = (Certificate) this.chainCerts.get((CertId) keys5.nextElement());
                if (usedCertificateSet.contains(certificate2) && hashtable.get(certificate2) == null) {
                    CertBag certBag2 = new CertBag(x509Certificate, new DEROctetString(certificate2.getEncoded()));
                    ASN1EncodableVector aSN1EncodableVector12 = new ASN1EncodableVector();
                    if (certificate2 instanceof PKCS12BagAttributeCarrier) {
                        PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier3 = (PKCS12BagAttributeCarrier) certificate2;
                        Enumeration bagAttributeKeys3 = pKCS12BagAttributeCarrier3.getBagAttributeKeys();
                        while (bagAttributeKeys3.hasMoreElements()) {
                            ASN1ObjectIdentifier aSN1ObjectIdentifier3 = (ASN1ObjectIdentifier) bagAttributeKeys3.nextElement();
                            if (!aSN1ObjectIdentifier3.equals((ASN1Primitive) PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                                ASN1EncodableVector aSN1EncodableVector13 = new ASN1EncodableVector();
                                aSN1EncodableVector13.add(aSN1ObjectIdentifier3);
                                aSN1EncodableVector13.add(new DERSet(pKCS12BagAttributeCarrier3.getBagAttribute(aSN1ObjectIdentifier3)));
                                aSN1EncodableVector12.add(new DERSequence(aSN1EncodableVector13));
                            }
                        }
                    }
                    aSN1EncodableVector7.add(new SafeBag(certBag, certBag2.toASN1Primitive(), new DERSet(aSN1EncodableVector12)));
                }
            } catch (CertificateEncodingException e4) {
                throw new IOException("Error encoding certificate: " + e4.toString());
            }
        }
        ContentInfo contentInfo = new ContentInfo(data, new BEROctetString(new AuthenticatedSafe(new ContentInfo[]{new ContentInfo(data, bEROctetString), new ContentInfo(encryptedData, new EncryptedData(data, algorithmIdentifier, new BEROctetString(cryptData(true, algorithmIdentifier, cArr, false, new DERSequence(aSN1EncodableVector7).getEncoded(ASN1Encoding.DER)))).toASN1Primitive())}).getEncoded(z ? ASN1Encoding.DER : ASN1Encoding.BER)));
        byte[] bArr3 = new byte[this.saltLength];
        this.random.nextBytes(bArr3);
        try {
            new Pfx(contentInfo, new MacData(new DigestInfo(this.macAlgorithm, calculatePbeMac(this.macAlgorithm.getAlgorithm(), bArr3, this.itCount, cArr, false, ((ASN1OctetString) contentInfo.getContent()).getOctets())), bArr3, this.itCount)).encodeTo(outputStream, z ? ASN1Encoding.DER : ASN1Encoding.BER);
        } catch (Exception e5) {
            throw new IOException("error constructing MAC: " + e5.toString());
        }
    }

    private SafeBag createSafeBag(String str, Certificate certificate) throws CertificateEncodingException {
        CertBag certBag = new CertBag(x509Certificate, new DEROctetString(certificate.getEncoded()));
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        boolean z = false;
        if (certificate instanceof PKCS12BagAttributeCarrier) {
            PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier) certificate;
            ASN1BMPString aSN1BMPString = (ASN1BMPString) pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
            if ((aSN1BMPString == null || !aSN1BMPString.getString().equals(str)) && str != null) {
                pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str));
            }
            Enumeration bagAttributeKeys = pKCS12BagAttributeCarrier.getBagAttributeKeys();
            while (bagAttributeKeys.hasMoreElements()) {
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) bagAttributeKeys.nextElement();
                if (!aSN1ObjectIdentifier.equals((ASN1Primitive) PKCSObjectIdentifiers.pkcs_9_at_localKeyId)) {
                    ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
                    aSN1EncodableVector2.add(aSN1ObjectIdentifier);
                    aSN1EncodableVector2.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
                    aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector2));
                    z = true;
                }
            }
        }
        if (!z) {
            ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
            aSN1EncodableVector3.add(pkcs_9_at_friendlyName);
            aSN1EncodableVector3.add(new DERSet(new DERBMPString(str)));
            aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
        }
        return new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector));
    }

    private Set getUsedCertificateSet() {
        HashSet hashSet = new HashSet();
        Enumeration keys = this.keys.keys();
        while (keys.hasMoreElements()) {
            Certificate[] engineGetCertificateChain = engineGetCertificateChain((String) keys.nextElement());
            for (int i = 0; i != engineGetCertificateChain.length; i++) {
                hashSet.add(engineGetCertificateChain[i]);
            }
        }
        Enumeration keys2 = this.certs.keys();
        while (keys2.hasMoreElements()) {
            hashSet.add(engineGetCertificate((String) keys2.nextElement()));
        }
        return hashSet;
    }

    private byte[] calculatePbeMac(ASN1ObjectIdentifier aSN1ObjectIdentifier, byte[] bArr, int i, char[] cArr, boolean z, byte[] bArr2) throws Exception {
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(bArr, i);
        Mac createMac = this.helper.createMac(aSN1ObjectIdentifier.getId());
        createMac.init(new PKCS12Key(cArr, z), pBEParameterSpec);
        createMac.update(bArr2);
        return createMac.doFinal();
    }
}