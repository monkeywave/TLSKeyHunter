package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.interfaces.DHPublicKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.LegacyTls13Verifier;

/* loaded from: classes2.dex */
public class JcaTlsCertificate implements TlsCertificate {
    protected static final int KU_CRL_SIGN = 6;
    protected static final int KU_DATA_ENCIPHERMENT = 3;
    protected static final int KU_DECIPHER_ONLY = 8;
    protected static final int KU_DIGITAL_SIGNATURE = 0;
    protected static final int KU_ENCIPHER_ONLY = 7;
    protected static final int KU_KEY_AGREEMENT = 4;
    protected static final int KU_KEY_CERT_SIGN = 5;
    protected static final int KU_KEY_ENCIPHERMENT = 2;
    protected static final int KU_NON_REPUDIATION = 1;
    protected final X509Certificate certificate;
    protected final JcaTlsCrypto crypto;
    protected DHPublicKey pubKeyDH;
    protected ECPublicKey pubKeyEC;
    protected PublicKey pubKeyRSA;

    public JcaTlsCertificate(JcaTlsCrypto jcaTlsCrypto, X509Certificate x509Certificate) {
        this.pubKeyDH = null;
        this.pubKeyEC = null;
        this.pubKeyRSA = null;
        this.crypto = jcaTlsCrypto;
        this.certificate = x509Certificate;
    }

    public JcaTlsCertificate(JcaTlsCrypto jcaTlsCrypto, byte[] bArr) throws IOException {
        this(jcaTlsCrypto, parseCertificate(jcaTlsCrypto.getHelper(), bArr));
    }

    public static JcaTlsCertificate convert(JcaTlsCrypto jcaTlsCrypto, TlsCertificate tlsCertificate) throws IOException {
        return tlsCertificate instanceof JcaTlsCertificate ? (JcaTlsCertificate) tlsCertificate : new JcaTlsCertificate(jcaTlsCrypto, tlsCertificate.getEncoded());
    }

    public static X509Certificate parseCertificate(JcaJceHelper jcaJceHelper, byte[] bArr) throws IOException {
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Certificate.getInstance(TlsUtils.readASN1Object(bArr)).getEncoded(ASN1Encoding.DER));
            X509Certificate x509Certificate = (X509Certificate) jcaJceHelper.createCertificateFactory("X.509").generateCertificate(byteArrayInputStream);
            if (byteArrayInputStream.available() == 0) {
                return x509Certificate;
            }
            throw new IOException("Extra data detected in stream");
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("unable to decode certificate", e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsCertificate checkUsageInRole(int i) throws IOException {
        if (i == 1) {
            validateKeyUsageBit(4);
            this.pubKeyDH = getPubKeyDH();
            return this;
        } else if (i == 2) {
            validateKeyUsageBit(4);
            this.pubKeyEC = getPubKeyEC();
            return this;
        } else {
            throw new TlsFatalAlert((short) 46);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsEncryptor createEncryptor(int i) throws IOException {
        validateKeyUsageBit(2);
        if (i == 3) {
            this.pubKeyRSA = getPubKeyRSA();
            return new JcaTlsRSAEncryptor(this.crypto, this.pubKeyRSA);
        }
        throw new TlsFatalAlert((short) 46);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public Tls13Verifier createVerifier(int i) throws IOException {
        validateKeyUsageBit(0);
        if (i != 513) {
            if (i != 515) {
                if (i != 1025) {
                    if (i != 1027) {
                        if (i != 1281) {
                            if (i != 1283) {
                                if (i != 1537) {
                                    if (i != 1539) {
                                        switch (i) {
                                            case SignatureScheme.rsa_pss_rsae_sha256 /* 2052 */:
                                            case SignatureScheme.rsa_pss_rsae_sha384 /* 2053 */:
                                            case SignatureScheme.rsa_pss_rsae_sha512 /* 2054 */:
                                                validateRSA_PSS_RSAE();
                                                int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i);
                                                String digestName = this.crypto.getDigestName(cryptoHashAlgorithm);
                                                return this.crypto.createTls13Verifier(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.crypto.getHelper()), getPubKeyRSA());
                                            case SignatureScheme.ed25519 /* 2055 */:
                                                return this.crypto.createTls13Verifier(EdDSAParameterSpec.Ed25519, null, getPubKeyEd25519());
                                            case SignatureScheme.ed448 /* 2056 */:
                                                return this.crypto.createTls13Verifier(EdDSAParameterSpec.Ed448, null, getPubKeyEd448());
                                            case SignatureScheme.rsa_pss_pss_sha256 /* 2057 */:
                                            case SignatureScheme.rsa_pss_pss_sha384 /* 2058 */:
                                            case SignatureScheme.rsa_pss_pss_sha512 /* 2059 */:
                                                validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(i));
                                                int cryptoHashAlgorithm2 = SignatureScheme.getCryptoHashAlgorithm(i);
                                                String digestName2 = this.crypto.getDigestName(cryptoHashAlgorithm2);
                                                return this.crypto.createTls13Verifier(RSAUtil.getDigestSigAlgName(digestName2) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm2, digestName2, this.crypto.getHelper()), getPubKeyRSA());
                                            default:
                                                switch (i) {
                                                    case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256 /* 2074 */:
                                                    case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384 /* 2075 */:
                                                    case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512 /* 2076 */:
                                                        break;
                                                    default:
                                                        throw new TlsFatalAlert((short) 46);
                                                }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return this.crypto.createTls13Verifier(RSAUtil.getDigestSigAlgName(this.crypto.getDigestName(SignatureScheme.getCryptoHashAlgorithm(i))) + "WITHECDSA", null, getPubKeyEC());
        }
        validateRSA_PKCS1();
        return this.crypto.createTls13Verifier(RSAUtil.getDigestSigAlgName(this.crypto.getDigestName(SignatureScheme.getCryptoHashAlgorithm(i))) + "WITHRSA", null, getPubKeyRSA());
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsVerifier createVerifier(short s) throws IOException {
        if (s == 7 || s == 8) {
            int from = SignatureScheme.from((short) 8, s);
            return new LegacyTls13Verifier(from, createVerifier(from));
        }
        validateKeyUsageBit(0);
        switch (s) {
            case 1:
                validateRSA_PKCS1();
                return new JcaTlsRSAVerifier(this.crypto, getPubKeyRSA());
            case 2:
                return new JcaTlsDSAVerifier(this.crypto, getPubKeyDSS());
            case 3:
                return new JcaTlsECDSAVerifier(this.crypto, getPubKeyEC());
            case 4:
            case 5:
            case 6:
                validateRSA_PSS_RSAE();
                return new JcaTlsRSAPSSVerifier(this.crypto, getPubKeyRSA(), SignatureScheme.from((short) 8, s));
            case 7:
            case 8:
            default:
                throw new TlsFatalAlert((short) 46);
            case 9:
            case 10:
            case 11:
                validateRSA_PSS_PSS(s);
                return new JcaTlsRSAPSSVerifier(this.crypto, getPubKeyRSA(), SignatureScheme.from((short) 8, s));
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getEncoded() throws IOException {
        try {
            return this.certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new TlsCryptoException("unable to encode certificate: " + e.getMessage(), e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getExtension(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IOException {
        byte[] extensionValue = this.certificate.getExtensionValue(aSN1ObjectIdentifier.getId());
        if (extensionValue == null) {
            return null;
        }
        return ((ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue)).getOctets();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public short getLegacySignatureAlgorithm() throws IOException {
        PublicKey publicKey = getPublicKey();
        if (supportsKeyUsageBit(0)) {
            if (publicKey instanceof RSAPublicKey) {
                return (short) 1;
            }
            if (publicKey instanceof DSAPublicKey) {
                return (short) 2;
            }
            return publicKey instanceof ECPublicKey ? (short) 3 : (short) -1;
        }
        return (short) -1;
    }

    DHPublicKey getPubKeyDH() throws IOException {
        try {
            return (DHPublicKey) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    DSAPublicKey getPubKeyDSS() throws IOException {
        try {
            return (DSAPublicKey) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    ECPublicKey getPubKeyEC() throws IOException {
        try {
            return (ECPublicKey) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    PublicKey getPubKeyEd25519() throws IOException {
        PublicKey publicKey = getPublicKey();
        if (EdDSAParameterSpec.Ed25519.equals(publicKey.getAlgorithm()) || ("EdDSA".equals(publicKey.getAlgorithm()) && publicKey.toString().indexOf(EdDSAParameterSpec.Ed25519) >= 0)) {
            return publicKey;
        }
        throw new TlsFatalAlert((short) 46);
    }

    PublicKey getPubKeyEd448() throws IOException {
        PublicKey publicKey = getPublicKey();
        if (EdDSAParameterSpec.Ed448.equals(publicKey.getAlgorithm()) || ("EdDSA".equals(publicKey.getAlgorithm()) && publicKey.toString().indexOf(EdDSAParameterSpec.Ed448) >= 0)) {
            return publicKey;
        }
        throw new TlsFatalAlert((short) 46);
    }

    PublicKey getPubKeyRSA() throws IOException {
        return getPublicKey();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public PublicKey getPublicKey() throws IOException {
        try {
            return this.certificate.getPublicKey();
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 42, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public BigInteger getSerialNumber() {
        return this.certificate.getSerialNumber();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public String getSigAlgOID() {
        return this.certificate.getSigAlgOID();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public ASN1Encodable getSigAlgParams() throws IOException {
        byte[] sigAlgParams = this.certificate.getSigAlgParams();
        if (sigAlgParams == null) {
            return null;
        }
        ASN1Primitive readASN1Object = TlsUtils.readASN1Object(sigAlgParams);
        TlsUtils.requireDEREncoding(readASN1Object, sigAlgParams);
        return readASN1Object;
    }

    protected SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws IOException {
        return SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded());
    }

    public X509Certificate getX509Certificate() {
        return this.certificate;
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to find switch 'out' block
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:817)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMaker.processSwitch(RegionMaker.java:856)
        	at jadx.core.dex.visitors.regions.RegionMaker.traverse(RegionMaker.java:160)
        	at jadx.core.dex.visitors.regions.RegionMaker.makeRegion(RegionMaker.java:94)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:52)
        */
    protected boolean implSupportsSignatureAlgorithm(short r4) throws java.io.IOException {
        /*
            r3 = this;
            java.security.PublicKey r0 = r3.getPublicKey()
            r1 = 1
            r2 = 0
            switch(r4) {
                case 1: goto L3b;
                case 2: goto L38;
                case 3: goto L35;
                case 4: goto L28;
                case 5: goto L28;
                case 6: goto L28;
                case 7: goto L25;
                case 8: goto L1a;
                case 9: goto Ld;
                case 10: goto Ld;
                case 11: goto Ld;
                default: goto L9;
            }
        L9:
            switch(r4) {
                case 26: goto L35;
                case 27: goto L35;
                case 28: goto L35;
                default: goto Lc;
            }
        Lc:
            return r2
        Ld:
            boolean r4 = r3.supportsRSA_PSS_PSS(r4)
            if (r4 == 0) goto L18
            boolean r4 = r0 instanceof java.security.interfaces.RSAPublicKey
            if (r4 == 0) goto L18
            goto L19
        L18:
            r1 = r2
        L19:
            return r1
        L1a:
            java.lang.String r4 = "Ed448"
        L1c:
            java.lang.String r0 = r0.getAlgorithm()
            boolean r4 = r4.equals(r0)
            return r4
        L25:
            java.lang.String r4 = "Ed25519"
            goto L1c
        L28:
            boolean r4 = r3.supportsRSA_PSS_RSAE()
            if (r4 == 0) goto L33
            boolean r4 = r0 instanceof java.security.interfaces.RSAPublicKey
            if (r4 == 0) goto L33
            goto L34
        L33:
            r1 = r2
        L34:
            return r1
        L35:
            boolean r4 = r0 instanceof java.security.interfaces.ECPublicKey
            return r4
        L38:
            boolean r4 = r0 instanceof java.security.interfaces.DSAPublicKey
            return r4
        L3b:
            boolean r4 = r3.supportsRSA_PKCS1()
            if (r4 == 0) goto L46
            boolean r4 = r0 instanceof java.security.interfaces.RSAPublicKey
            if (r4 == 0) goto L46
            goto L47
        L46:
            r1 = r2
        L47:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate.implSupportsSignatureAlgorithm(short):boolean");
    }

    protected boolean supportsKeyUsageBit(int i) {
        boolean[] keyUsage = this.certificate.getKeyUsage();
        return keyUsage == null || (keyUsage.length > i && keyUsage[i]);
    }

    protected boolean supportsRSA_PKCS1() throws IOException {
        return org.bouncycastle.tls.crypto.impl.RSAUtil.supportsPKCS1(getSubjectPublicKeyInfo().getAlgorithm());
    }

    protected boolean supportsRSA_PSS_PSS(short s) throws IOException {
        return org.bouncycastle.tls.crypto.impl.RSAUtil.supportsPSS_PSS(s, getSubjectPublicKeyInfo().getAlgorithm());
    }

    protected boolean supportsRSA_PSS_RSAE() throws IOException {
        return org.bouncycastle.tls.crypto.impl.RSAUtil.supportsPSS_RSAE(getSubjectPublicKeyInfo().getAlgorithm());
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public boolean supportsSignatureAlgorithm(short s) throws IOException {
        if (supportsKeyUsageBit(0)) {
            return implSupportsSignatureAlgorithm(s);
        }
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public boolean supportsSignatureAlgorithmCA(short s) throws IOException {
        return implSupportsSignatureAlgorithm(s);
    }

    protected void validateKeyUsageBit(int i) throws IOException {
        if (!supportsKeyUsageBit(i)) {
            throw new TlsFatalAlert((short) 46);
        }
    }

    protected void validateRSA_PKCS1() throws IOException {
        if (!supportsRSA_PKCS1()) {
            throw new TlsFatalAlert((short) 46);
        }
    }

    protected void validateRSA_PSS_PSS(short s) throws IOException {
        if (!supportsRSA_PSS_PSS(s)) {
            throw new TlsFatalAlert((short) 46);
        }
    }

    protected void validateRSA_PSS_RSAE() throws IOException {
        if (!supportsRSA_PSS_RSAE()) {
            throw new TlsFatalAlert((short) 46);
        }
    }
}