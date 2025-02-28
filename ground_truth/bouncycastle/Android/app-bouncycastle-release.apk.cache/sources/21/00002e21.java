package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.LegacyTls13Verifier;
import org.bouncycastle.tls.crypto.impl.RSAUtil;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsRawKeyCertificate */
/* loaded from: classes2.dex */
public class BcTlsRawKeyCertificate implements TlsCertificate {
    protected final BcTlsCrypto crypto;
    protected final SubjectPublicKeyInfo keyInfo;
    protected DHPublicKeyParameters pubKeyDH;
    protected ECPublicKeyParameters pubKeyEC;
    protected Ed25519PublicKeyParameters pubKeyEd25519;
    protected Ed448PublicKeyParameters pubKeyEd448;
    protected RSAKeyParameters pubKeyRSA;

    public BcTlsRawKeyCertificate(BcTlsCrypto bcTlsCrypto, SubjectPublicKeyInfo subjectPublicKeyInfo) {
        this.pubKeyDH = null;
        this.pubKeyEC = null;
        this.pubKeyEd25519 = null;
        this.pubKeyEd448 = null;
        this.pubKeyRSA = null;
        this.crypto = bcTlsCrypto;
        this.keyInfo = subjectPublicKeyInfo;
    }

    public BcTlsRawKeyCertificate(BcTlsCrypto bcTlsCrypto, byte[] bArr) {
        this(bcTlsCrypto, SubjectPublicKeyInfo.getInstance(bArr));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsCertificate checkUsageInRole(int i) throws IOException {
        if (i == 1) {
            validateKeyUsage(8);
            this.pubKeyDH = getPubKeyDH();
            return this;
        } else if (i == 2) {
            validateKeyUsage(8);
            this.pubKeyEC = getPubKeyEC();
            return this;
        } else {
            throw new TlsFatalAlert((short) 46);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsEncryptor createEncryptor(int i) throws IOException {
        validateKeyUsage(32);
        if (i == 3) {
            this.pubKeyRSA = getPubKeyRSA();
            return new BcTlsRSAEncryptor(this.crypto, this.pubKeyRSA);
        }
        throw new TlsFatalAlert((short) 46);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public Tls13Verifier createVerifier(int i) throws IOException {
        validateKeyUsage(128);
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
                                                Digest createDigest = this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i));
                                                PSSSigner pSSSigner = new PSSSigner(new RSAEngine(), createDigest, createDigest.getDigestSize());
                                                pSSSigner.init(false, getPubKeyRSA());
                                                return new BcTls13Verifier(pSSSigner);
                                            case SignatureScheme.ed25519 /* 2055 */:
                                                Ed25519Signer ed25519Signer = new Ed25519Signer();
                                                ed25519Signer.init(false, getPubKeyEd25519());
                                                return new BcTls13Verifier(ed25519Signer);
                                            case SignatureScheme.ed448 /* 2056 */:
                                                Ed448Signer ed448Signer = new Ed448Signer(TlsUtils.EMPTY_BYTES);
                                                ed448Signer.init(false, getPubKeyEd448());
                                                return new BcTls13Verifier(ed448Signer);
                                            case SignatureScheme.rsa_pss_pss_sha256 /* 2057 */:
                                            case SignatureScheme.rsa_pss_pss_sha384 /* 2058 */:
                                            case SignatureScheme.rsa_pss_pss_sha512 /* 2059 */:
                                                validateRSA_PSS_PSS(SignatureScheme.getSignatureAlgorithm(i));
                                                Digest createDigest2 = this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i));
                                                PSSSigner pSSSigner2 = new PSSSigner(new RSAEngine(), createDigest2, createDigest2.getDigestSize());
                                                pSSSigner2.init(false, getPubKeyRSA());
                                                return new BcTls13Verifier(pSSSigner2);
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
            DSADigestSigner dSADigestSigner = new DSADigestSigner(new ECDSASigner(), this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i)));
            dSADigestSigner.init(false, getPubKeyEC());
            return new BcTls13Verifier(dSADigestSigner);
        }
        validateRSA_PKCS1();
        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i);
        RSADigestSigner rSADigestSigner = new RSADigestSigner(this.crypto.createDigest(cryptoHashAlgorithm), TlsCryptoUtils.getOIDForHash(cryptoHashAlgorithm));
        rSADigestSigner.init(false, getPubKeyRSA());
        return new BcTls13Verifier(rSADigestSigner);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public TlsVerifier createVerifier(short s) throws IOException {
        if (s == 7 || s == 8) {
            int from = SignatureScheme.from((short) 8, s);
            return new LegacyTls13Verifier(from, createVerifier(from));
        }
        validateKeyUsage(128);
        switch (s) {
            case 1:
                validateRSA_PKCS1();
                return new BcTlsRSAVerifier(this.crypto, getPubKeyRSA());
            case 2:
                return new BcTlsDSAVerifier(this.crypto, getPubKeyDSS());
            case 3:
                return new BcTlsECDSAVerifier(this.crypto, getPubKeyEC());
            case 4:
            case 5:
            case 6:
                validateRSA_PSS_RSAE();
                return new BcTlsRSAPSSVerifier(this.crypto, getPubKeyRSA(), SignatureScheme.from((short) 8, s));
            case 7:
            case 8:
            default:
                throw new TlsFatalAlert((short) 46);
            case 9:
            case 10:
            case 11:
                validateRSA_PSS_PSS(s);
                return new BcTlsRSAPSSVerifier(this.crypto, getPubKeyRSA(), SignatureScheme.from((short) 8, s));
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getEncoded() throws IOException {
        return this.keyInfo.getEncoded(ASN1Encoding.DER);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getExtension(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IOException {
        return null;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public short getLegacySignatureAlgorithm() throws IOException {
        AsymmetricKeyParameter publicKey = getPublicKey();
        if (publicKey.isPrivate()) {
            throw new TlsFatalAlert((short) 80);
        }
        if (supportsKeyUsage(128)) {
            if (publicKey instanceof RSAKeyParameters) {
                return (short) 1;
            }
            if (publicKey instanceof DSAPublicKeyParameters) {
                return (short) 2;
            }
            return publicKey instanceof ECPublicKeyParameters ? (short) 3 : (short) -1;
        }
        return (short) -1;
    }

    public DHPublicKeyParameters getPubKeyDH() throws IOException {
        try {
            return (DHPublicKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    public DSAPublicKeyParameters getPubKeyDSS() throws IOException {
        try {
            return (DSAPublicKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    public ECPublicKeyParameters getPubKeyEC() throws IOException {
        try {
            return (ECPublicKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    public Ed25519PublicKeyParameters getPubKeyEd25519() throws IOException {
        try {
            return (Ed25519PublicKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    public Ed448PublicKeyParameters getPubKeyEd448() throws IOException {
        try {
            return (Ed448PublicKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    public RSAKeyParameters getPubKeyRSA() throws IOException {
        try {
            return (RSAKeyParameters) getPublicKey();
        } catch (ClassCastException e) {
            throw new TlsFatalAlert((short) 46, (Throwable) e);
        }
    }

    protected AsymmetricKeyParameter getPublicKey() throws IOException {
        try {
            return PublicKeyFactory.createKey(this.keyInfo);
        } catch (RuntimeException e) {
            throw new TlsFatalAlert((short) 43, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public BigInteger getSerialNumber() {
        return null;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public String getSigAlgOID() {
        return null;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public ASN1Encodable getSigAlgParams() {
        return null;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.keyInfo;
    }

    protected boolean supportsKeyUsage(int i) {
        return true;
    }

    protected boolean supportsRSA_PKCS1() {
        return RSAUtil.supportsPKCS1(this.keyInfo.getAlgorithm());
    }

    protected boolean supportsRSA_PSS_PSS(short s) {
        return RSAUtil.supportsPSS_PSS(s, this.keyInfo.getAlgorithm());
    }

    protected boolean supportsRSA_PSS_RSAE() {
        return RSAUtil.supportsPSS_RSAE(this.keyInfo.getAlgorithm());
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public boolean supportsSignatureAlgorithm(short s) throws IOException {
        return supportsSignatureAlgorithm(s, 128);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    protected boolean supportsSignatureAlgorithm(short s, int i) throws IOException {
        if (supportsKeyUsage(i)) {
            AsymmetricKeyParameter publicKey = getPublicKey();
            switch (s) {
                case 1:
                    return supportsRSA_PKCS1() && (publicKey instanceof RSAKeyParameters);
                case 2:
                    return publicKey instanceof DSAPublicKeyParameters;
                case 3:
                    break;
                case 4:
                case 5:
                case 6:
                    return supportsRSA_PSS_RSAE() && (publicKey instanceof RSAKeyParameters);
                case 7:
                    return publicKey instanceof Ed25519PublicKeyParameters;
                case 8:
                    return publicKey instanceof Ed448PublicKeyParameters;
                case 9:
                case 10:
                case 11:
                    return supportsRSA_PSS_PSS(s) && (publicKey instanceof RSAKeyParameters);
                default:
                    switch (s) {
                        case 26:
                        case 27:
                        case 28:
                            break;
                        default:
                            return false;
                    }
            }
            return publicKey instanceof ECPublicKeyParameters;
        }
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCertificate
    public boolean supportsSignatureAlgorithmCA(short s) throws IOException {
        return supportsSignatureAlgorithm(s, 4);
    }

    public void validateKeyUsage(int i) throws IOException {
        if (!supportsKeyUsage(i)) {
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