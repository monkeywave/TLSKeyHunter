package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.SRP6Group;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.tls.crypto.impl.TlsNullCipher;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Client;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6Server;
import org.bouncycastle.tls.crypto.impl.jcajce.srp.SRP6VerifierGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class JcaTlsCrypto extends AbstractTlsCrypto {
    private final SecureRandom entropySource;
    private final JcaJceHelper helper;
    private final SecureRandom nonceEntropySource;
    private final Hashtable supportedEncryptionAlgorithms = new Hashtable();
    private final Hashtable supportedNamedGroups = new Hashtable();
    private final Hashtable supportedOther = new Hashtable();

    /* JADX INFO: Access modifiers changed from: protected */
    public JcaTlsCrypto(JcaJceHelper jcaJceHelper, SecureRandom secureRandom, SecureRandom secureRandom2) {
        this.helper = jcaJceHelper;
        this.entropySource = secureRandom;
        this.nonceEntropySource = secureRandom2;
    }

    private TlsCipher createChaCha20Poly1305(TlsCryptoParameters tlsCryptoParameters) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, new JceChaCha20Poly1305(this, this.helper, true), new JceChaCha20Poly1305(this, this.helper, false), 32, 16, 2);
    }

    private TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("AES/CCM/NoPadding", "AES", i, true), createAEADCipher("AES/CCM/NoPadding", "AES", i, false), i, i2, 1);
    }

    private TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("AES/GCM/NoPadding", "AES", i, true), createAEADCipher("AES/GCM/NoPadding", "AES", i, false), i, i2, 3);
    }

    private TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("ARIA/GCM/NoPadding", "ARIA", i, true), createAEADCipher("ARIA/GCM/NoPadding", "ARIA", i, false), i, i2, 3);
    }

    private TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("Camellia/GCM/NoPadding", "Camellia", i, true), createAEADCipher("Camellia/GCM/NoPadding", "Camellia", i, false), i, i2, 3);
    }

    private TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters tlsCryptoParameters) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("SM4/CCM/NoPadding", "SM4", 16, true), createAEADCipher("SM4/CCM/NoPadding", "SM4", 16, false), 16, 16, 1);
    }

    private TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters tlsCryptoParameters) throws IOException, GeneralSecurityException {
        return new TlsAEADCipher(tlsCryptoParameters, createAEADCipher("SM4/GCM/NoPadding", "SM4", 16, true), createAEADCipher("SM4/GCM/NoPadding", "SM4", 16, false), 16, 16, 3);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public JceTlsSecret adoptLocalSecret(byte[] bArr) {
        return new JceTlsSecret(this, bArr);
    }

    public byte[] calculateKeyAgreement(String str, PrivateKey privateKey, PublicKey publicKey, String str2) throws GeneralSecurityException {
        KeyAgreement createKeyAgreement = this.helper.createKeyAgreement(str);
        createKeyAgreement.init(privateKey);
        createKeyAgreement.doPhase(publicKey, true);
        try {
            return createKeyAgreement.generateSecret(str2).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            if (XDHParameterSpec.X25519.equals(str) || XDHParameterSpec.X448.equals(str)) {
                return createKeyAgreement.generateSecret();
            }
            throw e;
        }
    }

    protected TlsAEADCipherImpl createAEADCipher(String str, String str2, int i, boolean z) throws GeneralSecurityException {
        return new JceAEADCipherImpl(this, this.helper, str, str2, i, z);
    }

    protected TlsBlockCipherImpl createBlockCipher(String str, String str2, int i, boolean z) throws GeneralSecurityException {
        return new JceBlockCipherImpl(this, this.helper.createCipher(str), str2, i, z);
    }

    protected TlsBlockCipherImpl createBlockCipherWithCBCImplicitIV(String str, String str2, int i, boolean z) throws GeneralSecurityException {
        return new JceBlockCipherWithCBCImplicitIVImpl(this, this.helper.createCipher(str), str2, z);
    }

    protected TlsBlockCipherImpl createCBCBlockCipherImpl(TlsCryptoParameters tlsCryptoParameters, String str, int i, boolean z) throws GeneralSecurityException {
        String str2 = str + "/CBC/NoPadding";
        return TlsImplUtils.isTLSv11(tlsCryptoParameters) ? createBlockCipher(str2, str, i, z) : createBlockCipherWithCBCImplicitIV(str2, str, i, z);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCertificate createCertificate(short s, byte[] bArr) throws IOException {
        if (s == 0) {
            return new JcaTlsCertificate(this, bArr);
        }
        throw new TlsFatalAlert((short) 43);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCertificate createCertificate(byte[] bArr) throws IOException {
        return createCertificate((short) 0, bArr);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCipher createCipher(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        try {
            if (i != 0) {
                switch (i) {
                    case 7:
                        return createCipher_CBC(tlsCryptoParameters, "DESede", 24, i2);
                    case 8:
                        return createCipher_CBC(tlsCryptoParameters, "AES", 16, i2);
                    case 9:
                        return createCipher_CBC(tlsCryptoParameters, "AES", 32, i2);
                    case 10:
                        return createCipher_AES_GCM(tlsCryptoParameters, 16, 16);
                    case 11:
                        return createCipher_AES_GCM(tlsCryptoParameters, 32, 16);
                    case 12:
                        return createCipher_CBC(tlsCryptoParameters, "Camellia", 16, i2);
                    case 13:
                        return createCipher_CBC(tlsCryptoParameters, "Camellia", 32, i2);
                    case 14:
                        return createCipher_CBC(tlsCryptoParameters, "SEED", 16, i2);
                    case 15:
                        return createCipher_AES_CCM(tlsCryptoParameters, 16, 16);
                    case 16:
                        return createCipher_AES_CCM(tlsCryptoParameters, 16, 8);
                    case 17:
                        return createCipher_AES_CCM(tlsCryptoParameters, 32, 16);
                    case 18:
                        return createCipher_AES_CCM(tlsCryptoParameters, 32, 8);
                    case 19:
                        return createCipher_Camellia_GCM(tlsCryptoParameters, 16, 16);
                    case 20:
                        return createCipher_Camellia_GCM(tlsCryptoParameters, 32, 16);
                    case 21:
                        return createChaCha20Poly1305(tlsCryptoParameters);
                    case 22:
                        return createCipher_CBC(tlsCryptoParameters, "ARIA", 16, i2);
                    case 23:
                        return createCipher_CBC(tlsCryptoParameters, "ARIA", 32, i2);
                    case 24:
                        return createCipher_ARIA_GCM(tlsCryptoParameters, 16, 16);
                    case 25:
                        return createCipher_ARIA_GCM(tlsCryptoParameters, 32, 16);
                    case 26:
                        return createCipher_SM4_CCM(tlsCryptoParameters);
                    case 27:
                        return createCipher_SM4_GCM(tlsCryptoParameters);
                    case 28:
                        return createCipher_CBC(tlsCryptoParameters, "SM4", 16, i2);
                    default:
                        throw new TlsFatalAlert((short) 80);
                }
            }
            return createNullCipher(tlsCryptoParameters, i2);
        } catch (GeneralSecurityException e) {
            throw new TlsCryptoException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    protected TlsCipher createCipher_CBC(TlsCryptoParameters tlsCryptoParameters, String str, int i, int i2) throws GeneralSecurityException, IOException {
        return new TlsBlockCipher(tlsCryptoParameters, createCBCBlockCipherImpl(tlsCryptoParameters, str, i, true), createCBCBlockCipherImpl(tlsCryptoParameters, str, i, false), createMAC(tlsCryptoParameters, i2), createMAC(tlsCryptoParameters, i2), i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsDHDomain createDHDomain(TlsDHConfig tlsDHConfig) {
        return new JceTlsDHDomain(this, tlsDHConfig);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsECDomain createECDomain(TlsECConfig tlsECConfig) {
        int namedGroup = tlsECConfig.getNamedGroup();
        return namedGroup != 29 ? namedGroup != 30 ? new JceTlsECDomain(this, tlsECConfig) : new JceX448Domain(this) : new JceX25519Domain(this);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsHMAC createHMAC(int i) {
        if (i == 1 || i == 2 || i == 3 || i == 4 || i == 5) {
            return createHMACForHash(TlsCryptoUtils.getHashForHMAC(i));
        }
        throw new IllegalArgumentException("invalid MACAlgorithm: " + i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsHMAC createHMACForHash(int i) {
        String hMACAlgorithmName = getHMACAlgorithmName(i);
        try {
            return new JceTlsHMAC(i, this.helper.createMac(hMACAlgorithmName), hMACAlgorithmName);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("cannot create HMAC: " + hMACAlgorithmName, e);
        }
    }

    protected TlsHMAC createHMAC_SSL(int i) throws GeneralSecurityException, IOException {
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i != 4) {
                        if (i == 5) {
                            return new JcaSSL3HMAC(createHash(getDigestName(6)), 64, 128);
                        }
                        throw new TlsFatalAlert((short) 80);
                    }
                    return new JcaSSL3HMAC(createHash(getDigestName(5)), 48, 128);
                }
                return new JcaSSL3HMAC(createHash(getDigestName(4)), 32, 64);
            }
            return new JcaSSL3HMAC(createHash(getDigestName(2)), 20, 64);
        }
        return new JcaSSL3HMAC(createHash(getDigestName(1)), 16, 64);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsHash createHash(int i) {
        try {
            return createHash(getDigestName(i));
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalArgumentException("unable to create message digest:" + e.getMessage(), e);
        }
    }

    protected TlsHash createHash(String str) throws GeneralSecurityException {
        return new JcaTlsHash(this.helper.createDigest(str));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsKemDomain createKemDomain(TlsKemConfig tlsKemConfig) {
        return new JceTlsMLKemDomain(this, tlsKemConfig);
    }

    protected TlsHMAC createMAC(TlsCryptoParameters tlsCryptoParameters, int i) throws GeneralSecurityException, IOException {
        return TlsImplUtils.isSSL(tlsCryptoParameters) ? createHMAC_SSL(i) : createHMAC(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsNonceGenerator createNonceGenerator(byte[] bArr) {
        return new JcaNonceGenerator(this.nonceEntropySource, bArr);
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters tlsCryptoParameters, int i) throws IOException, GeneralSecurityException {
        return new TlsNullCipher(tlsCryptoParameters, createMAC(tlsCryptoParameters, i), createMAC(tlsCryptoParameters, i));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Cipher createRSAEncryptionCipher() throws GeneralSecurityException {
        try {
            return getHelper().createCipher("RSA/NONE/PKCS1Padding");
        } catch (GeneralSecurityException unused) {
            return getHelper().createCipher("RSA/ECB/PKCS1Padding");
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6Client createSRP6Client(TlsSRPConfig tlsSRPConfig) {
        final SRP6Client sRP6Client = new SRP6Client();
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        sRP6Client.init(new SRP6Group(explicitNG[0], explicitNG[1]), createHash(2), getSecureRandom());
        return new TlsSRP6Client() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto.1
            @Override // org.bouncycastle.tls.crypto.TlsSRP6Client
            public BigInteger calculateSecret(BigInteger bigInteger) throws TlsFatalAlert {
                try {
                    return sRP6Client.calculateSecret(bigInteger);
                } catch (IllegalArgumentException e) {
                    throw new TlsFatalAlert((short) 47, (Throwable) e);
                }
            }

            @Override // org.bouncycastle.tls.crypto.TlsSRP6Client
            public BigInteger generateClientCredentials(byte[] bArr, byte[] bArr2, byte[] bArr3) {
                return sRP6Client.generateClientCredentials(bArr, bArr2, bArr3);
            }
        };
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6Server createSRP6Server(TlsSRPConfig tlsSRPConfig, BigInteger bigInteger) {
        final SRP6Server sRP6Server = new SRP6Server();
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        sRP6Server.init(new SRP6Group(explicitNG[0], explicitNG[1]), bigInteger, createHash(2), getSecureRandom());
        return new TlsSRP6Server() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto.2
            @Override // org.bouncycastle.tls.crypto.TlsSRP6Server
            public BigInteger calculateSecret(BigInteger bigInteger2) throws IOException {
                try {
                    return sRP6Server.calculateSecret(bigInteger2);
                } catch (IllegalArgumentException e) {
                    throw new TlsFatalAlert((short) 47, (Throwable) e);
                }
            }

            @Override // org.bouncycastle.tls.crypto.TlsSRP6Server
            public BigInteger generateServerCredentials() {
                return sRP6Server.generateServerCredentials();
            }
        };
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig tlsSRPConfig) {
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        final SRP6VerifierGenerator sRP6VerifierGenerator = new SRP6VerifierGenerator();
        sRP6VerifierGenerator.init(explicitNG[0], explicitNG[1], createHash(2));
        return new TlsSRP6VerifierGenerator() { // from class: org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto.3
            @Override // org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator
            public BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3) {
                return sRP6VerifierGenerator.generateVerifier(bArr, bArr2, bArr3);
            }
        };
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret createSecret(byte[] bArr) {
        return adoptLocalSecret(Arrays.clone(bArr));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsStreamSigner createStreamSigner(String str, AlgorithmParameterSpec algorithmParameterSpec, PrivateKey privateKey, boolean z) throws IOException {
        SecureRandom secureRandom;
        if (z) {
            try {
                secureRandom = getSecureRandom();
            } catch (GeneralSecurityException e) {
                throw new TlsFatalAlert((short) 80, (Throwable) e);
            }
        } else {
            secureRandom = null;
        }
        JcaJceHelper helper = getHelper();
        if (algorithmParameterSpec != null) {
            try {
                Signature createSignature = helper.createSignature(str);
                createSignature.initSign(privateKey, secureRandom);
                helper = new ProviderJcaJceHelper(createSignature.getProvider());
            } catch (InvalidKeyException e2) {
                String upperCase = Strings.toUpperCase(str);
                if (upperCase.endsWith("MGF1")) {
                    return createStreamSigner(upperCase.replace("ANDMGF1", "SSA-PSS"), algorithmParameterSpec, privateKey, z);
                }
                throw e2;
            }
        }
        Signature createSignature2 = helper.createSignature(str);
        if (algorithmParameterSpec != null) {
            createSignature2.setParameter(algorithmParameterSpec);
        }
        createSignature2.initSign(privateKey, secureRandom);
        return new JcaTlsStreamSigner(createSignature2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsStreamSigner createStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm, PrivateKey privateKey, boolean z) throws IOException {
        return createStreamSigner(JcaUtils.getJcaAlgorithmName(signatureAndHashAlgorithm), null, privateKey, z);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsStreamVerifier createStreamVerifier(String str, AlgorithmParameterSpec algorithmParameterSpec, byte[] bArr, PublicKey publicKey) throws IOException {
        try {
            JcaJceHelper helper = getHelper();
            if (algorithmParameterSpec != null) {
                Signature createSignature = helper.createSignature(str);
                createSignature.initVerify(publicKey);
                helper = new ProviderJcaJceHelper(createSignature.getProvider());
            }
            Signature createSignature2 = helper.createSignature(str);
            if (algorithmParameterSpec != null) {
                createSignature2.setParameter(algorithmParameterSpec);
            }
            createSignature2.initVerify(publicKey);
            return new JcaTlsStreamVerifier(createSignature2, bArr);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsStreamVerifier createStreamVerifier(DigitallySigned digitallySigned, PublicKey publicKey) throws IOException {
        return createStreamVerifier(JcaUtils.getJcaAlgorithmName(digitallySigned.getAlgorithm()), null, digitallySigned.getSignature(), publicKey);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public Tls13Verifier createTls13Verifier(String str, AlgorithmParameterSpec algorithmParameterSpec, PublicKey publicKey) throws IOException {
        try {
            JcaJceHelper helper = getHelper();
            if (algorithmParameterSpec != null) {
                Signature createSignature = helper.createSignature(str);
                createSignature.initVerify(publicKey);
                helper = new ProviderJcaJceHelper(createSignature.getProvider());
            }
            Signature createSignature2 = helper.createSignature(str);
            if (algorithmParameterSpec != null) {
                createSignature2.setParameter(algorithmParameterSpec);
            }
            createSignature2.initVerify(publicKey);
            return new JcaTls13Verifier(createSignature2);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret generateRSAPreMasterSecret(ProtocolVersion protocolVersion) {
        byte[] bArr = new byte[48];
        getSecureRandom().nextBytes(bArr);
        TlsUtils.writeVersion(protocolVersion, bArr, 0);
        return adoptLocalSecret(bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getDigestName(int i) {
        switch (i) {
            case 1:
                return "MD5";
            case 2:
                return McElieceCCA2KeyGenParameterSpec.SHA1;
            case 3:
                return McElieceCCA2KeyGenParameterSpec.SHA224;
            case 4:
                return "SHA-256";
            case 5:
                return McElieceCCA2KeyGenParameterSpec.SHA384;
            case 6:
                return "SHA-512";
            case 7:
                return "SM3";
            case 8:
                return "GOST3411-2012-256";
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + i);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getHMACAlgorithmName(int i) {
        switch (i) {
            case 1:
                return "HmacMD5";
            case 2:
                return "HmacSHA1";
            case 3:
                return "HmacSHA224";
            case 4:
                return "HmacSHA256";
            case 5:
                return "HmacSHA384";
            case 6:
                return "HmacSHA512";
            case 7:
                return "HmacSM3";
            case 8:
                return "HmacGOST3411-2012-256";
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + i);
        }
    }

    public JcaJceHelper getHelper() {
        return this.helper;
    }

    public AlgorithmParameters getNamedGroupAlgorithmParameters(int i) throws GeneralSecurityException {
        if (NamedGroup.refersToAnXDHCurve(i)) {
            if (i == 29 || i == 30) {
                return null;
            }
        } else if (NamedGroup.refersToAnECDSACurve(i)) {
            return ECUtil.getAlgorithmParameters(this, NamedGroup.getCurveName(i));
        } else {
            if (NamedGroup.refersToASpecificFiniteField(i)) {
                return DHUtil.getAlgorithmParameters(this, TlsDHUtils.getNamedDHGroup(i));
            }
            if (NamedGroup.refersToASpecificKem(i)) {
                if (i != 1896 && i != 4132) {
                    switch (i) {
                    }
                }
                return null;
            }
        }
        throw new IllegalArgumentException("NamedGroup not supported: " + NamedGroup.getText(i));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public SecureRandom getSecureRandom() {
        return this.entropySource;
    }

    public AlgorithmParameters getSignatureSchemeAlgorithmParameters(int i) throws GeneralSecurityException {
        int cryptoHashAlgorithm;
        String digestName;
        if (SignatureScheme.isRSAPSS(i) && (cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i)) >= 0) {
            AlgorithmParameterSpec pSSParameterSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, getDigestName(cryptoHashAlgorithm), getHelper());
            Signature createSignature = getHelper().createSignature(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1");
            createSignature.setParameter(pSSParameterSpec);
            return createSignature.getParameters();
        }
        return null;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasAnyStreamVerifiers(Vector vector) {
        boolean isSunMSCAPIProviderActive = JcaUtils.isSunMSCAPIProviderActive();
        int size = vector.size();
        for (int i = 0; i < size; i++) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) vector.elementAt(i);
            short signature = signatureAndHashAlgorithm.getSignature();
            if (signature != 1) {
                if (signature == 2 && HashAlgorithm.getOutputSize(signatureAndHashAlgorithm.getHash()) != 20) {
                    return true;
                }
            } else if (isSunMSCAPIProviderActive) {
                return true;
            }
            switch (SignatureScheme.from(signatureAndHashAlgorithm)) {
                case SignatureScheme.rsa_pss_rsae_sha256 /* 2052 */:
                case SignatureScheme.rsa_pss_rsae_sha384 /* 2053 */:
                case SignatureScheme.rsa_pss_rsae_sha512 /* 2054 */:
                case SignatureScheme.ed25519 /* 2055 */:
                case SignatureScheme.ed448 /* 2056 */:
                case SignatureScheme.rsa_pss_pss_sha256 /* 2057 */:
                case SignatureScheme.rsa_pss_pss_sha384 /* 2058 */:
                case SignatureScheme.rsa_pss_pss_sha512 /* 2059 */:
                    return true;
                default:
            }
        }
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasAnyStreamVerifiersLegacy(short[] sArr) {
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasCryptoHashAlgorithm(int i) {
        return true;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasCryptoSignatureAlgorithm(int i) {
        switch (i) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                return true;
            default:
                return false;
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasDHAgreement() {
        return true;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasECDHAgreement() {
        return true;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasEncryptionAlgorithm(int i) {
        Integer valueOf = Integers.valueOf(i);
        synchronized (this.supportedEncryptionAlgorithms) {
            Boolean bool = (Boolean) this.supportedEncryptionAlgorithms.get(valueOf);
            if (bool != null) {
                return bool.booleanValue();
            }
            Boolean isSupportedEncryptionAlgorithm = isSupportedEncryptionAlgorithm(i);
            if (isSupportedEncryptionAlgorithm == null) {
                return false;
            }
            synchronized (this.supportedEncryptionAlgorithms) {
                Boolean bool2 = (Boolean) this.supportedEncryptionAlgorithms.put(valueOf, isSupportedEncryptionAlgorithm);
                if (bool2 != null && isSupportedEncryptionAlgorithm != bool2) {
                    this.supportedEncryptionAlgorithms.put(valueOf, bool2);
                    isSupportedEncryptionAlgorithm = bool2;
                }
            }
            return isSupportedEncryptionAlgorithm.booleanValue();
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasHKDFAlgorithm(int i) {
        return i == 4 || i == 5 || i == 6 || i == 7;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasKemAgreement() {
        return true;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasMacAlgorithm(int i) {
        return i == 1 || i == 2 || i == 3 || i == 4 || i == 5;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasNamedGroup(int i) {
        Integer valueOf = Integers.valueOf(i);
        synchronized (this.supportedNamedGroups) {
            Boolean bool = (Boolean) this.supportedNamedGroups.get(valueOf);
            if (bool != null) {
                return bool.booleanValue();
            }
            Boolean isSupportedNamedGroup = isSupportedNamedGroup(i);
            if (isSupportedNamedGroup == null) {
                return false;
            }
            synchronized (this.supportedNamedGroups) {
                Boolean bool2 = (Boolean) this.supportedNamedGroups.put(valueOf, isSupportedNamedGroup);
                if (bool2 != null && isSupportedNamedGroup != bool2) {
                    this.supportedNamedGroups.put(valueOf, bool2);
                    isSupportedNamedGroup = bool2;
                }
            }
            return isSupportedNamedGroup.booleanValue();
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasRSAEncryption() {
        Boolean bool;
        synchronized (this.supportedOther) {
            Boolean bool2 = (Boolean) this.supportedOther.get("KE_RSA");
            if (bool2 != null) {
                return bool2.booleanValue();
            }
            try {
                createRSAEncryptionCipher();
                bool = Boolean.TRUE;
            } catch (GeneralSecurityException unused) {
                bool = Boolean.FALSE;
            }
            synchronized (this.supportedOther) {
                Boolean bool3 = (Boolean) this.supportedOther.put("KE_RSA", bool);
                if (bool3 != null && bool != bool3) {
                    this.supportedOther.put("KE_RSA", bool3);
                    bool = bool3;
                }
            }
            return bool.booleanValue();
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasSRPAuthentication() {
        return true;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasSignatureAlgorithm(short s) {
        switch (s) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
                return true;
            default:
                switch (s) {
                    case 26:
                    case 27:
                    case 28:
                        return true;
                    default:
                        return false;
                }
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        short signature = signatureAndHashAlgorithm.getSignature();
        short hash = signatureAndHashAlgorithm.getHash();
        return hash != 1 ? hash != 3 ? hasSignatureAlgorithm(signature) : !JcaUtils.isSunMSCAPIProviderActive() && hasSignatureAlgorithm(signature) : 1 == signature && hasSignatureAlgorithm(signature);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasSignatureScheme(int i) {
        if (i != 1800) {
            short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(i);
            int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i);
            return cryptoHashAlgorithm != 1 ? cryptoHashAlgorithm != 3 ? hasSignatureAlgorithm(signatureAlgorithm) : !JcaUtils.isSunMSCAPIProviderActive() && hasSignatureAlgorithm(signatureAlgorithm) : 1 == signatureAlgorithm && hasSignatureAlgorithm(signatureAlgorithm);
        }
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret hkdfInit(int i) {
        return adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(i)]);
    }

    protected Boolean isSupportedEncryptionAlgorithm(int i) {
        boolean isUsableCipher;
        String str;
        switch (i) {
            case 0:
                return Boolean.TRUE;
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 29:
            case 30:
            case 31:
                return Boolean.FALSE;
            case 7:
                isUsableCipher = isUsableCipher("DESede/CBC/NoPadding", 192);
                break;
            case 8:
                isUsableCipher = isUsableCipher("AES/CBC/NoPadding", 128);
                break;
            case 9:
                isUsableCipher = isUsableCipher("AES/CBC/NoPadding", 256);
                break;
            case 10:
                isUsableCipher = isUsableCipher("AES/GCM/NoPadding", 128);
                break;
            case 11:
                isUsableCipher = isUsableCipher("AES/GCM/NoPadding", 256);
                break;
            case 12:
                isUsableCipher = isUsableCipher("Camellia/CBC/NoPadding", 128);
                break;
            case 13:
                isUsableCipher = isUsableCipher("Camellia/CBC/NoPadding", 256);
                break;
            case 14:
                str = "SEED/CBC/NoPadding";
                isUsableCipher = isUsableCipher(str, 128);
                break;
            case 15:
            case 16:
                isUsableCipher = isUsableCipher("AES/CCM/NoPadding", 128);
                break;
            case 17:
            case 18:
                isUsableCipher = isUsableCipher("AES/CCM/NoPadding", 256);
                break;
            case 19:
                isUsableCipher = isUsableCipher("Camellia/GCM/NoPadding", 128);
                break;
            case 20:
                isUsableCipher = isUsableCipher("Camellia/GCM/NoPadding", 256);
                break;
            case 21:
                return Boolean.valueOf(isUsableCipher("ChaCha7539", 256) && isUsableMAC("Poly1305"));
            case 22:
                isUsableCipher = isUsableCipher("ARIA/CBC/NoPadding", 128);
                break;
            case 23:
                isUsableCipher = isUsableCipher("ARIA/CBC/NoPadding", 256);
                break;
            case 24:
                isUsableCipher = isUsableCipher("ARIA/GCM/NoPadding", 128);
                break;
            case 25:
                isUsableCipher = isUsableCipher("ARIA/GCM/NoPadding", 256);
                break;
            case 26:
                str = "SM4/CCM/NoPadding";
                isUsableCipher = isUsableCipher(str, 128);
                break;
            case 27:
                str = "SM4/GCM/NoPadding";
                isUsableCipher = isUsableCipher(str, 128);
                break;
            case 28:
                str = "SM4/CBC/NoPadding";
                isUsableCipher = isUsableCipher(str, 128);
                break;
            default:
                return null;
        }
        return Boolean.valueOf(isUsableCipher);
    }

    protected Boolean isSupportedNamedGroup(int i) {
        try {
            if (NamedGroup.refersToAnXDHCurve(i)) {
                if (i == 29) {
                    this.helper.createKeyAgreement(XDHParameterSpec.X25519);
                    return Boolean.TRUE;
                } else if (i != 30) {
                    return null;
                } else {
                    this.helper.createKeyAgreement(XDHParameterSpec.X448);
                    return Boolean.TRUE;
                }
            } else if (NamedGroup.refersToASpecificKem(i)) {
                return Boolean.TRUE;
            } else {
                if (NamedGroup.refersToAnECDSACurve(i)) {
                    return Boolean.valueOf(ECUtil.isCurveSupported(this, NamedGroup.getCurveName(i)));
                }
                if (NamedGroup.refersToASpecificFiniteField(i)) {
                    return Boolean.valueOf(DHUtil.isGroupSupported(this, TlsDHUtils.getNamedDHGroup(i)));
                }
                return null;
            }
        } catch (GeneralSecurityException unused) {
            return Boolean.FALSE;
        }
    }

    protected boolean isUsableCipher(String str, int i) {
        try {
            this.helper.createCipher(str);
            return Cipher.getMaxAllowedKeyLength(str) >= i;
        } catch (GeneralSecurityException unused) {
            return false;
        }
    }

    protected boolean isUsableMAC(String str) {
        try {
            this.helper.createMac(str);
            return true;
        } catch (GeneralSecurityException unused) {
            return false;
        }
    }
}