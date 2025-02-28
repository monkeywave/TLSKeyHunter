package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
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
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipher;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipher;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;
import org.bouncycastle.tls.crypto.impl.TlsNullCipher;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto */
/* loaded from: classes2.dex */
public class BcTlsCrypto extends AbstractTlsCrypto {
    private final SecureRandom entropySource;

    public BcTlsCrypto() {
        this(new SecureRandom());
    }

    public BcTlsCrypto(SecureRandom secureRandom) {
        this.entropySource = secureRandom;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsSecret adoptLocalSecret(byte[] bArr) {
        return new BcTlsSecret(this, bArr);
    }

    public Digest cloneDigest(int i, Digest digest) {
        switch (i) {
            case 1:
                return new MD5Digest((MD5Digest) digest);
            case 2:
                return new SHA1Digest((SHA1Digest) digest);
            case 3:
                return new SHA224Digest((SHA224Digest) digest);
            case 4:
                return SHA256Digest.newInstance(digest);
            case 5:
                return new SHA384Digest((SHA384Digest) digest);
            case 6:
                return new SHA512Digest((SHA512Digest) digest);
            case 7:
                return new SM3Digest((SM3Digest) digest);
            case 8:
                return new GOST3411_2012_256Digest((GOST3411_2012_256Digest) digest);
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + i);
        }
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_CCM() {
        return createCCMMode(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_AES_GCM() {
        return createGCMMode(createAESEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_ARIA_GCM() {
        return createGCMMode(createARIAEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_Camellia_GCM() {
        return createGCMMode(createCamelliaEngine());
    }

    protected AEADBlockCipher createAEADBlockCipher_SM4_CCM() {
        return createCCMMode(createSM4Engine());
    }

    protected AEADBlockCipher createAEADBlockCipher_SM4_GCM() {
        return createGCMMode(createSM4Engine());
    }

    protected BlockCipher createAESEngine() {
        return AESEngine.newInstance();
    }

    protected BlockCipher createARIAEngine() {
        return new ARIAEngine();
    }

    protected BlockCipher createBlockCipher(int i) throws IOException {
        if (i != 7) {
            if (i == 8 || i == 9) {
                return createAESEngine();
            }
            if (i == 22 || i == 23) {
                return createARIAEngine();
            }
            if (i != 28) {
                switch (i) {
                    case 12:
                    case 13:
                        return createCamelliaEngine();
                    case 14:
                        return createSEEDEngine();
                    default:
                        throw new TlsFatalAlert((short) 80);
                }
            }
            return createSM4Engine();
        }
        return createDESedeEngine();
    }

    protected BlockCipher createCBCBlockCipher(int i) throws IOException {
        return createCBCBlockCipher(createBlockCipher(i));
    }

    protected BlockCipher createCBCBlockCipher(BlockCipher blockCipher) {
        return CBCBlockCipher.newInstance(blockCipher);
    }

    protected AEADBlockCipher createCCMMode(BlockCipher blockCipher) {
        return new CCMBlockCipher(blockCipher);
    }

    protected BlockCipher createCamelliaEngine() {
        return new CamelliaEngine();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCertificate createCertificate(short s, byte[] bArr) throws IOException {
        if (s != 0) {
            if (s == 2) {
                return new BcTlsRawKeyCertificate(this, bArr);
            }
            throw new TlsFatalAlert((short) 80);
        }
        return new BcTlsCertificate(this, bArr);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCertificate createCertificate(byte[] bArr) throws IOException {
        return createCertificate((short) 0, bArr);
    }

    protected TlsCipher createChaCha20Poly1305(TlsCryptoParameters tlsCryptoParameters) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcChaCha20Poly1305(true), new BcChaCha20Poly1305(false), 32, 16, 2);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsCipher createCipher(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        if (i != 0) {
            switch (i) {
                case 7:
                    return createCipher_CBC(tlsCryptoParameters, i, 24, i2);
                case 8:
                case 12:
                case 14:
                case 22:
                case 28:
                    return createCipher_CBC(tlsCryptoParameters, i, 16, i2);
                case 9:
                case 13:
                case 23:
                    return createCipher_CBC(tlsCryptoParameters, i, 32, i2);
                case 10:
                    return createCipher_AES_GCM(tlsCryptoParameters, 16, 16);
                case 11:
                    return createCipher_AES_GCM(tlsCryptoParameters, 32, 16);
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
                case 24:
                    return createCipher_ARIA_GCM(tlsCryptoParameters, 16, 16);
                case 25:
                    return createCipher_ARIA_GCM(tlsCryptoParameters, 32, 16);
                case 26:
                    return createCipher_SM4_CCM(tlsCryptoParameters);
                case 27:
                    return createCipher_SM4_GCM(tlsCryptoParameters);
                default:
                    throw new TlsFatalAlert((short) 80);
            }
        }
        return createNullCipher(tlsCryptoParameters, i2);
    }

    protected TlsAEADCipher createCipher_AES_CCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_CCM(), false), i, i2, 1);
    }

    protected TlsAEADCipher createCipher_AES_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_AES_GCM(), false), i, i2, 3);
    }

    protected TlsAEADCipher createCipher_ARIA_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_ARIA_GCM(), false), i, i2, 3);
    }

    protected TlsCipher createCipher_CBC(TlsCryptoParameters tlsCryptoParameters, int i, int i2, int i3) throws IOException {
        return new TlsBlockCipher(tlsCryptoParameters, new BcTlsBlockCipherImpl(createCBCBlockCipher(i), true), new BcTlsBlockCipherImpl(createCBCBlockCipher(i), false), createMAC(tlsCryptoParameters, i3), createMAC(tlsCryptoParameters, i3), i2);
    }

    protected TlsAEADCipher createCipher_Camellia_GCM(TlsCryptoParameters tlsCryptoParameters, int i, int i2) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_Camellia_GCM(), false), i, i2, 3);
    }

    protected TlsAEADCipher createCipher_SM4_CCM(TlsCryptoParameters tlsCryptoParameters) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_CCM(), false), 16, 16, 1);
    }

    protected TlsAEADCipher createCipher_SM4_GCM(TlsCryptoParameters tlsCryptoParameters) throws IOException {
        return new TlsAEADCipher(tlsCryptoParameters, new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), true), new BcTlsAEADCipherImpl(createAEADBlockCipher_SM4_GCM(), false), 16, 16, 3);
    }

    protected BlockCipher createDESedeEngine() {
        return new DESedeEngine();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsDHDomain createDHDomain(TlsDHConfig tlsDHConfig) {
        return new BcTlsDHDomain(this, tlsDHConfig);
    }

    public Digest createDigest(int i) {
        switch (i) {
            case 1:
                return new MD5Digest();
            case 2:
                return new SHA1Digest();
            case 3:
                return new SHA224Digest();
            case 4:
                return new SHA256Digest();
            case 5:
                return new SHA384Digest();
            case 6:
                return new SHA512Digest();
            case 7:
                return new SM3Digest();
            case 8:
                return new GOST3411_2012_256Digest();
            default:
                throw new IllegalArgumentException("invalid CryptoHashAlgorithm: " + i);
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsECDomain createECDomain(TlsECConfig tlsECConfig) {
        int namedGroup = tlsECConfig.getNamedGroup();
        return namedGroup != 29 ? namedGroup != 30 ? new BcTlsECDomain(this, tlsECConfig) : new BcX448Domain(this) : new BcX25519Domain(this);
    }

    protected AEADBlockCipher createGCMMode(BlockCipher blockCipher) {
        return GCMBlockCipher.newInstance(blockCipher);
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
        return new BcTlsHMAC(new HMac(createDigest(i)));
    }

    protected TlsHMAC createHMAC_SSL(int i) throws IOException {
        if (i != 1) {
            if (i != 2) {
                if (i != 3) {
                    if (i != 4) {
                        if (i == 5) {
                            return new BcSSL3HMAC(createDigest(6));
                        }
                        throw new TlsFatalAlert((short) 80);
                    }
                    return new BcSSL3HMAC(createDigest(5));
                }
                return new BcSSL3HMAC(createDigest(4));
            }
            return new BcSSL3HMAC(createDigest(2));
        }
        return new BcSSL3HMAC(createDigest(1));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsHash createHash(int i) {
        return new BcTlsHash(this, i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsKemDomain createKemDomain(TlsKemConfig tlsKemConfig) {
        return new BcTlsMLKemDomain(this, tlsKemConfig);
    }

    protected TlsHMAC createMAC(TlsCryptoParameters tlsCryptoParameters, int i) throws IOException {
        return TlsImplUtils.isSSL(tlsCryptoParameters) ? createHMAC_SSL(i) : createHMAC(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsNonceGenerator createNonceGenerator(byte[] bArr) {
        Digest createDigest = createDigest(4);
        byte[] bArr2 = new byte[TlsCryptoUtils.getHashOutputSize(4)];
        getSecureRandom().nextBytes(bArr2);
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(createDigest);
        digestRandomGenerator.addSeedMaterial(bArr);
        digestRandomGenerator.addSeedMaterial(bArr2);
        return new BcTlsNonceGenerator(digestRandomGenerator);
    }

    protected TlsNullCipher createNullCipher(TlsCryptoParameters tlsCryptoParameters, int i) throws IOException {
        return new TlsNullCipher(tlsCryptoParameters, createMAC(tlsCryptoParameters, i), createMAC(tlsCryptoParameters, i));
    }

    protected BlockCipher createSEEDEngine() {
        return new SEEDEngine();
    }

    protected BlockCipher createSM4Engine() {
        return new SM4Engine();
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6Client createSRP6Client(TlsSRPConfig tlsSRPConfig) {
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        SRP6GroupParameters sRP6GroupParameters = new SRP6GroupParameters(explicitNG[0], explicitNG[1]);
        SRP6Client sRP6Client = new SRP6Client();
        sRP6Client.init(sRP6GroupParameters, createDigest(2), getSecureRandom());
        return new BcTlsSRP6Client(sRP6Client);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6Server createSRP6Server(TlsSRPConfig tlsSRPConfig, BigInteger bigInteger) {
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        SRP6GroupParameters sRP6GroupParameters = new SRP6GroupParameters(explicitNG[0], explicitNG[1]);
        SRP6Server sRP6Server = new SRP6Server();
        sRP6Server.init(sRP6GroupParameters, bigInteger, createDigest(2), getSecureRandom());
        return new BcTlsSRP6Server(sRP6Server);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSRP6VerifierGenerator createSRP6VerifierGenerator(TlsSRPConfig tlsSRPConfig) {
        BigInteger[] explicitNG = tlsSRPConfig.getExplicitNG();
        SRP6VerifierGenerator sRP6VerifierGenerator = new SRP6VerifierGenerator();
        sRP6VerifierGenerator.init(explicitNG[0], explicitNG[1], createDigest(2));
        return new BcTlsSRP6VerifierGenerator(sRP6VerifierGenerator);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret createSecret(byte[] bArr) {
        return adoptLocalSecret(Arrays.clone(bArr));
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret generateRSAPreMasterSecret(ProtocolVersion protocolVersion) {
        byte[] bArr = new byte[48];
        getSecureRandom().nextBytes(bArr);
        TlsUtils.writeVersion(protocolVersion, bArr, 0);
        return adoptLocalSecret(bArr);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public SecureRandom getSecureRandom() {
        return this.entropySource;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasAnyStreamVerifiers(Vector vector) {
        int size = vector.size();
        for (int i = 0; i < size; i++) {
            int from = SignatureScheme.from((SignatureAndHashAlgorithm) vector.elementAt(i));
            if (from == 2055 || from == 2056) {
                return true;
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
        switch (i) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                return true;
            default:
                return false;
        }
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
        if (i != 0) {
            switch (i) {
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case 14:
                case 15:
                case 16:
                case 17:
                case 18:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                case 24:
                case 25:
                case 26:
                case 27:
                case 28:
                    return true;
                default:
                    return false;
            }
        }
        return true;
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
        return NamedGroup.refersToASpecificGroup(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasRSAEncryption() {
        return true;
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
        return signatureAndHashAlgorithm.getHash() != 1 ? hasSignatureAlgorithm(signature) : 1 == signature && hasSignatureAlgorithm(signature);
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public boolean hasSignatureScheme(int i) {
        if (i != 1800) {
            short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(i);
            return SignatureScheme.getCryptoHashAlgorithm(i) != 1 ? hasSignatureAlgorithm(signatureAlgorithm) : 1 == signatureAlgorithm && hasSignatureAlgorithm(signatureAlgorithm);
        }
        return false;
    }

    @Override // org.bouncycastle.tls.crypto.TlsCrypto
    public TlsSecret hkdfInit(int i) {
        return adoptLocalSecret(new byte[TlsCryptoUtils.getHashOutputSize(i)]);
    }
}