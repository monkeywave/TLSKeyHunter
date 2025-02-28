package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.CipherSuite;
import sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import sun.security.internal.spec.TlsKeyMaterialSpec;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation.class */
public enum SSLTrafficKeyDerivation implements SSLKeyDerivationGenerator {
    SSL30("kdf_ssl30", new S30TrafficKeyDerivationGenerator()),
    TLS10("kdf_tls10", new T10TrafficKeyDerivationGenerator()),
    TLS12("kdf_tls12", new T12TrafficKeyDerivationGenerator()),
    TLS13("kdf_tls13", new T13TrafficKeyDerivationGenerator());
    
    final String name;
    final SSLKeyDerivationGenerator keyDerivationGenerator;

    SSLTrafficKeyDerivation(String name, SSLKeyDerivationGenerator keyDerivationGenerator) {
        this.name = name;
        this.keyDerivationGenerator = keyDerivationGenerator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLTrafficKeyDerivation valueOf(ProtocolVersion protocolVersion) {
        switch (protocolVersion) {
            case SSL30:
                return SSL30;
            case TLS10:
            case TLS11:
            case DTLS10:
                return TLS10;
            case TLS12:
            case DTLS12:
                return TLS12;
            case TLS13:
                return TLS13;
            default:
                return null;
        }
    }

    @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
    public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
        return this.keyDerivationGenerator.createKeyDerivation(context, secretKey);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$S30TrafficKeyDerivationGenerator.class */
    private static final class S30TrafficKeyDerivationGenerator implements SSLKeyDerivationGenerator {
        private S30TrafficKeyDerivationGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
            return new LegacyTrafficKeyDerivation(context, secretKey);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$T10TrafficKeyDerivationGenerator.class */
    private static final class T10TrafficKeyDerivationGenerator implements SSLKeyDerivationGenerator {
        private T10TrafficKeyDerivationGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
            return new LegacyTrafficKeyDerivation(context, secretKey);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$T12TrafficKeyDerivationGenerator.class */
    private static final class T12TrafficKeyDerivationGenerator implements SSLKeyDerivationGenerator {
        private T12TrafficKeyDerivationGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
            return new LegacyTrafficKeyDerivation(context, secretKey);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$T13TrafficKeyDerivationGenerator.class */
    private static final class T13TrafficKeyDerivationGenerator implements SSLKeyDerivationGenerator {
        private T13TrafficKeyDerivationGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
            return new T13TrafficKeyDerivation(context, secretKey);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$T13TrafficKeyDerivation.class */
    static final class T13TrafficKeyDerivation implements SSLKeyDerivation {

        /* renamed from: cs */
        private final CipherSuite f1006cs;
        private final SecretKey secret;

        T13TrafficKeyDerivation(HandshakeContext context, SecretKey secret) {
            this.secret = secret;
            this.f1006cs = context.negotiatedCipherSuite;
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
        public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
            KeySchedule ks = KeySchedule.valueOf(algorithm);
            try {
                HKDF hkdf = new HKDF(this.f1006cs.hashAlg.name);
                byte[] hkdfInfo = createHkdfInfo(ks.label, ks.getKeyLength(this.f1006cs));
                return hkdf.expand(this.secret, hkdfInfo, ks.getKeyLength(this.f1006cs), ks.getAlgorithm(this.f1006cs, algorithm));
            } catch (GeneralSecurityException gse) {
                throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(gse));
            }
        }

        private static byte[] createHkdfInfo(byte[] label, int length) throws IOException {
            byte[] info = new byte[4 + label.length];
            ByteBuffer m = ByteBuffer.wrap(info);
            try {
                Record.putInt16(m, length);
                Record.putBytes8(m, label);
                Record.putInt8(m, 0);
                return info;
            } catch (IOException ioe) {
                throw new RuntimeException("Unexpected exception", ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$KeySchedule.class */
    private enum KeySchedule {
        TlsKey("key", false),
        TlsIv("iv", true),
        TlsUpdateNplus1("traffic upd", false);
        
        private final byte[] label;
        private final boolean isIv;

        KeySchedule(String label, boolean isIv) {
            this.label = ("tls13 " + label).getBytes();
            this.isIv = isIv;
        }

        int getKeyLength(CipherSuite cs) {
            if (this == TlsUpdateNplus1) {
                return cs.hashAlg.hashLength;
            }
            return this.isIv ? cs.bulkCipher.ivSize : cs.bulkCipher.keySize;
        }

        String getAlgorithm(CipherSuite cs, String algorithm) {
            return this.isIv ? algorithm : cs.bulkCipher.algorithm;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTrafficKeyDerivation$LegacyTrafficKeyDerivation.class */
    static final class LegacyTrafficKeyDerivation implements SSLKeyDerivation {
        private final HandshakeContext context;
        private final SecretKey masterSecret;
        private final TlsKeyMaterialSpec keyMaterialSpec;

        LegacyTrafficKeyDerivation(HandshakeContext context, SecretKey masterSecret) {
            String keyMaterialAlg;
            CipherSuite.HashAlg hashAlg;
            this.context = context;
            this.masterSecret = masterSecret;
            CipherSuite cipherSuite = context.negotiatedCipherSuite;
            ProtocolVersion protocolVersion = context.negotiatedProtocol;
            int hashSize = cipherSuite.macAlg.size;
            boolean is_exportable = cipherSuite.exportable;
            SSLCipher cipher = cipherSuite.bulkCipher;
            int expandedKeySize = is_exportable ? cipher.expandedKeySize : 0;
            byte majorVersion = protocolVersion.major;
            byte minorVersion = protocolVersion.minor;
            if (protocolVersion.isDTLS) {
                if (protocolVersion.f978id == ProtocolVersion.DTLS10.f978id) {
                    majorVersion = ProtocolVersion.TLS11.major;
                    minorVersion = ProtocolVersion.TLS11.minor;
                    keyMaterialAlg = "SunTlsKeyMaterial";
                    hashAlg = CipherSuite.HashAlg.H_NONE;
                } else {
                    majorVersion = ProtocolVersion.TLS12.major;
                    minorVersion = ProtocolVersion.TLS12.minor;
                    keyMaterialAlg = "SunTls12KeyMaterial";
                    hashAlg = cipherSuite.hashAlg;
                }
            } else if (protocolVersion.f978id >= ProtocolVersion.TLS12.f978id) {
                keyMaterialAlg = "SunTls12KeyMaterial";
                hashAlg = cipherSuite.hashAlg;
            } else {
                keyMaterialAlg = "SunTlsKeyMaterial";
                hashAlg = CipherSuite.HashAlg.H_NONE;
            }
            int ivSize = cipher.ivSize;
            if (cipher.cipherType == CipherType.AEAD_CIPHER) {
                ivSize = cipher.fixedIvSize;
            } else if (cipher.cipherType == CipherType.BLOCK_CIPHER && protocolVersion.useTLS11PlusSpec()) {
                ivSize = 0;
            }
            AlgorithmParameterSpec tlsKeyMaterialParameterSpec = new TlsKeyMaterialParameterSpec(masterSecret, majorVersion & 255, minorVersion & 255, context.clientHelloRandom.randomBytes, context.serverHelloRandom.randomBytes, cipher.algorithm, cipher.keySize, expandedKeySize, ivSize, hashSize, hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
            try {
                KeyGenerator kg = JsseJce.getKeyGenerator(keyMaterialAlg);
                kg.init(tlsKeyMaterialParameterSpec);
                this.keyMaterialSpec = kg.generateKey();
            } catch (GeneralSecurityException e) {
                throw new ProviderException(e);
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public SecretKey getTrafficKey(String algorithm) {
            boolean z = true;
            switch (algorithm.hashCode()) {
                case -1716638551:
                    if (algorithm.equals("serverWriteIv")) {
                        z = true;
                        break;
                    }
                    break;
                case -1702941973:
                    if (algorithm.equals("clientWriteKey")) {
                        z = true;
                        break;
                    }
                    break;
                case -1676186013:
                    if (algorithm.equals("serverWriteKey")) {
                        z = true;
                        break;
                    }
                    break;
                case -1622415813:
                    if (algorithm.equals("clientMacKey")) {
                        z = false;
                        break;
                    }
                    break;
                case 1720625075:
                    if (algorithm.equals("serverMacKey")) {
                        z = true;
                        break;
                    }
                    break;
                case 2023276321:
                    if (algorithm.equals("clientWriteIv")) {
                        z = true;
                        break;
                    }
                    break;
            }
            switch (z) {
                case false:
                    return this.keyMaterialSpec.getClientMacKey();
                case true:
                    return this.keyMaterialSpec.getServerMacKey();
                case true:
                    return this.keyMaterialSpec.getClientCipherKey();
                case true:
                    return this.keyMaterialSpec.getServerCipherKey();
                case true:
                    IvParameterSpec cliIvSpec = this.keyMaterialSpec.getClientIv();
                    if (cliIvSpec == null) {
                        return null;
                    }
                    return new SecretKeySpec(cliIvSpec.getIV(), "TlsIv");
                case true:
                    IvParameterSpec srvIvSpec = this.keyMaterialSpec.getServerIv();
                    if (srvIvSpec == null) {
                        return null;
                    }
                    return new SecretKeySpec(srvIvSpec.getIV(), "TlsIv");
                default:
                    return null;
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
        public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
            return getTrafficKey(algorithm);
        }
    }
}