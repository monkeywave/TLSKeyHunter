package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.openjsse.sun.security.internal.spec.TlsMasterSecretParameterSpec;
import org.openjsse.sun.security.ssl.CipherSuite;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLMasterKeyDerivation.class */
enum SSLMasterKeyDerivation implements SSLKeyDerivationGenerator {
    SSL30("kdf_ssl30"),
    TLS10("kdf_tls10"),
    TLS12("kdf_tls12");
    
    final String name;

    SSLMasterKeyDerivation(String name) {
        this.name = name;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLMasterKeyDerivation valueOf(ProtocolVersion protocolVersion) {
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
            default:
                return null;
        }
    }

    @Override // org.openjsse.sun.security.ssl.SSLKeyDerivationGenerator
    public SSLKeyDerivation createKeyDerivation(HandshakeContext context, SecretKey secretKey) throws IOException {
        return new LegacyMasterKeyDerivation(context, secretKey);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLMasterKeyDerivation$LegacyMasterKeyDerivation.class */
    private static final class LegacyMasterKeyDerivation implements SSLKeyDerivation {
        final HandshakeContext context;
        final SecretKey preMasterSecret;

        LegacyMasterKeyDerivation(HandshakeContext context, SecretKey preMasterSecret) {
            this.context = context;
            this.preMasterSecret = preMasterSecret;
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
        public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec params) throws IOException {
            String masterAlg;
            CipherSuite.HashAlg hashAlg;
            TlsMasterSecretParameterSpec spec;
            CipherSuite cipherSuite = this.context.negotiatedCipherSuite;
            ProtocolVersion protocolVersion = this.context.negotiatedProtocol;
            byte majorVersion = protocolVersion.major;
            byte minorVersion = protocolVersion.minor;
            if (protocolVersion.isDTLS) {
                if (protocolVersion.f978id == ProtocolVersion.DTLS10.f978id) {
                    majorVersion = ProtocolVersion.TLS11.major;
                    minorVersion = ProtocolVersion.TLS11.minor;
                    masterAlg = "SunTlsMasterSecret";
                    hashAlg = CipherSuite.HashAlg.H_NONE;
                } else {
                    majorVersion = ProtocolVersion.TLS12.major;
                    minorVersion = ProtocolVersion.TLS12.minor;
                    masterAlg = "SunTls12MasterSecret";
                    hashAlg = cipherSuite.hashAlg;
                }
            } else if (protocolVersion.f978id >= ProtocolVersion.TLS12.f978id) {
                masterAlg = "SunTls12MasterSecret";
                hashAlg = cipherSuite.hashAlg;
            } else {
                masterAlg = "SunTlsMasterSecret";
                hashAlg = CipherSuite.HashAlg.H_NONE;
            }
            if (this.context.handshakeSession.useExtendedMasterSecret) {
                masterAlg = "SunTlsExtendedMasterSecret";
                this.context.handshakeHash.utilize();
                byte[] sessionHash = this.context.handshakeHash.digest();
                spec = new TlsMasterSecretParameterSpec(this.preMasterSecret, majorVersion & 255, minorVersion & 255, sessionHash, hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
            } else {
                spec = new TlsMasterSecretParameterSpec(this.preMasterSecret, majorVersion & 255, minorVersion & 255, this.context.clientHelloRandom.randomBytes, this.context.serverHelloRandom.randomBytes, hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
            }
            try {
                KeyGenerator kg = JsseJce.getKeyGenerator(masterAlg);
                kg.init(spec);
                return kg.generateKey();
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException iae) {
                if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                    SSLLogger.fine("RSA master secret generation error.", iae);
                }
                throw new ProviderException(iae);
            }
        }
    }
}