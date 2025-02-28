package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;
import org.openjsse.sun.security.ssl.SSLCipher;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.SSLTrafficKeyDerivation;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ChangeCipherSpec.class */
public final class ChangeCipherSpec {
    static final SSLConsumer t10Consumer = new T10ChangeCipherSpecConsumer();
    static final HandshakeProducer t10Producer = new T10ChangeCipherSpecProducer();
    static final SSLConsumer t13Consumer = new T13ChangeCipherSpecConsumer();

    ChangeCipherSpec() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ChangeCipherSpec$T10ChangeCipherSpecProducer.class */
    private static final class T10ChangeCipherSpecProducer implements HandshakeProducer {
        private T10ChangeCipherSpecProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            Authenticator writeAuthenticator;
            HandshakeContext hc = (HandshakeContext) context;
            SSLKeyDerivation kd = hc.handshakeKeyDerivation;
            if (!(kd instanceof SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation)) {
                throw new UnsupportedOperationException("Not supported.");
            }
            SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation tkd = (SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation) kd;
            CipherSuite ncs = hc.negotiatedCipherSuite;
            if (ncs.bulkCipher.cipherType == CipherType.AEAD_CIPHER) {
                writeAuthenticator = Authenticator.valueOf(hc.negotiatedProtocol);
            } else {
                try {
                    writeAuthenticator = Authenticator.valueOf(hc.negotiatedProtocol, ncs.macAlg, tkd.getTrafficKey(hc.sslConfig.isClientMode ? "clientMacKey" : "serverMacKey"));
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    throw new SSLException("Algorithm missing:  ", e);
                }
            }
            SecretKey writeKey = tkd.getTrafficKey(hc.sslConfig.isClientMode ? "clientWriteKey" : "serverWriteKey");
            SecretKey writeIv = tkd.getTrafficKey(hc.sslConfig.isClientMode ? "clientWriteIv" : "serverWriteIv");
            IvParameterSpec iv = writeIv == null ? null : new IvParameterSpec(writeIv.getEncoded());
            try {
                SSLCipher.SSLWriteCipher writeCipher = ncs.bulkCipher.createWriteCipher(writeAuthenticator, hc.negotiatedProtocol, writeKey, iv, hc.sslContext.getSecureRandom());
                if (writeCipher == null) {
                    throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + ncs + ") and protocol version (" + hc.negotiatedProtocol + ")");
                }
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Produced ChangeCipherSpec message", new Object[0]);
                }
                hc.conContext.outputRecord.changeWriteCiphers(writeCipher, true);
                return null;
            } catch (GeneralSecurityException gse) {
                throw new SSLException("Algorithm missing:  ", gse);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ChangeCipherSpec$T10ChangeCipherSpecConsumer.class */
    private static final class T10ChangeCipherSpecConsumer implements SSLConsumer {
        private T10ChangeCipherSpecConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            Authenticator readAuthenticator;
            TransportContext tc = (TransportContext) context;
            tc.consumers.remove(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id));
            if (message.remaining() != 1 || message.get() != 1) {
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE, "Malformed or unexpected ChangeCipherSpec message");
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ChangeCipherSpec message", new Object[0]);
            }
            if (tc.handshakeContext == null) {
                throw tc.fatal(Alert.HANDSHAKE_FAILURE, "Unexpected ChangeCipherSpec message");
            }
            HandshakeContext hc = tc.handshakeContext;
            if (hc.handshakeKeyDerivation == null) {
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected ChangeCipherSpec message");
            }
            SSLKeyDerivation kd = hc.handshakeKeyDerivation;
            if (kd instanceof SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation) {
                SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation tkd = (SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation) kd;
                CipherSuite ncs = hc.negotiatedCipherSuite;
                if (ncs.bulkCipher.cipherType == CipherType.AEAD_CIPHER) {
                    readAuthenticator = Authenticator.valueOf(hc.negotiatedProtocol);
                } else {
                    try {
                        readAuthenticator = Authenticator.valueOf(hc.negotiatedProtocol, ncs.macAlg, tkd.getTrafficKey(hc.sslConfig.isClientMode ? "serverMacKey" : "clientMacKey"));
                    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                        throw new SSLException("Algorithm missing:  ", e);
                    }
                }
                SecretKey readKey = tkd.getTrafficKey(hc.sslConfig.isClientMode ? "serverWriteKey" : "clientWriteKey");
                SecretKey readIv = tkd.getTrafficKey(hc.sslConfig.isClientMode ? "serverWriteIv" : "clientWriteIv");
                IvParameterSpec iv = readIv == null ? null : new IvParameterSpec(readIv.getEncoded());
                try {
                    SSLCipher.SSLReadCipher readCipher = ncs.bulkCipher.createReadCipher(readAuthenticator, hc.negotiatedProtocol, readKey, iv, hc.sslContext.getSecureRandom());
                    if (readCipher == null) {
                        throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + hc.negotiatedCipherSuite + ") and protocol version (" + hc.negotiatedProtocol + ")");
                    }
                    tc.inputRecord.changeReadCiphers(readCipher);
                    return;
                } catch (GeneralSecurityException gse) {
                    throw new SSLException("Algorithm missing:  ", gse);
                }
            }
            throw new UnsupportedOperationException("Not supported.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/ChangeCipherSpec$T13ChangeCipherSpecConsumer.class */
    private static final class T13ChangeCipherSpecConsumer implements SSLConsumer {
        private T13ChangeCipherSpecConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            TransportContext tc = (TransportContext) context;
            tc.consumers.remove(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id));
            if (message.remaining() != 1 || message.get() != 1) {
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE, "Malformed or unexpected ChangeCipherSpec message");
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ChangeCipherSpec message", new Object[0]);
            }
        }
    }
}