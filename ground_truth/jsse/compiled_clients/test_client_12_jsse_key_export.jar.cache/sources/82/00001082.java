package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.text.MessageFormat;
import java.util.Locale;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.SSLBasicKeyDerivation;
import org.openjsse.sun.security.ssl.SSLCipher;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.internal.spec.TlsPrfParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished.class */
final class Finished {
    static final SSLConsumer t12HandshakeConsumer = new T12FinishedConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12FinishedProducer();
    static final SSLConsumer t13HandshakeConsumer = new T13FinishedConsumer();
    static final HandshakeProducer t13HandshakeProducer = new T13FinishedProducer();

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$VerifyDataGenerator.class */
    public interface VerifyDataGenerator {
        byte[] createVerifyData(HandshakeContext handshakeContext, boolean z) throws IOException;
    }

    Finished() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$FinishedMessage.class */
    public static final class FinishedMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] verifyData;

        FinishedMessage(HandshakeContext context) throws IOException {
            super(context);
            VerifyDataScheme vds = VerifyDataScheme.valueOf(context.negotiatedProtocol);
            try {
                byte[] vd = vds.createVerifyData(context, false);
                this.verifyData = vd;
            } catch (IOException ioe) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Failed to generate verify_data", ioe);
            }
        }

        FinishedMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            int verifyDataLen = 12;
            if (context.negotiatedProtocol == ProtocolVersion.SSL30) {
                verifyDataLen = 36;
            } else if (context.negotiatedProtocol.useTLS13PlusSpec()) {
                verifyDataLen = context.negotiatedCipherSuite.hashAlg.hashLength;
            }
            if (m.remaining() != verifyDataLen) {
                throw context.conContext.fatal(Alert.DECODE_ERROR, "Inappropriate finished message: need " + verifyDataLen + " but remaining " + m.remaining() + " bytes verify_data");
            }
            this.verifyData = new byte[verifyDataLen];
            m.get(this.verifyData);
            VerifyDataScheme vd = VerifyDataScheme.valueOf(context.negotiatedProtocol);
            try {
                byte[] myVerifyData = vd.createVerifyData(context, true);
                if (!MessageDigest.isEqual(myVerifyData, this.verifyData)) {
                    throw context.conContext.fatal(Alert.DECRYPT_ERROR, "The Finished message cannot be verified.");
                }
            } catch (IOException ioe) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Failed to generate verify_data", ioe);
            }
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.FINISHED;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            return this.verifyData.length;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.write(this.verifyData);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"Finished\": '{'\n  \"verify data\": '{'\n{0}\n  '}''}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encode(this.verifyData), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$VerifyDataScheme.class */
    enum VerifyDataScheme {
        SSL30("kdf_ssl30", new S30VerifyDataGenerator()),
        TLS10("kdf_tls10", new T10VerifyDataGenerator()),
        TLS12("kdf_tls12", new T12VerifyDataGenerator()),
        TLS13("kdf_tls13", new T13VerifyDataGenerator());
        
        final String name;
        final VerifyDataGenerator generator;

        VerifyDataScheme(String name, VerifyDataGenerator verifyDataGenerator) {
            this.name = name;
            this.generator = verifyDataGenerator;
        }

        static VerifyDataScheme valueOf(ProtocolVersion protocolVersion) {
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

        public byte[] createVerifyData(HandshakeContext context, boolean isValidation) throws IOException {
            if (this.generator != null) {
                return this.generator.createVerifyData(context, isValidation);
            }
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$S30VerifyDataGenerator.class */
    private static final class S30VerifyDataGenerator implements VerifyDataGenerator {
        private S30VerifyDataGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.Finished.VerifyDataGenerator
        public byte[] createVerifyData(HandshakeContext context, boolean isValidation) throws IOException {
            HandshakeHash handshakeHash = context.handshakeHash;
            SecretKey masterSecretKey = context.handshakeSession.getMasterSecret();
            boolean useClientLabel = (context.sslConfig.isClientMode && !isValidation) || (!context.sslConfig.isClientMode && isValidation);
            return handshakeHash.digest(useClientLabel, masterSecretKey);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T10VerifyDataGenerator.class */
    private static final class T10VerifyDataGenerator implements VerifyDataGenerator {
        private T10VerifyDataGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.Finished.VerifyDataGenerator
        public byte[] createVerifyData(HandshakeContext context, boolean isValidation) throws IOException {
            String tlsLabel;
            HandshakeHash handshakeHash = context.handshakeHash;
            SecretKey masterSecretKey = context.handshakeSession.getMasterSecret();
            boolean useClientLabel = (context.sslConfig.isClientMode && !isValidation) || (!context.sslConfig.isClientMode && isValidation);
            if (useClientLabel) {
                tlsLabel = "client finished";
            } else {
                tlsLabel = "server finished";
            }
            try {
                byte[] seed = handshakeHash.digest();
                CipherSuite.HashAlg hashAlg = CipherSuite.HashAlg.H_NONE;
                AlgorithmParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(masterSecretKey, tlsLabel, seed, 12, hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
                KeyGenerator kg = JsseJce.getKeyGenerator("SunTlsPrf");
                kg.init(tlsPrfParameterSpec);
                SecretKey prfKey = kg.generateKey();
                if (!"RAW".equals(prfKey.getFormat())) {
                    throw new ProviderException("Invalid PRF output, format must be RAW. Format received: " + prfKey.getFormat());
                }
                byte[] finished = prfKey.getEncoded();
                return finished;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("PRF failed", e);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T12VerifyDataGenerator.class */
    private static final class T12VerifyDataGenerator implements VerifyDataGenerator {
        private T12VerifyDataGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.Finished.VerifyDataGenerator
        public byte[] createVerifyData(HandshakeContext context, boolean isValidation) throws IOException {
            String tlsLabel;
            CipherSuite cipherSuite = context.negotiatedCipherSuite;
            HandshakeHash handshakeHash = context.handshakeHash;
            SecretKey masterSecretKey = context.handshakeSession.getMasterSecret();
            boolean useClientLabel = (context.sslConfig.isClientMode && !isValidation) || (!context.sslConfig.isClientMode && isValidation);
            if (useClientLabel) {
                tlsLabel = "client finished";
            } else {
                tlsLabel = "server finished";
            }
            try {
                byte[] seed = handshakeHash.digest();
                CipherSuite.HashAlg hashAlg = cipherSuite.hashAlg;
                AlgorithmParameterSpec tlsPrfParameterSpec = new TlsPrfParameterSpec(masterSecretKey, tlsLabel, seed, 12, hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
                KeyGenerator kg = JsseJce.getKeyGenerator("SunTls12Prf");
                kg.init(tlsPrfParameterSpec);
                SecretKey prfKey = kg.generateKey();
                if (!"RAW".equals(prfKey.getFormat())) {
                    throw new ProviderException("Invalid PRF output, format must be RAW. Format received: " + prfKey.getFormat());
                }
                byte[] finished = prfKey.getEncoded();
                return finished;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("PRF failed", e);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T13VerifyDataGenerator.class */
    private static final class T13VerifyDataGenerator implements VerifyDataGenerator {
        private static final byte[] hkdfLabel = "tls13 finished".getBytes();
        private static final byte[] hkdfContext = new byte[0];

        private T13VerifyDataGenerator() {
        }

        @Override // org.openjsse.sun.security.ssl.Finished.VerifyDataGenerator
        public byte[] createVerifyData(HandshakeContext context, boolean isValidation) throws IOException {
            CipherSuite.HashAlg hashAlg = context.negotiatedCipherSuite.hashAlg;
            SecretKey secret = isValidation ? context.baseReadSecret : context.baseWriteSecret;
            SSLBasicKeyDerivation kdf = new SSLBasicKeyDerivation(secret, hashAlg.name, hkdfLabel, hkdfContext, hashAlg.hashLength);
            AlgorithmParameterSpec keySpec = new SSLBasicKeyDerivation.SecretSizeSpec(hashAlg.hashLength);
            SecretKey finishedSecret = kdf.deriveKey("TlsFinishedSecret", keySpec);
            String hmacAlg = "Hmac" + hashAlg.name.replace("-", "");
            try {
                Mac hmac = JsseJce.getMac(hmacAlg);
                hmac.init(finishedSecret);
                return hmac.doFinal(context.handshakeHash.digest());
            } catch (InvalidKeyException | NoSuchAlgorithmException ex) {
                throw new ProviderException("Failed to generate verify_data", ex);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T12FinishedProducer.class */
    private static final class T12FinishedProducer implements HandshakeProducer {
        private T12FinishedProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            if (hc.sslConfig.isClientMode) {
                return onProduceFinished((ClientHandshakeContext) context, message);
            }
            return onProduceFinished((ServerHandshakeContext) context, message);
        }

        private byte[] onProduceFinished(ClientHandshakeContext chc, SSLHandshake.HandshakeMessage message) throws IOException {
            chc.handshakeHash.update();
            FinishedMessage fm = new FinishedMessage(chc);
            ChangeCipherSpec.t10Producer.produce(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client Finished handshake message", fm);
            }
            fm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            if (chc.conContext.secureRenegotiation) {
                chc.conContext.clientVerifyData = fm.verifyData;
            }
            if (!chc.isResumption) {
                chc.conContext.consumers.put(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t10Consumer);
                chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                chc.conContext.inputRecord.expectingFinishFlight();
                return null;
            }
            if (chc.handshakeSession.isRejoinable()) {
                ((SSLSessionContextImpl) chc.sslContext.engineGetClientSessionContext()).put(chc.handshakeSession);
            }
            chc.conContext.conSession = chc.handshakeSession.finish();
            chc.conContext.protocolVersion = chc.negotiatedProtocol;
            chc.handshakeFinished = true;
            if (!chc.sslContext.isDTLS()) {
                chc.conContext.finishHandshake();
                return null;
            }
            return null;
        }

        private byte[] onProduceFinished(ServerHandshakeContext shc, SSLHandshake.HandshakeMessage message) throws IOException {
            shc.handshakeHash.update();
            FinishedMessage fm = new FinishedMessage(shc);
            ChangeCipherSpec.t10Producer.produce(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced server Finished handshake message", fm);
            }
            fm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            if (shc.conContext.secureRenegotiation) {
                shc.conContext.serverVerifyData = fm.verifyData;
            }
            if (shc.isResumption) {
                shc.conContext.consumers.put(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id), ChangeCipherSpec.t10Consumer);
                shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                shc.conContext.inputRecord.expectingFinishFlight();
                return null;
            }
            if (shc.handshakeSession.isRejoinable()) {
                ((SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext()).put(shc.handshakeSession);
            }
            shc.conContext.conSession = shc.handshakeSession.finish();
            shc.conContext.protocolVersion = shc.negotiatedProtocol;
            shc.handshakeFinished = true;
            if (!shc.sslContext.isDTLS()) {
                shc.conContext.finishHandshake();
                return null;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T12FinishedConsumer.class */
    private static final class T12FinishedConsumer implements SSLConsumer {
        private T12FinishedConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            hc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.FINISHED.f987id));
            if (hc.conContext.consumers.containsKey(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id))) {
                throw hc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Missing ChangeCipherSpec message");
            }
            if (hc.sslConfig.isClientMode) {
                onConsumeFinished((ClientHandshakeContext) context, message);
            } else {
                onConsumeFinished((ServerHandshakeContext) context, message);
            }
        }

        private void onConsumeFinished(ClientHandshakeContext chc, ByteBuffer message) throws IOException {
            FinishedMessage fm = new FinishedMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming server Finished handshake message", fm);
            }
            if (chc.conContext.secureRenegotiation) {
                chc.conContext.serverVerifyData = fm.verifyData;
            }
            if (!chc.isResumption) {
                if (chc.handshakeSession.isRejoinable()) {
                    ((SSLSessionContextImpl) chc.sslContext.engineGetClientSessionContext()).put(chc.handshakeSession);
                }
                chc.conContext.conSession = chc.handshakeSession.finish();
                chc.conContext.protocolVersion = chc.negotiatedProtocol;
                chc.handshakeFinished = true;
                if (!chc.sslContext.isDTLS()) {
                    chc.conContext.finishHandshake();
                }
            } else {
                chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
            }
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = chc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(chc, fm);
                }
            }
        }

        private void onConsumeFinished(ServerHandshakeContext shc, ByteBuffer message) throws IOException {
            if (!shc.isResumption && shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected Finished handshake message");
            }
            FinishedMessage fm = new FinishedMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming client Finished handshake message", fm);
            }
            if (shc.conContext.secureRenegotiation) {
                shc.conContext.clientVerifyData = fm.verifyData;
            }
            if (shc.isResumption) {
                if (shc.handshakeSession.isRejoinable()) {
                    ((SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext()).put(shc.handshakeSession);
                }
                shc.conContext.conSession = shc.handshakeSession.finish();
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.handshakeFinished = true;
                if (!shc.sslContext.isDTLS()) {
                    shc.conContext.finishHandshake();
                }
            } else {
                shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
            }
            SSLHandshake[] probableHandshakeMessages = {SSLHandshake.FINISHED};
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer = shc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, fm);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T13FinishedProducer.class */
    private static final class T13FinishedProducer implements HandshakeProducer {
        private T13FinishedProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            if (hc.sslConfig.isClientMode) {
                return onProduceFinished((ClientHandshakeContext) context, message);
            }
            return onProduceFinished((ServerHandshakeContext) context, message);
        }

        private byte[] onProduceFinished(ClientHandshakeContext chc, SSLHandshake.HandshakeMessage message) throws IOException {
            chc.handshakeHash.update();
            FinishedMessage fm = new FinishedMessage(chc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client Finished handshake message", fm);
            }
            fm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            if (chc.conContext.secureRenegotiation) {
                chc.conContext.clientVerifyData = fm.verifyData;
            }
            SSLKeyDerivation kd = chc.handshakeKeyDerivation;
            if (kd == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
            if (kdg == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + chc.negotiatedProtocol);
            }
            try {
                SecretKey writeSecret = kd.deriveKey("TlsClientAppTrafficSecret", null);
                SSLKeyDerivation writeKD = kdg.createKeyDerivation(chc, writeSecret);
                SecretKey writeKey = writeKD.deriveKey("TlsKey", null);
                SecretKey writeIvSecret = writeKD.deriveKey("TlsIv", null);
                IvParameterSpec writeIv = new IvParameterSpec(writeIvSecret.getEncoded());
                SSLCipher.SSLWriteCipher writeCipher = chc.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(chc.negotiatedProtocol), chc.negotiatedProtocol, writeKey, writeIv, chc.sslContext.getSecureRandom());
                if (writeCipher == null) {
                    throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + chc.negotiatedCipherSuite + ") and protocol version (" + chc.negotiatedProtocol + ")");
                }
                chc.baseWriteSecret = writeSecret;
                chc.conContext.outputRecord.changeWriteCiphers(writeCipher, false);
                SSLSecretDerivation sd = ((SSLSecretDerivation) kd).forContext(chc);
                SecretKey resumptionMasterSecret = sd.deriveKey("TlsResumptionMasterSecret", null);
                chc.handshakeSession.setResumptionMasterSecret(resumptionMasterSecret);
                chc.conContext.conSession = chc.handshakeSession.finish();
                chc.conContext.protocolVersion = chc.negotiatedProtocol;
                chc.handshakeFinished = true;
                chc.conContext.finishHandshake();
                return null;
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive application secrets", gse);
            }
        }

        private byte[] onProduceFinished(ServerHandshakeContext shc, SSLHandshake.HandshakeMessage message) throws IOException {
            shc.handshakeHash.update();
            FinishedMessage fm = new FinishedMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced server Finished handshake message", fm);
            }
            fm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            SSLKeyDerivation kd = shc.handshakeKeyDerivation;
            if (kd == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
            if (kdg == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
            }
            try {
                SecretKey saltSecret = kd.deriveKey("TlsSaltSecret", null);
                CipherSuite.HashAlg hashAlg = shc.negotiatedCipherSuite.hashAlg;
                HKDF hkdf = new HKDF(hashAlg.name);
                byte[] zeros = new byte[hashAlg.hashLength];
                SecretKeySpec sharedSecret = new SecretKeySpec(zeros, "TlsZeroSecret");
                SecretKey masterSecret = hkdf.extract(saltSecret, sharedSecret, "TlsMasterSecret");
                SSLKeyDerivation secretKD = new SSLSecretDerivation(shc, masterSecret);
                SecretKey writeSecret = secretKD.deriveKey("TlsServerAppTrafficSecret", null);
                SSLKeyDerivation writeKD = kdg.createKeyDerivation(shc, writeSecret);
                SecretKey writeKey = writeKD.deriveKey("TlsKey", null);
                SecretKey writeIvSecret = writeKD.deriveKey("TlsIv", null);
                IvParameterSpec writeIv = new IvParameterSpec(writeIvSecret.getEncoded());
                SSLCipher.SSLWriteCipher writeCipher = shc.negotiatedCipherSuite.bulkCipher.createWriteCipher(Authenticator.valueOf(shc.negotiatedProtocol), shc.negotiatedProtocol, writeKey, writeIv, shc.sslContext.getSecureRandom());
                if (writeCipher == null) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + shc.negotiatedCipherSuite + ") and protocol version (" + shc.negotiatedProtocol + ")");
                }
                shc.baseWriteSecret = writeSecret;
                shc.conContext.outputRecord.changeWriteCiphers(writeCipher, false);
                shc.handshakeKeyDerivation = secretKD;
                if (shc.conContext.secureRenegotiation) {
                    shc.conContext.serverVerifyData = fm.verifyData;
                }
                shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                return null;
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive application secrets", gse);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Finished$T13FinishedConsumer.class */
    private static final class T13FinishedConsumer implements SSLConsumer {
        private T13FinishedConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            if (hc.sslConfig.isClientMode) {
                onConsumeFinished((ClientHandshakeContext) context, message);
            } else {
                onConsumeFinished((ServerHandshakeContext) context, message);
            }
        }

        private void onConsumeFinished(ClientHandshakeContext chc, ByteBuffer message) throws IOException {
            if (!chc.isResumption && (chc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id)) || chc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id)))) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected Finished handshake message");
            }
            FinishedMessage fm = new FinishedMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming server Finished handshake message", fm);
            }
            if (chc.conContext.secureRenegotiation) {
                chc.conContext.serverVerifyData = fm.verifyData;
            }
            chc.conContext.consumers.remove(Byte.valueOf(ContentType.CHANGE_CIPHER_SPEC.f965id));
            chc.handshakeHash.update();
            SSLKeyDerivation kd = chc.handshakeKeyDerivation;
            if (kd == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
            if (kdg == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + chc.negotiatedProtocol);
            }
            if (!chc.isResumption && chc.handshakeSession.isRejoinable()) {
                SSLSessionContextImpl sessionContext = (SSLSessionContextImpl) chc.sslContext.engineGetClientSessionContext();
                sessionContext.put(chc.handshakeSession);
            }
            try {
                SecretKey saltSecret = kd.deriveKey("TlsSaltSecret", null);
                CipherSuite.HashAlg hashAlg = chc.negotiatedCipherSuite.hashAlg;
                HKDF hkdf = new HKDF(hashAlg.name);
                byte[] zeros = new byte[hashAlg.hashLength];
                SecretKeySpec sharedSecret = new SecretKeySpec(zeros, "TlsZeroSecret");
                SecretKey masterSecret = hkdf.extract(saltSecret, sharedSecret, "TlsMasterSecret");
                SSLKeyDerivation secretKD = new SSLSecretDerivation(chc, masterSecret);
                SecretKey readSecret = secretKD.deriveKey("TlsServerAppTrafficSecret", null);
                SSLKeyDerivation writeKD = kdg.createKeyDerivation(chc, readSecret);
                SecretKey readKey = writeKD.deriveKey("TlsKey", null);
                SecretKey readIvSecret = writeKD.deriveKey("TlsIv", null);
                IvParameterSpec readIv = new IvParameterSpec(readIvSecret.getEncoded());
                SSLCipher.SSLReadCipher readCipher = chc.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(chc.negotiatedProtocol), chc.negotiatedProtocol, readKey, readIv, chc.sslContext.getSecureRandom());
                if (readCipher == null) {
                    throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + chc.negotiatedCipherSuite + ") and protocol version (" + chc.negotiatedProtocol + ")");
                }
                chc.baseReadSecret = readSecret;
                chc.conContext.inputRecord.changeReadCiphers(readCipher);
                chc.handshakeKeyDerivation = secretKD;
                chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.FINISHED.f987id), SSLHandshake.FINISHED);
                SSLHandshake[] probableHandshakeMessages = {SSLHandshake.CERTIFICATE, SSLHandshake.CERTIFICATE_VERIFY, SSLHandshake.FINISHED};
                for (SSLHandshake hs : probableHandshakeMessages) {
                    HandshakeProducer handshakeProducer = chc.handshakeProducers.remove(Byte.valueOf(hs.f987id));
                    if (handshakeProducer != null) {
                        handshakeProducer.produce(chc, null);
                    }
                }
            } catch (GeneralSecurityException gse) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive application secrets", gse);
            }
        }

        private void onConsumeFinished(ServerHandshakeContext shc, ByteBuffer message) throws IOException {
            if (!shc.isResumption && (shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id)) || shc.handshakeConsumers.containsKey(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id)))) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected Finished handshake message");
            }
            FinishedMessage fm = new FinishedMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming client Finished handshake message", fm);
            }
            if (shc.conContext.secureRenegotiation) {
                shc.conContext.clientVerifyData = fm.verifyData;
            }
            SSLKeyDerivation kd = shc.handshakeKeyDerivation;
            if (kd == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "no key derivation");
            }
            SSLTrafficKeyDerivation kdg = SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
            if (kdg == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Not supported key derivation: " + shc.negotiatedProtocol);
            }
            if (!shc.isResumption && shc.handshakeSession.isRejoinable()) {
                SSLSessionContextImpl sessionContext = (SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext();
                sessionContext.put(shc.handshakeSession);
            }
            try {
                SecretKey readSecret = kd.deriveKey("TlsClientAppTrafficSecret", null);
                SSLKeyDerivation readKD = kdg.createKeyDerivation(shc, readSecret);
                SecretKey readKey = readKD.deriveKey("TlsKey", null);
                SecretKey readIvSecret = readKD.deriveKey("TlsIv", null);
                IvParameterSpec readIv = new IvParameterSpec(readIvSecret.getEncoded());
                SSLCipher.SSLReadCipher readCipher = shc.negotiatedCipherSuite.bulkCipher.createReadCipher(Authenticator.valueOf(shc.negotiatedProtocol), shc.negotiatedProtocol, readKey, readIv, shc.sslContext.getSecureRandom());
                if (readCipher == null) {
                    throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Illegal cipher suite (" + shc.negotiatedCipherSuite + ") and protocol version (" + shc.negotiatedProtocol + ")");
                }
                shc.baseReadSecret = readSecret;
                shc.conContext.inputRecord.changeReadCiphers(readCipher);
                shc.handshakeHash.update();
                SSLSecretDerivation sd = ((SSLSecretDerivation) kd).forContext(shc);
                SecretKey resumptionMasterSecret = sd.deriveKey("TlsResumptionMasterSecret", null);
                shc.handshakeSession.setResumptionMasterSecret(resumptionMasterSecret);
                shc.conContext.conSession = shc.handshakeSession.finish();
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.handshakeFinished = true;
                if (!shc.sslContext.isDTLS()) {
                    shc.conContext.finishHandshake();
                }
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Sending new session ticket", new Object[0]);
                }
                NewSessionTicket.kickstartProducer.produce(shc);
            } catch (GeneralSecurityException gse) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "Failure to derive application secrets", gse);
            }
        }
    }
}