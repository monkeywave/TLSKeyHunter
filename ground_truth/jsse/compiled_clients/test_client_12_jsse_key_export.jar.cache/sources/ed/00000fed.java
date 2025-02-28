package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import org.openjsse.javax.net.ssl.SSLEngine;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.X509Authentication;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest.class */
final class CertificateRequest {
    static final SSLConsumer t10HandshakeConsumer = new T10CertificateRequestConsumer();
    static final HandshakeProducer t10HandshakeProducer = new T10CertificateRequestProducer();
    static final SSLConsumer t12HandshakeConsumer = new T12CertificateRequestConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12CertificateRequestProducer();
    static final SSLConsumer t13HandshakeConsumer = new T13CertificateRequestConsumer();
    static final HandshakeProducer t13HandshakeProducer = new T13CertificateRequestProducer();

    CertificateRequest() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$ClientCertificateType.class */
    public enum ClientCertificateType {
        RSA_SIGN((byte) 1, "rsa_sign", "RSA", true),
        DSS_SIGN((byte) 2, "dss_sign", "DSA", true),
        RSA_FIXED_DH((byte) 3, "rsa_fixed_dh"),
        DSS_FIXED_DH((byte) 4, "dss_fixed_dh"),
        RSA_EPHEMERAL_DH((byte) 5, "rsa_ephemeral_dh"),
        DSS_EPHEMERAL_DH((byte) 6, "dss_ephemeral_dh"),
        FORTEZZA_DMS((byte) 20, "fortezza_dms"),
        ECDSA_SIGN((byte) 64, "ecdsa_sign", "EC", JsseJce.isEcAvailable()),
        RSA_FIXED_ECDH((byte) 65, "rsa_fixed_ecdh"),
        ECDSA_FIXED_ECDH((byte) 66, "ecdsa_fixed_ecdh");
        
        private static final byte[] CERT_TYPES;

        /* renamed from: id */
        final byte f963id;
        final String name;
        final String keyAlgorithm;
        final boolean isAvailable;

        static {
            CERT_TYPES = JsseJce.isEcAvailable() ? new byte[]{ECDSA_SIGN.f963id, RSA_SIGN.f963id, DSS_SIGN.f963id} : new byte[]{RSA_SIGN.f963id, DSS_SIGN.f963id};
        }

        ClientCertificateType(byte id, String name) {
            this(id, name, null, false);
        }

        ClientCertificateType(byte id, String name, String keyAlgorithm, boolean isAvailable) {
            this.f963id = id;
            this.name = name;
            this.keyAlgorithm = keyAlgorithm;
            this.isAvailable = isAvailable;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String nameOf(byte id) {
            ClientCertificateType[] values;
            for (ClientCertificateType cct : values()) {
                if (cct.f963id == id) {
                    return cct.name;
                }
            }
            return "UNDEFINED-CLIENT-CERTIFICATE-TYPE(" + ((int) id) + ")";
        }

        private static ClientCertificateType valueOf(byte id) {
            ClientCertificateType[] values;
            for (ClientCertificateType cct : values()) {
                if (cct.f963id == id) {
                    return cct;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String[] getKeyTypes(byte[] ids) {
            ArrayList<String> keyTypes = new ArrayList<>(3);
            for (byte id : ids) {
                ClientCertificateType cct = valueOf(id);
                if (cct.isAvailable) {
                    keyTypes.add(cct.keyAlgorithm);
                }
            }
            return (String[]) keyTypes.toArray(new String[0]);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T10CertificateRequestMessage.class */
    static final class T10CertificateRequestMessage extends SSLHandshake.HandshakeMessage {
        final byte[] types;
        final List<byte[]> authorities;

        T10CertificateRequestMessage(HandshakeContext handshakeContext, X509Certificate[] trustedCerts, CipherSuite.KeyExchange keyExchange) {
            super(handshakeContext);
            this.authorities = new ArrayList(trustedCerts.length);
            for (X509Certificate cert : trustedCerts) {
                X500Principal x500Principal = cert.getSubjectX500Principal();
                this.authorities.add(x500Principal.getEncoded());
            }
            this.types = ClientCertificateType.CERT_TYPES;
        }

        T10CertificateRequestMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() < 4) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Incorrect CertificateRequest message: no sufficient data");
            }
            this.types = Record.getBytes8(m);
            int listLen = Record.getInt16(m);
            if (listLen > m.remaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Incorrect CertificateRequest message:no sufficient data");
            }
            if (listLen > 0) {
                this.authorities = new LinkedList();
                while (listLen > 0) {
                    byte[] encoded = Record.getBytes16(m);
                    listLen -= 2 + encoded.length;
                    this.authorities.add(encoded);
                }
                return;
            }
            this.authorities = Collections.emptyList();
        }

        String[] getKeyTypes() {
            return ClientCertificateType.getKeyTypes(this.types);
        }

        X500Principal[] getAuthorities() {
            List<X500Principal> principals = new ArrayList<>(this.authorities.size());
            for (byte[] encoded : this.authorities) {
                X500Principal principal = new X500Principal(encoded);
                principals.add(principal);
            }
            return (X500Principal[]) principals.toArray(new X500Principal[0]);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_REQUEST;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int len = 1 + this.types.length + 2;
            for (byte[] encoded : this.authorities) {
                len += encoded.length + 2;
            }
            return len;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes8(this.types);
            int listLen = 0;
            for (byte[] encoded : this.authorities) {
                listLen += encoded.length + 2;
            }
            hos.putInt16(listLen);
            for (byte[] encoded2 : this.authorities) {
                hos.putBytes16(encoded2);
            }
        }

        public String toString() {
            byte[] bArr;
            MessageFormat messageFormat = new MessageFormat("\"CertificateRequest\": '{'\n  \"certificate types\": {0}\n  \"certificate authorities\": {1}\n'}'", Locale.ENGLISH);
            List<String> typeNames = new ArrayList<>(this.types.length);
            for (byte type : this.types) {
                typeNames.add(ClientCertificateType.nameOf(type));
            }
            List<String> authorityNames = new ArrayList<>(this.authorities.size());
            for (byte[] encoded : this.authorities) {
                X500Principal principal = new X500Principal(encoded);
                authorityNames.add(principal.toString());
            }
            Object[] messageFields = {typeNames, authorityNames};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T10CertificateRequestProducer.class */
    private static final class T10CertificateRequestProducer implements HandshakeProducer {
        private T10CertificateRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            X509Certificate[] caCerts = shc.sslContext.getX509TrustManager().getAcceptedIssuers();
            T10CertificateRequestMessage crm = new T10CertificateRequestMessage(shc, caCerts, shc.negotiatedCipherSuite.keyExchange);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateRequest handshake message", crm);
            }
            crm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T10CertificateRequestConsumer.class */
    private static final class T10CertificateRequestConsumer implements SSLConsumer {
        private T10CertificateRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id));
            SSLConsumer certStatCons = chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id));
            if (certStatCons != null) {
                CertificateStatus.handshakeAbsence.absent(context, null);
            }
            T10CertificateRequestMessage crm = new T10CertificateRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateRequest handshake message", crm);
            }
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            X509ExtendedKeyManager km = chc.sslContext.getX509KeyManager();
            String clientAlias = null;
            if (chc.conContext.transport instanceof SSLSocketImpl) {
                clientAlias = km.chooseClientAlias(crm.getKeyTypes(), crm.getAuthorities(), (SSLSocket) chc.conContext.transport);
            } else if (chc.conContext.transport instanceof SSLEngineImpl) {
                clientAlias = km.chooseEngineClientAlias(crm.getKeyTypes(), crm.getAuthorities(), (SSLEngine) chc.conContext.transport);
            }
            if (clientAlias == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available client authentication", new Object[0]);
                    return;
                }
                return;
            }
            PrivateKey clientPrivateKey = km.getPrivateKey(clientAlias);
            if (clientPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available client private key", new Object[0]);
                    return;
                }
                return;
            }
            X509Certificate[] clientCerts = km.getCertificateChain(clientAlias);
            if (clientCerts == null || clientCerts.length == 0) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available client certificate", new Object[0]);
                    return;
                }
                return;
            }
            chc.handshakePossessions.add(new X509Authentication.X509Possession(clientPrivateKey, clientCerts));
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T12CertificateRequestMessage.class */
    static final class T12CertificateRequestMessage extends SSLHandshake.HandshakeMessage {
        final byte[] types;
        final int[] algorithmIds;
        final List<byte[]> authorities;

        T12CertificateRequestMessage(HandshakeContext handshakeContext, X509Certificate[] trustedCerts, CipherSuite.KeyExchange keyExchange, List<SignatureScheme> signatureSchemes) throws IOException {
            super(handshakeContext);
            this.types = ClientCertificateType.CERT_TYPES;
            if (signatureSchemes == null || signatureSchemes.isEmpty()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No signature algorithms specified for CertificateRequest hanshake message");
            }
            this.algorithmIds = new int[signatureSchemes.size()];
            int i = 0;
            for (SignatureScheme scheme : signatureSchemes) {
                int i2 = i;
                i++;
                this.algorithmIds[i2] = scheme.f1007id;
            }
            this.authorities = new ArrayList(trustedCerts.length);
            for (X509Certificate cert : trustedCerts) {
                X500Principal x500Principal = cert.getSubjectX500Principal();
                this.authorities.add(x500Principal.getEncoded());
            }
        }

        T12CertificateRequestMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() < 8) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: no sufficient data");
            }
            this.types = Record.getBytes8(m);
            if (m.remaining() < 6) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: no sufficient data");
            }
            byte[] algs = Record.getBytes16(m);
            if (algs == null || algs.length == 0 || (algs.length & 1) != 0) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: incomplete signature algorithms");
            }
            this.algorithmIds = new int[algs.length >> 1];
            int i = 0;
            int j = 0;
            while (i < algs.length) {
                int i2 = i;
                int i3 = i + 1;
                byte hash = algs[i2];
                i = i3 + 1;
                byte sign = algs[i3];
                int i4 = j;
                j++;
                this.algorithmIds[i4] = ((hash & 255) << 8) | (sign & 255);
            }
            if (m.remaining() < 2) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: no sufficient data");
            }
            int listLen = Record.getInt16(m);
            if (listLen > m.remaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest message: no sufficient data");
            }
            if (listLen > 0) {
                this.authorities = new LinkedList();
                while (listLen > 0) {
                    byte[] encoded = Record.getBytes16(m);
                    listLen -= 2 + encoded.length;
                    this.authorities.add(encoded);
                }
                return;
            }
            this.authorities = Collections.emptyList();
        }

        String[] getKeyTypes() {
            return ClientCertificateType.getKeyTypes(this.types);
        }

        X500Principal[] getAuthorities() {
            List<X500Principal> principals = new ArrayList<>(this.authorities.size());
            for (byte[] encoded : this.authorities) {
                X500Principal principal = new X500Principal(encoded);
                principals.add(principal);
            }
            return (X500Principal[]) principals.toArray(new X500Principal[0]);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_REQUEST;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int len = 1 + this.types.length + 2 + (this.algorithmIds.length << 1) + 2;
            for (byte[] encoded : this.authorities) {
                len += encoded.length + 2;
            }
            return len;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            int[] iArr;
            hos.putBytes8(this.types);
            int listLen = 0;
            for (byte[] encoded : this.authorities) {
                listLen += encoded.length + 2;
            }
            hos.putInt16(this.algorithmIds.length << 1);
            for (int algorithmId : this.algorithmIds) {
                hos.putInt16(algorithmId);
            }
            hos.putInt16(listLen);
            for (byte[] encoded2 : this.authorities) {
                hos.putBytes16(encoded2);
            }
        }

        public String toString() {
            byte[] bArr;
            int[] iArr;
            MessageFormat messageFormat = new MessageFormat("\"CertificateRequest\": '{'\n  \"certificate types\": {0}\n  \"supported signature algorithms\": {1}\n  \"certificate authorities\": {2}\n'}'", Locale.ENGLISH);
            List<String> typeNames = new ArrayList<>(this.types.length);
            for (byte type : this.types) {
                typeNames.add(ClientCertificateType.nameOf(type));
            }
            List<String> algorithmNames = new ArrayList<>(this.algorithmIds.length);
            for (int algorithmId : this.algorithmIds) {
                algorithmNames.add(SignatureScheme.nameOf(algorithmId));
            }
            List<String> authorityNames = new ArrayList<>(this.authorities.size());
            for (byte[] encoded : this.authorities) {
                X500Principal principal = new X500Principal(encoded);
                authorityNames.add(principal.toString());
            }
            Object[] messageFields = {typeNames, algorithmNames, authorityNames};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T12CertificateRequestProducer.class */
    private static final class T12CertificateRequestProducer implements HandshakeProducer {
        private T12CertificateRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.localSupportedSignAlgs == null) {
                shc.localSupportedSignAlgs = SignatureScheme.getSupportedAlgorithms(shc.sslConfig, shc.algorithmConstraints, shc.activeProtocols);
            }
            if (shc.localSupportedSignAlgs == null || shc.localSupportedSignAlgs.isEmpty()) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No supported signature algorithm");
            }
            X509Certificate[] caCerts = shc.sslContext.getX509TrustManager().getAcceptedIssuers();
            T12CertificateRequestMessage crm = new T12CertificateRequestMessage(shc, caCerts, shc.negotiatedCipherSuite.keyExchange, shc.localSupportedSignAlgs);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateRequest handshake message", crm);
            }
            crm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T12CertificateRequestConsumer.class */
    private static final class T12CertificateRequestConsumer implements SSLConsumer {
        private T12CertificateRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            int[] iArr;
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id));
            SSLConsumer certStatCons = chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id));
            if (certStatCons != null) {
                CertificateStatus.handshakeAbsence.absent(context, null);
            }
            T12CertificateRequestMessage crm = new T12CertificateRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateRequest handshake message", crm);
            }
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            List<SignatureScheme> sss = new LinkedList<>();
            for (int id : crm.algorithmIds) {
                SignatureScheme ss = SignatureScheme.valueOf(id);
                if (ss != null) {
                    sss.add(ss);
                }
            }
            chc.peerRequestedSignatureSchemes = sss;
            chc.peerRequestedCertSignSchemes = sss;
            chc.handshakeSession.setPeerSupportedSignatureAlgorithms(sss);
            chc.peerSupportedAuthorities = crm.getAuthorities();
            SSLPossession pos = choosePossession(chc);
            if (pos == null) {
                return;
            }
            chc.handshakePossessions.add(pos);
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
        }

        private static SSLPossession choosePossession(HandshakeContext hc) throws IOException {
            if (hc.peerRequestedCertSignSchemes == null || hc.peerRequestedCertSignSchemes.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No signature and hash algorithms in CertificateRequest", new Object[0]);
                    return null;
                }
                return null;
            }
            Collection<String> checkedKeyTypes = new HashSet<>();
            for (SignatureScheme ss : hc.peerRequestedCertSignSchemes) {
                if (checkedKeyTypes.contains(ss.keyAlgorithm)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("Unsupported authentication scheme: " + ss.name, new Object[0]);
                    }
                } else if (SignatureScheme.getPreferableAlgorithm(hc.peerRequestedSignatureSchemes, ss, hc.negotiatedProtocol) == null) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning("Unable to produce CertificateVerify for signature scheme: " + ss.name, new Object[0]);
                    }
                    checkedKeyTypes.add(ss.keyAlgorithm);
                } else {
                    SSLAuthentication ka = X509Authentication.valueOf(ss);
                    if (ka == null) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.warning("Unsupported authentication scheme: " + ss.name, new Object[0]);
                        }
                        checkedKeyTypes.add(ss.keyAlgorithm);
                    } else {
                        SSLPossession pos = ka.createPossession(hc);
                        if (pos == null) {
                            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                                SSLLogger.warning("Unavailable authentication scheme: " + ss.name, new Object[0]);
                            }
                        } else {
                            return pos;
                        }
                    }
                }
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("No available authentication scheme", new Object[0]);
                return null;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T13CertificateRequestMessage.class */
    static final class T13CertificateRequestMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] requestContext;
        private final SSLExtensions extensions;

        T13CertificateRequestMessage(HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);
            this.requestContext = new byte[0];
            this.extensions = new SSLExtensions(this);
        }

        T13CertificateRequestMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() < 5) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: no sufficient data");
            }
            this.requestContext = Record.getBytes8(m);
            if (m.remaining() < 4) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid CertificateRequest handshake message: no sufficient extensions data");
            }
            SSLExtension[] enabledExtensions = handshakeContext.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE_REQUEST);
            this.extensions = new SSLExtensions(this, m, enabledExtensions);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_REQUEST;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        int messageLength() {
            return 1 + this.requestContext.length + this.extensions.length();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes8(this.requestContext);
            this.extensions.send(hos);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"CertificateRequest\": '{'\n  \"certificate_request_context\": \"{0}\",\n  \"extensions\": [\n{1}\n  ]\n'}'", Locale.ENGLISH);
            Object[] messageFields = {Utilities.toHexString(this.requestContext), Utilities.indent(Utilities.indent(this.extensions.toString()))};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T13CertificateRequestProducer.class */
    private static final class T13CertificateRequestProducer implements HandshakeProducer {
        private T13CertificateRequestProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            T13CertificateRequestMessage crm = new T13CertificateRequestMessage(shc);
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE_REQUEST, shc.negotiatedProtocol);
            crm.extensions.produce(shc, extTypes);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced CertificateRequest message", crm);
            }
            crm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            shc.certRequestContext = (byte[]) crm.requestContext.clone();
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            shc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateRequest$T13CertificateRequestConsumer.class */
    private static final class T13CertificateRequestConsumer implements SSLConsumer {
        private T13CertificateRequestConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_REQUEST.f987id));
            T13CertificateRequestMessage crm = new T13CertificateRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming CertificateRequest handshake message", crm);
            }
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE_REQUEST);
            crm.extensions.consumeOnLoad(chc, extTypes);
            crm.extensions.consumeOnTrade(chc, extTypes);
            chc.certRequestContext = (byte[]) crm.requestContext.clone();
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id), SSLHandshake.CERTIFICATE);
            chc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id), SSLHandshake.CERTIFICATE_VERIFY);
        }
    }
}