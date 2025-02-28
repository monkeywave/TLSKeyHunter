package org.openjsse.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.ClientHello;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.X509Authentication;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage.class */
final class CertificateMessage {
    static final SSLConsumer t12HandshakeConsumer = new T12CertificateConsumer();
    static final HandshakeProducer t12HandshakeProducer = new T12CertificateProducer();
    static final SSLConsumer t13HandshakeConsumer = new T13CertificateConsumer();
    static final HandshakeProducer t13HandshakeProducer = new T13CertificateProducer();

    CertificateMessage() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T12CertificateMessage.class */
    public static final class T12CertificateMessage extends SSLHandshake.HandshakeMessage {
        final List<byte[]> encodedCertChain;

        T12CertificateMessage(HandshakeContext handshakeContext, X509Certificate[] certChain) throws SSLException {
            super(handshakeContext);
            List<byte[]> encodedCerts = new ArrayList<>(certChain.length);
            for (X509Certificate cert : certChain) {
                try {
                    encodedCerts.add(cert.getEncoded());
                } catch (CertificateEncodingException cee) {
                    throw handshakeContext.conContext.fatal(Alert.INTERNAL_ERROR, "Could not encode certificate (" + cert.getSubjectX500Principal() + ")", cee);
                }
            }
            this.encodedCertChain = encodedCerts;
        }

        T12CertificateMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            int listLen = Record.getInt24(m);
            if (listLen > m.remaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Error parsing certificate message:no sufficient data");
            }
            if (listLen > 0) {
                List<byte[]> encodedCerts = new LinkedList<>();
                while (listLen > 0) {
                    byte[] encodedCert = Record.getBytes24(m);
                    listLen -= 3 + encodedCert.length;
                    encodedCerts.add(encodedCert);
                    if (encodedCerts.size() > SSLConfiguration.maxCertificateChainLength) {
                        throw new SSLProtocolException("The certificate chain length (" + encodedCerts.size() + ") exceeds the maximum allowed length (" + SSLConfiguration.maxCertificateChainLength + ")");
                    }
                }
                this.encodedCertChain = encodedCerts;
                return;
            }
            this.encodedCertChain = Collections.emptyList();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int msgLen = 3;
            for (byte[] encodedCert : this.encodedCertChain) {
                msgLen += encodedCert.length + 3;
            }
            return msgLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            int listLen = 0;
            for (byte[] encodedCert : this.encodedCertChain) {
                listLen += encodedCert.length + 3;
            }
            hos.putInt24(listLen);
            for (byte[] encodedCert2 : this.encodedCertChain) {
                hos.putBytes24(encodedCert2);
            }
        }

        public String toString() {
            Object obj;
            if (this.encodedCertChain.isEmpty()) {
                return "\"Certificates\": <empty list>";
            }
            Object[] x509Certs = new Object[this.encodedCertChain.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (byte[] encodedCert : this.encodedCertChain) {
                    try {
                        obj = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
                    } catch (CertificateException e) {
                        obj = encodedCert;
                    }
                    int i2 = i;
                    i++;
                    x509Certs[i2] = obj;
                }
            } catch (CertificateException e2) {
                int i3 = 0;
                for (byte[] encodedCert2 : this.encodedCertChain) {
                    int i4 = i3;
                    i3++;
                    x509Certs[i4] = encodedCert2;
                }
            }
            MessageFormat messageFormat = new MessageFormat("\"Certificates\": [\n{0}\n]", Locale.ENGLISH);
            Object[] messageFields = {SSLLogger.toString(x509Certs)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T12CertificateProducer.class */
    private static final class T12CertificateProducer implements HandshakeProducer {
        private T12CertificateProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            if (hc.sslConfig.isClientMode) {
                return onProduceCertificate((ClientHandshakeContext) context, message);
            }
            return onProduceCertificate((ServerHandshakeContext) context, message);
        }

        private byte[] onProduceCertificate(ServerHandshakeContext shc, SSLHandshake.HandshakeMessage message) throws IOException {
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    break;
                }
            }
            if (x509Possession == null) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR, "No expected X.509 certificate for server authentication");
            }
            shc.handshakeSession.setLocalPrivateKey(x509Possession.popPrivateKey);
            shc.handshakeSession.setLocalCertificates(x509Possession.popCerts);
            T12CertificateMessage cm = new T12CertificateMessage(shc, x509Possession.popCerts);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced server Certificate handshake message", cm);
            }
            cm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }

        private byte[] onProduceCertificate(ClientHandshakeContext chc, SSLHandshake.HandshakeMessage message) throws IOException {
            X509Authentication.X509Possession x509Possession = null;
            Iterator<SSLPossession> it = chc.handshakePossessions.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                SSLPossession possession = it.next();
                if (possession instanceof X509Authentication.X509Possession) {
                    x509Possession = (X509Authentication.X509Possession) possession;
                    break;
                }
            }
            if (x509Possession == null) {
                if (chc.negotiatedProtocol.useTLS10PlusSpec()) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("No X.509 certificate for client authentication, use empty Certificate message instead", new Object[0]);
                    }
                    x509Possession = new X509Authentication.X509Possession(null, new X509Certificate[0]);
                } else {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("No X.509 certificate for client authentication, send a no_certificate alert", new Object[0]);
                    }
                    chc.conContext.warning(Alert.NO_CERTIFICATE);
                    return null;
                }
            }
            chc.handshakeSession.setLocalPrivateKey(x509Possession.popPrivateKey);
            if (x509Possession.popCerts != null && x509Possession.popCerts.length != 0) {
                chc.handshakeSession.setLocalCertificates(x509Possession.popCerts);
            } else {
                chc.handshakeSession.setLocalCertificates(null);
            }
            T12CertificateMessage cm = new T12CertificateMessage(chc, x509Possession.popCerts);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced client Certificate handshake message", cm);
            }
            cm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T12CertificateConsumer.class */
    static final class T12CertificateConsumer implements SSLConsumer {
        private T12CertificateConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            hc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id));
            T12CertificateMessage cm = new T12CertificateMessage(hc, message);
            if (hc.sslConfig.isClientMode) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming server Certificate handshake message", cm);
                }
                onCertificate((ClientHandshakeContext) context, cm);
                return;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming client Certificate handshake message", cm);
            }
            onCertificate((ServerHandshakeContext) context, cm);
        }

        private void onCertificate(ServerHandshakeContext shc, T12CertificateMessage certificateMessage) throws IOException {
            List<byte[]> encodedCerts = certificateMessage.encodedCertChain;
            if (encodedCerts == null || encodedCerts.isEmpty()) {
                shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
                if (shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_REQUESTED) {
                    throw shc.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
                }
                return;
            }
            X509Certificate[] x509Certs = new X509Certificate[encodedCerts.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (byte[] encodedCert : encodedCerts) {
                    int i2 = i;
                    i++;
                    x509Certs[i2] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
                }
                checkClientCerts(shc, x509Certs);
                shc.handshakeCredentials.add(new X509Authentication.X509Credentials(x509Certs[0].getPublicKey(), x509Certs));
                shc.handshakeSession.setPeerCertificates(x509Certs);
            } catch (CertificateException ce) {
                throw shc.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", ce);
            }
        }

        private void onCertificate(ClientHandshakeContext chc, T12CertificateMessage certificateMessage) throws IOException {
            String identityAlg;
            List<byte[]> encodedCerts = certificateMessage.encodedCertChain;
            if (encodedCerts == null || encodedCerts.isEmpty()) {
                throw chc.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
            }
            X509Certificate[] x509Certs = new X509Certificate[encodedCerts.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (byte[] encodedCert : encodedCerts) {
                    int i2 = i;
                    i++;
                    x509Certs[i2] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
                }
                if (chc.reservedServerCerts != null && !chc.handshakeSession.useExtendedMasterSecret && (((identityAlg = chc.sslConfig.identificationProtocol) == null || identityAlg.length() == 0) && !isIdentityEquivalent(x509Certs[0], chc.reservedServerCerts[0]))) {
                    throw chc.conContext.fatal(Alert.BAD_CERTIFICATE, "server certificate change is restricted during renegotiation");
                }
                if (chc.staplingActive) {
                    chc.deferredCerts = x509Certs;
                } else {
                    checkServerCerts(chc, x509Certs);
                }
                chc.handshakeCredentials.add(new X509Authentication.X509Credentials(x509Certs[0].getPublicKey(), x509Certs));
                chc.handshakeSession.setPeerCertificates(x509Certs);
            } catch (CertificateException ce) {
                throw chc.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", ce);
            }
        }

        private static boolean isIdentityEquivalent(X509Certificate thisCert, X509Certificate prevCert) {
            if (thisCert.equals(prevCert)) {
                return true;
            }
            Collection<List<?>> thisSubjectAltNames = null;
            try {
                thisSubjectAltNames = thisCert.getSubjectAlternativeNames();
            } catch (CertificateParsingException e) {
                if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                    SSLLogger.fine("Attempt to obtain subjectAltNames extension failed!", new Object[0]);
                }
            }
            Collection<List<?>> prevSubjectAltNames = null;
            try {
                prevSubjectAltNames = prevCert.getSubjectAlternativeNames();
            } catch (CertificateParsingException e2) {
                if (SSLLogger.isOn && SSLLogger.isOn("handshake")) {
                    SSLLogger.fine("Attempt to obtain subjectAltNames extension failed!", new Object[0]);
                }
            }
            if (thisSubjectAltNames != null && prevSubjectAltNames != null) {
                Collection<String> thisSubAltIPAddrs = getSubjectAltNames(thisSubjectAltNames, 7);
                Collection<String> prevSubAltIPAddrs = getSubjectAltNames(prevSubjectAltNames, 7);
                if (thisSubAltIPAddrs != null && prevSubAltIPAddrs != null && isEquivalent(thisSubAltIPAddrs, prevSubAltIPAddrs)) {
                    return true;
                }
                Collection<String> thisSubAltDnsNames = getSubjectAltNames(thisSubjectAltNames, 2);
                Collection<String> prevSubAltDnsNames = getSubjectAltNames(prevSubjectAltNames, 2);
                if (thisSubAltDnsNames != null && prevSubAltDnsNames != null && isEquivalent(thisSubAltDnsNames, prevSubAltDnsNames)) {
                    return true;
                }
            }
            X500Principal thisSubject = thisCert.getSubjectX500Principal();
            X500Principal prevSubject = prevCert.getSubjectX500Principal();
            X500Principal thisIssuer = thisCert.getIssuerX500Principal();
            X500Principal prevIssuer = prevCert.getIssuerX500Principal();
            return !thisSubject.getName().isEmpty() && !prevSubject.getName().isEmpty() && thisSubject.equals(prevSubject) && thisIssuer.equals(prevIssuer);
        }

        private static Collection<String> getSubjectAltNames(Collection<List<?>> subjectAltNames, int type) {
            String subAltDnsName;
            HashSet<String> subAltDnsNames = null;
            for (List<?> subjectAltName : subjectAltNames) {
                int subjectAltNameType = ((Integer) subjectAltName.get(0)).intValue();
                if (subjectAltNameType == type && (subAltDnsName = (String) subjectAltName.get(1)) != null && !subAltDnsName.isEmpty()) {
                    if (subAltDnsNames == null) {
                        subAltDnsNames = new HashSet<>(subjectAltNames.size());
                    }
                    subAltDnsNames.add(subAltDnsName);
                }
            }
            return subAltDnsNames;
        }

        private static boolean isEquivalent(Collection<String> thisSubAltNames, Collection<String> prevSubAltNames) {
            for (String thisSubAltName : thisSubAltNames) {
                for (String prevSubAltName : prevSubAltNames) {
                    if (thisSubAltName.equalsIgnoreCase(prevSubAltName)) {
                        return true;
                    }
                }
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static void checkServerCerts(ClientHandshakeContext chc, X509Certificate[] certs) throws IOException {
            String keyExchangeString;
            X509TrustManager tm = chc.sslContext.getX509TrustManager();
            if (chc.negotiatedCipherSuite.keyExchange == CipherSuite.KeyExchange.K_RSA_EXPORT || chc.negotiatedCipherSuite.keyExchange == CipherSuite.KeyExchange.K_DHE_RSA_EXPORT) {
                keyExchangeString = CipherSuite.KeyExchange.K_RSA.name;
            } else {
                keyExchangeString = chc.negotiatedCipherSuite.keyExchange.name;
            }
            try {
                if (tm instanceof X509ExtendedTrustManager) {
                    if (chc.conContext.transport instanceof SSLEngine) {
                        SSLEngine engine = (SSLEngine) chc.conContext.transport;
                        ((X509ExtendedTrustManager) tm).checkServerTrusted((X509Certificate[]) certs.clone(), keyExchangeString, engine);
                    } else {
                        SSLSocket socket = (SSLSocket) chc.conContext.transport;
                        ((X509ExtendedTrustManager) tm).checkServerTrusted((X509Certificate[]) certs.clone(), keyExchangeString, socket);
                    }
                    chc.handshakeSession.setPeerCertificates(certs);
                    return;
                }
                throw new CertificateException("Improper X509TrustManager implementation");
            } catch (CertificateException ce) {
                throw chc.conContext.fatal(getCertificateAlert(chc, ce), ce);
            }
        }

        private static void checkClientCerts(ServerHandshakeContext shc, X509Certificate[] certs) throws IOException {
            String authType;
            X509TrustManager tm = shc.sslContext.getX509TrustManager();
            PublicKey key = certs[0].getPublicKey();
            String keyAlgorithm = key.getAlgorithm();
            boolean z = true;
            switch (keyAlgorithm.hashCode()) {
                case 2206:
                    if (keyAlgorithm.equals("EC")) {
                        z = true;
                        break;
                    }
                    break;
                case 67986:
                    if (keyAlgorithm.equals("DSA")) {
                        z = true;
                        break;
                    }
                    break;
                case 81440:
                    if (keyAlgorithm.equals("RSA")) {
                        z = false;
                        break;
                    }
                    break;
                case 1775481508:
                    if (keyAlgorithm.equals("RSASSA-PSS")) {
                        z = true;
                        break;
                    }
                    break;
            }
            switch (z) {
                case false:
                case true:
                case true:
                case true:
                    authType = keyAlgorithm;
                    break;
                default:
                    authType = "UNKNOWN";
                    break;
            }
            try {
                if (tm instanceof X509ExtendedTrustManager) {
                    if (shc.conContext.transport instanceof SSLEngine) {
                        SSLEngine engine = (SSLEngine) shc.conContext.transport;
                        ((X509ExtendedTrustManager) tm).checkClientTrusted((X509Certificate[]) certs.clone(), authType, engine);
                    } else {
                        SSLSocket socket = (SSLSocket) shc.conContext.transport;
                        ((X509ExtendedTrustManager) tm).checkClientTrusted((X509Certificate[]) certs.clone(), authType, socket);
                    }
                    return;
                }
                throw new CertificateException("Improper X509TrustManager implementation");
            } catch (CertificateException ce) {
                throw shc.conContext.fatal(Alert.CERTIFICATE_UNKNOWN, ce);
            }
        }

        private static Alert getCertificateAlert(ClientHandshakeContext chc, CertificateException cexc) {
            Alert alert = Alert.CERTIFICATE_UNKNOWN;
            Throwable baseCause = cexc.getCause();
            if (baseCause instanceof CertPathValidatorException) {
                CertPathValidatorException cpve = (CertPathValidatorException) baseCause;
                CertPathValidatorException.Reason reason = cpve.getReason();
                if (reason == CertPathValidatorException.BasicReason.REVOKED) {
                    alert = chc.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_REVOKED;
                } else if (reason == CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS) {
                    alert = chc.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_UNKNOWN;
                } else if (reason == CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED) {
                    alert = Alert.UNSUPPORTED_CERTIFICATE;
                } else if (reason == CertPathValidatorException.BasicReason.EXPIRED) {
                    alert = Alert.CERTIFICATE_EXPIRED;
                } else if (reason == CertPathValidatorException.BasicReason.INVALID_SIGNATURE || reason == CertPathValidatorException.BasicReason.NOT_YET_VALID) {
                    alert = Alert.BAD_CERTIFICATE;
                }
            }
            return alert;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$CertificateEntry.class */
    public static final class CertificateEntry {
        final byte[] encoded;
        private final SSLExtensions extensions;

        CertificateEntry(byte[] encoded, SSLExtensions extensions) {
            this.encoded = encoded;
            this.extensions = extensions;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public int getEncodedSize() {
            int extLen = this.extensions.length();
            if (extLen == 0) {
                extLen = 2;
            }
            return 3 + this.encoded.length + extLen;
        }

        public String toString() {
            Object x509Certs;
            MessageFormat messageFormat = new MessageFormat("\n'{'\n{0}\n  \"extensions\": '{'\n{1}\n  '}'\n'}',", Locale.ENGLISH);
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                x509Certs = cf.generateCertificate(new ByteArrayInputStream(this.encoded));
            } catch (CertificateException e) {
                x509Certs = this.encoded;
            }
            Object[] messageFields = {SSLLogger.toString(x509Certs), Utilities.indent(this.extensions.toString(), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T13CertificateMessage.class */
    public static final class T13CertificateMessage extends SSLHandshake.HandshakeMessage {
        private final byte[] requestContext;
        private final List<CertificateEntry> certEntries;

        T13CertificateMessage(HandshakeContext context, byte[] requestContext, X509Certificate[] certificates) throws SSLException, CertificateException {
            super(context);
            this.requestContext = (byte[]) requestContext.clone();
            this.certEntries = new LinkedList();
            for (X509Certificate cert : certificates) {
                byte[] encoded = cert.getEncoded();
                SSLExtensions extensions = new SSLExtensions(this);
                this.certEntries.add(new CertificateEntry(encoded, extensions));
            }
        }

        T13CertificateMessage(HandshakeContext handshakeContext, byte[] requestContext, List<CertificateEntry> certificates) {
            super(handshakeContext);
            this.requestContext = (byte[]) requestContext.clone();
            this.certEntries = certificates;
        }

        T13CertificateMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            if (m.remaining() < 4) {
                throw new SSLProtocolException("Invalid Certificate message: insufficient data (length=" + m.remaining() + ")");
            }
            this.requestContext = Record.getBytes8(m);
            if (m.remaining() < 3) {
                throw new SSLProtocolException("Invalid Certificate message: insufficient certificate entries data (length=" + m.remaining() + ")");
            }
            int listLen = Record.getInt24(m);
            if (listLen != m.remaining()) {
                throw new SSLProtocolException("Invalid Certificate message: incorrect list length (length=" + listLen + ")");
            }
            SSLExtension[] enabledExtensions = handshakeContext.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE);
            List<CertificateEntry> certList = new LinkedList<>();
            while (m.hasRemaining()) {
                byte[] encodedCert = Record.getBytes24(m);
                if (encodedCert.length == 0) {
                    throw new SSLProtocolException("Invalid Certificate message: empty cert_data");
                }
                SSLExtensions extensions = new SSLExtensions(this, m, enabledExtensions);
                certList.add(new CertificateEntry(encodedCert, extensions));
                if (certList.size() > SSLConfiguration.maxCertificateChainLength) {
                    throw new SSLProtocolException("The certificate chain length (" + certList.size() + ") exceeds the maximum allowed length (" + SSLConfiguration.maxCertificateChainLength + ")");
                }
            }
            this.certEntries = Collections.unmodifiableList(certList);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int msgLen = 4 + this.requestContext.length;
            for (CertificateEntry entry : this.certEntries) {
                msgLen += entry.getEncodedSize();
            }
            return msgLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            int entryListLen = 0;
            for (CertificateEntry entry : this.certEntries) {
                entryListLen += entry.getEncodedSize();
            }
            hos.putBytes8(this.requestContext);
            hos.putInt24(entryListLen);
            for (CertificateEntry entry2 : this.certEntries) {
                hos.putBytes24(entry2.encoded);
                if (entry2.extensions.length() != 0) {
                    entry2.extensions.send(hos);
                } else {
                    hos.putInt16(0);
                }
            }
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"Certificate\": '{'\n  \"certificate_request_context\": \"{0}\",\n  \"certificate_list\": [{1}\n]\n'}'", Locale.ENGLISH);
            StringBuilder builder = new StringBuilder(512);
            for (CertificateEntry entry : this.certEntries) {
                builder.append(entry.toString());
            }
            Object[] messageFields = {Utilities.toHexString(this.requestContext), Utilities.indent(builder.toString())};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T13CertificateProducer.class */
    private static final class T13CertificateProducer implements HandshakeProducer {
        private T13CertificateProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            if (hc.sslConfig.isClientMode) {
                return onProduceCertificate((ClientHandshakeContext) context, message);
            }
            return onProduceCertificate((ServerHandshakeContext) context, message);
        }

        private byte[] onProduceCertificate(ServerHandshakeContext shc, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            SSLPossession pos = choosePossession(shc, clientHello);
            if (pos == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No available authentication scheme");
            }
            if (!(pos instanceof X509Authentication.X509Possession)) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X.509 certificate for server authentication");
            }
            X509Authentication.X509Possession x509Possession = (X509Authentication.X509Possession) pos;
            X509Certificate[] localCerts = x509Possession.popCerts;
            if (localCerts == null || localCerts.length == 0) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No X.509 certificate for server authentication");
            }
            shc.handshakePossessions.add(x509Possession);
            shc.handshakeSession.setLocalPrivateKey(x509Possession.popPrivateKey);
            shc.handshakeSession.setLocalCertificates(localCerts);
            try {
                T13CertificateMessage cm = new T13CertificateMessage(shc, new byte[0], localCerts);
                shc.stapleParams = StatusResponseManager.processStapling(shc);
                shc.staplingActive = shc.stapleParams != null;
                SSLExtension[] enabledCTExts = shc.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE, Arrays.asList(ProtocolVersion.PROTOCOLS_OF_13));
                for (CertificateEntry certEnt : cm.certEntries) {
                    shc.currentCertEntry = certEnt;
                    certEnt.extensions.produce(shc, enabledCTExts);
                }
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Produced server Certificate message", cm);
                }
                cm.write(shc.handshakeOutput);
                shc.handshakeOutput.flush();
                return null;
            } catch (CertificateException | SSLException ce) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to produce server Certificate message", ce);
            }
        }

        private static SSLPossession choosePossession(HandshakeContext hc, ClientHello.ClientHelloMessage clientHello) throws IOException {
            if (hc.peerRequestedCertSignSchemes == null || hc.peerRequestedCertSignSchemes.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No signature_algorithms(_cert) in ClientHello", new Object[0]);
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

        private byte[] onProduceCertificate(ClientHandshakeContext chc, SSLHandshake.HandshakeMessage message) throws IOException {
            X509Certificate[] localCerts;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            SSLPossession pos = choosePossession(chc, clientHello);
            if (pos == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("No available client authentication scheme", new Object[0]);
                }
                localCerts = new X509Certificate[0];
            } else {
                chc.handshakePossessions.add(pos);
                if (!(pos instanceof X509Authentication.X509Possession)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("No X.509 certificate for client authentication", new Object[0]);
                    }
                    localCerts = new X509Certificate[0];
                } else {
                    X509Authentication.X509Possession x509Possession = (X509Authentication.X509Possession) pos;
                    localCerts = x509Possession.popCerts;
                    chc.handshakeSession.setLocalPrivateKey(x509Possession.popPrivateKey);
                }
            }
            if (localCerts != null && localCerts.length != 0) {
                chc.handshakeSession.setLocalCertificates(localCerts);
            } else {
                chc.handshakeSession.setLocalCertificates(null);
            }
            try {
                T13CertificateMessage cm = new T13CertificateMessage(chc, chc.certRequestContext, localCerts);
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Produced client Certificate message", cm);
                }
                cm.write(chc.handshakeOutput);
                chc.handshakeOutput.flush();
                return null;
            } catch (CertificateException | SSLException ce) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Failed to produce client Certificate message", ce);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateMessage$T13CertificateConsumer.class */
    private static final class T13CertificateConsumer implements SSLConsumer {
        private T13CertificateConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            hc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE.f987id));
            T13CertificateMessage cm = new T13CertificateMessage(hc, message);
            if (hc.sslConfig.isClientMode) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Consuming server Certificate handshake message", cm);
                }
                onConsumeCertificate((ClientHandshakeContext) context, cm);
                return;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming client Certificate handshake message", cm);
            }
            onConsumeCertificate((ServerHandshakeContext) context, cm);
        }

        private void onConsumeCertificate(ServerHandshakeContext shc, T13CertificateMessage certificateMessage) throws IOException {
            if (certificateMessage.certEntries == null || certificateMessage.certEntries.isEmpty()) {
                shc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_VERIFY.f987id));
                if (shc.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED) {
                    throw shc.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty client certificate chain");
                }
                return;
            }
            X509Certificate[] cliCerts = checkClientCerts(shc, certificateMessage.certEntries);
            shc.handshakeCredentials.add(new X509Authentication.X509Credentials(cliCerts[0].getPublicKey(), cliCerts));
            shc.handshakeSession.setPeerCertificates(cliCerts);
        }

        private void onConsumeCertificate(ClientHandshakeContext chc, T13CertificateMessage certificateMessage) throws IOException {
            if (certificateMessage.certEntries == null || certificateMessage.certEntries.isEmpty()) {
                throw chc.conContext.fatal(Alert.BAD_CERTIFICATE, "Empty server certificate chain");
            }
            SSLExtension[] enabledExtensions = chc.sslConfig.getEnabledExtensions(SSLHandshake.CERTIFICATE);
            for (CertificateEntry certEnt : certificateMessage.certEntries) {
                certEnt.extensions.consumeOnLoad(chc, enabledExtensions);
            }
            X509Certificate[] srvCerts = checkServerCerts(chc, certificateMessage.certEntries);
            chc.handshakeCredentials.add(new X509Authentication.X509Credentials(srvCerts[0].getPublicKey(), srvCerts));
            chc.handshakeSession.setPeerCertificates(srvCerts);
        }

        private static X509Certificate[] checkClientCerts(ServerHandshakeContext shc, List<CertificateEntry> certEntries) throws IOException {
            String authType;
            X509Certificate[] certs = new X509Certificate[certEntries.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (CertificateEntry entry : certEntries) {
                    int i2 = i;
                    i++;
                    certs[i2] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(entry.encoded));
                }
                String keyAlgorithm = certs[0].getPublicKey().getAlgorithm();
                boolean z = true;
                switch (keyAlgorithm.hashCode()) {
                    case 2206:
                        if (keyAlgorithm.equals("EC")) {
                            z = true;
                            break;
                        }
                        break;
                    case 67986:
                        if (keyAlgorithm.equals("DSA")) {
                            z = true;
                            break;
                        }
                        break;
                    case 81440:
                        if (keyAlgorithm.equals("RSA")) {
                            z = false;
                            break;
                        }
                        break;
                    case 1775481508:
                        if (keyAlgorithm.equals("RSASSA-PSS")) {
                            z = true;
                            break;
                        }
                        break;
                }
                switch (z) {
                    case false:
                    case true:
                    case true:
                    case true:
                        authType = keyAlgorithm;
                        break;
                    default:
                        authType = "UNKNOWN";
                        break;
                }
                try {
                    X509TrustManager tm = shc.sslContext.getX509TrustManager();
                    if (tm instanceof X509ExtendedTrustManager) {
                        if (shc.conContext.transport instanceof SSLEngine) {
                            SSLEngine engine = (SSLEngine) shc.conContext.transport;
                            ((X509ExtendedTrustManager) tm).checkClientTrusted((X509Certificate[]) certs.clone(), authType, engine);
                        } else {
                            SSLSocket socket = (SSLSocket) shc.conContext.transport;
                            ((X509ExtendedTrustManager) tm).checkClientTrusted((X509Certificate[]) certs.clone(), authType, socket);
                        }
                        shc.handshakeSession.setPeerCertificates(certs);
                        return certs;
                    }
                    throw new CertificateException("Improper X509TrustManager implementation");
                } catch (CertificateException ce) {
                    throw shc.conContext.fatal(Alert.CERTIFICATE_UNKNOWN, ce);
                }
            } catch (CertificateException ce2) {
                throw shc.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", ce2);
            }
        }

        private static X509Certificate[] checkServerCerts(ClientHandshakeContext chc, List<CertificateEntry> certEntries) throws IOException {
            X509Certificate[] certs = new X509Certificate[certEntries.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (CertificateEntry entry : certEntries) {
                    int i2 = i;
                    i++;
                    certs[i2] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(entry.encoded));
                }
                try {
                    X509TrustManager tm = chc.sslContext.getX509TrustManager();
                    if (tm instanceof X509ExtendedTrustManager) {
                        if (chc.conContext.transport instanceof SSLEngine) {
                            SSLEngine engine = (SSLEngine) chc.conContext.transport;
                            ((X509ExtendedTrustManager) tm).checkServerTrusted((X509Certificate[]) certs.clone(), "UNKNOWN", engine);
                        } else {
                            SSLSocket socket = (SSLSocket) chc.conContext.transport;
                            ((X509ExtendedTrustManager) tm).checkServerTrusted((X509Certificate[]) certs.clone(), "UNKNOWN", socket);
                        }
                        chc.handshakeSession.setPeerCertificates(certs);
                        return certs;
                    }
                    throw new CertificateException("Improper X509TrustManager implementation");
                } catch (CertificateException ce) {
                    throw chc.conContext.fatal(getCertificateAlert(chc, ce), ce);
                }
            } catch (CertificateException ce2) {
                throw chc.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", ce2);
            }
        }

        private static Alert getCertificateAlert(ClientHandshakeContext chc, CertificateException cexc) {
            Alert alert = Alert.CERTIFICATE_UNKNOWN;
            Throwable baseCause = cexc.getCause();
            if (baseCause instanceof CertPathValidatorException) {
                CertPathValidatorException cpve = (CertPathValidatorException) baseCause;
                CertPathValidatorException.Reason reason = cpve.getReason();
                if (reason == CertPathValidatorException.BasicReason.REVOKED) {
                    alert = chc.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_REVOKED;
                } else if (reason == CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS) {
                    alert = chc.staplingActive ? Alert.BAD_CERT_STATUS_RESPONSE : Alert.CERTIFICATE_UNKNOWN;
                }
            }
            return alert;
        }
    }
}