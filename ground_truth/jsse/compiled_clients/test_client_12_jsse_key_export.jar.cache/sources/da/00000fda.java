package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.x500.X500Principal;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension.class */
final class CertificateAuthorityExtension {
    static final HandshakeProducer chNetworkProducer = new CHCertificateAuthoritiesProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHCertificateAuthoritiesConsumer();
    static final HandshakeConsumer chOnTradeConsumer = new CHCertificateAuthoritiesUpdate();
    static final HandshakeProducer crNetworkProducer = new CRCertificateAuthoritiesProducer();
    static final SSLExtension.ExtensionConsumer crOnLoadConsumer = new CRCertificateAuthoritiesConsumer();
    static final HandshakeConsumer crOnTradeConsumer = new CRCertificateAuthoritiesUpdate();
    static final SSLStringizer ssStringizer = new CertificateAuthoritiesStringizer();

    CertificateAuthorityExtension() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CertificateAuthoritiesSpec.class */
    static final class CertificateAuthoritiesSpec implements SSLExtension.SSLExtensionSpec {
        final X500Principal[] authorities;

        CertificateAuthoritiesSpec(List<X500Principal> authorities) {
            if (authorities != null) {
                this.authorities = new X500Principal[authorities.size()];
                int i = 0;
                for (X500Principal name : authorities) {
                    int i2 = i;
                    i++;
                    this.authorities[i2] = name;
                }
                return;
            }
            this.authorities = new X500Principal[0];
        }

        CertificateAuthoritiesSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid signature_algorithms: insufficient data");
            }
            int caLength = Record.getInt16(buffer);
            if (buffer.remaining() != caLength) {
                throw new SSLProtocolException("Invalid certificate_authorities: incorrect data size");
            }
            ArrayList<X500Principal> dnList = new ArrayList<>();
            while (buffer.remaining() > 0) {
                byte[] dn = Record.getBytes16(buffer);
                X500Principal ca = new X500Principal(dn);
                dnList.add(ca);
            }
            this.authorities = (X500Principal[]) dnList.toArray(new X500Principal[dnList.size()]);
        }

        X500Principal[] getAuthorities() {
            return this.authorities;
        }

        public String toString() {
            X500Principal[] x500PrincipalArr;
            MessageFormat messageFormat = new MessageFormat("\"certificate authorities\": '['{0}']'", Locale.ENGLISH);
            if (this.authorities == null || this.authorities.length == 0) {
                Object[] messageFields = {"<no supported certificate authorities specified>"};
                return messageFormat.format(messageFields);
            }
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (X500Principal ca : this.authorities) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append("]; [");
                }
                builder.append(ca);
            }
            Object[] messageFields2 = {builder.toString()};
            return messageFormat.format(messageFields2);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CertificateAuthoritiesStringizer.class */
    private static final class CertificateAuthoritiesStringizer implements SSLStringizer {
        private CertificateAuthoritiesStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CertificateAuthoritiesSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CHCertificateAuthoritiesProducer.class */
    private static final class CHCertificateAuthoritiesProducer implements HandshakeProducer {
        private final boolean enableCAExtension;
        private final int maxCAExtensionSize;

        private CHCertificateAuthoritiesProducer() {
            this.enableCAExtension = Utilities.getBooleanProperty("org.openjsse.client.enableCAExtension", false);
            this.maxCAExtensionSize = Utilities.getUIntProperty("org.openjsse.client.maxCAExtensionSize", 8192);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_CERTIFICATE_AUTHORITIES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable certificate_authorities extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (!this.enableCAExtension) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore disabled certificate_authorities extension", new Object[0]);
                    return null;
                }
                return null;
            } else {
                if (chc.localSupportedAuthorities == null) {
                    X509Certificate[] caCerts = chc.sslContext.getX509TrustManager().getAcceptedIssuers();
                    ArrayList<X500Principal> authList = new ArrayList<>(caCerts.length);
                    for (X509Certificate cert : caCerts) {
                        authList.add(cert.getSubjectX500Principal());
                    }
                    if (!authList.isEmpty()) {
                        chc.localSupportedAuthorities = authList;
                    }
                }
                if (chc.localSupportedAuthorities == null) {
                    return null;
                }
                int vectorLen = 0;
                List<byte[]> authorities = new ArrayList<>();
                for (X500Principal ca : chc.localSupportedAuthorities) {
                    byte[] enc = ca.getEncoded();
                    int len = enc.length + 2;
                    if (vectorLen + len <= this.maxCAExtensionSize) {
                        vectorLen += len;
                        authorities.add(enc);
                    }
                }
                byte[] extData = new byte[vectorLen + 2];
                ByteBuffer m = ByteBuffer.wrap(extData);
                Record.putInt16(m, vectorLen);
                for (byte[] enc2 : authorities) {
                    Record.putBytes16(m, enc2);
                }
                chc.handshakeExtensions.put(SSLExtension.CH_CERTIFICATE_AUTHORITIES, new CertificateAuthoritiesSpec(chc.localSupportedAuthorities));
                return extData;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CHCertificateAuthoritiesConsumer.class */
    private static final class CHCertificateAuthoritiesConsumer implements SSLExtension.ExtensionConsumer {
        private CHCertificateAuthoritiesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_CERTIFICATE_AUTHORITIES)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable certificate_authorities extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                CertificateAuthoritiesSpec spec = new CertificateAuthoritiesSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_CERTIFICATE_AUTHORITIES, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CHCertificateAuthoritiesUpdate.class */
    private static final class CHCertificateAuthoritiesUpdate implements HandshakeConsumer {
        private CHCertificateAuthoritiesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            CertificateAuthoritiesSpec spec = (CertificateAuthoritiesSpec) shc.handshakeExtensions.get(SSLExtension.CH_CERTIFICATE_AUTHORITIES);
            if (spec == null) {
                return;
            }
            shc.peerSupportedAuthorities = spec.getAuthorities();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CRCertificateAuthoritiesProducer.class */
    private static final class CRCertificateAuthoritiesProducer implements HandshakeProducer {
        private final boolean enableCAExtension;
        private final int maxCAExtensionSize;

        private CRCertificateAuthoritiesProducer() {
            this.enableCAExtension = Utilities.getBooleanProperty("org.openjsse.server.enableCAExtension", true);
            this.maxCAExtensionSize = Utilities.getUIntProperty("org.openjsse.server.maxCAExtensionSize", 8192);
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CR_CERTIFICATE_AUTHORITIES)) {
                throw shc.conContext.fatal(Alert.MISSING_EXTENSION, "No available certificate_authority extension for client certificate authentication");
            }
            if (!this.enableCAExtension) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore disabled certificate_authorities extension", new Object[0]);
                    return null;
                }
                return null;
            }
            if (shc.localSupportedAuthorities == null) {
                X509Certificate[] caCerts = shc.sslContext.getX509TrustManager().getAcceptedIssuers();
                ArrayList<X500Principal> authList = new ArrayList<>(caCerts.length);
                for (X509Certificate cert : caCerts) {
                    authList.add(cert.getSubjectX500Principal());
                }
                if (!authList.isEmpty()) {
                    shc.localSupportedAuthorities = authList;
                }
            }
            if (shc.localSupportedAuthorities == null) {
                return null;
            }
            int vectorLen = 0;
            List<byte[]> authorities = new ArrayList<>();
            for (X500Principal ca : shc.localSupportedAuthorities) {
                byte[] enc = ca.getEncoded();
                int len = enc.length + 2;
                if (vectorLen + len <= this.maxCAExtensionSize) {
                    vectorLen += len;
                    authorities.add(enc);
                }
            }
            byte[] extData = new byte[vectorLen + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putInt16(m, vectorLen);
            for (byte[] enc2 : authorities) {
                Record.putBytes16(m, enc2);
            }
            shc.handshakeExtensions.put(SSLExtension.CR_CERTIFICATE_AUTHORITIES, new CertificateAuthoritiesSpec(shc.localSupportedAuthorities));
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CRCertificateAuthoritiesConsumer.class */
    private static final class CRCertificateAuthoritiesConsumer implements SSLExtension.ExtensionConsumer {
        private CRCertificateAuthoritiesConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CR_CERTIFICATE_AUTHORITIES)) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE, "No available certificate_authority extension for client certificate authentication");
            }
            try {
                CertificateAuthoritiesSpec spec = new CertificateAuthoritiesSpec(buffer);
                chc.handshakeExtensions.put(SSLExtension.CR_CERTIFICATE_AUTHORITIES, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateAuthorityExtension$CRCertificateAuthoritiesUpdate.class */
    private static final class CRCertificateAuthoritiesUpdate implements HandshakeConsumer {
        private CRCertificateAuthoritiesUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CertificateAuthoritiesSpec spec = (CertificateAuthoritiesSpec) chc.handshakeExtensions.get(SSLExtension.CR_CERTIFICATE_AUTHORITIES);
            if (spec == null) {
                return;
            }
            chc.peerSupportedAuthorities = spec.getAuthorities();
        }
    }
}