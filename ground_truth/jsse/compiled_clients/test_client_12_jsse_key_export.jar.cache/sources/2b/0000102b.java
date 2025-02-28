package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.ClientHello;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.ServerHello;
import org.openjsse.sun.security.util.HexDumpEncoder;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension.class */
public class CookieExtension {
    static final HandshakeProducer chNetworkProducer = new CHCookieProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHCookieConsumer();
    static final HandshakeConsumer chOnTradeConsumer = new CHCookieUpdate();
    static final HandshakeProducer hrrNetworkProducer = new HRRCookieProducer();
    static final SSLExtension.ExtensionConsumer hrrOnLoadConsumer = new HRRCookieConsumer();
    static final HandshakeProducer hrrNetworkReproducer = new HRRCookieReproducer();
    static final CookieStringizer cookieStringizer = new CookieStringizer();

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$CookieSpec.class */
    static class CookieSpec implements SSLExtension.SSLExtensionSpec {
        final byte[] cookie;

        private CookieSpec(ByteBuffer m) throws IOException {
            if (m.remaining() < 3) {
                throw new SSLProtocolException("Invalid cookie extension: insufficient data");
            }
            this.cookie = Record.getBytes16(m);
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"cookie\": '{'\n{0}\n'}',", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {Utilities.indent(hexEncoder.encode(this.cookie))};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$CookieStringizer.class */
    public static final class CookieStringizer implements SSLStringizer {
        private CookieStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CookieSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$CHCookieProducer.class */
    private static final class CHCookieProducer implements HandshakeProducer {
        private CHCookieProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_COOKIE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable cookie extension", new Object[0]);
                    return null;
                }
                return null;
            }
            CookieSpec spec = (CookieSpec) chc.handshakeExtensions.get(SSLExtension.HRR_COOKIE);
            if (spec != null && spec.cookie != null && spec.cookie.length != 0) {
                byte[] extData = new byte[spec.cookie.length + 2];
                ByteBuffer m = ByteBuffer.wrap(extData);
                Record.putBytes16(m, spec.cookie);
                return extData;
            }
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$CHCookieConsumer.class */
    private static final class CHCookieConsumer implements SSLExtension.ExtensionConsumer {
        private CHCookieConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_COOKIE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable cookie extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                CookieSpec spec = new CookieSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_COOKIE, spec);
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$CHCookieUpdate.class */
    private static final class CHCookieUpdate implements HandshakeConsumer {
        private CHCookieUpdate() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage) message;
            CookieSpec spec = (CookieSpec) shc.handshakeExtensions.get(SSLExtension.CH_COOKIE);
            if (spec == null) {
                return;
            }
            HelloCookieManager hcm = shc.sslContext.getHelloCookieManager(shc.negotiatedProtocol);
            if (!hcm.isCookieValid(shc, clientHello, spec.cookie)) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "unrecognized cookie");
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$HRRCookieProducer.class */
    private static final class HRRCookieProducer implements HandshakeProducer {
        private HRRCookieProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            ServerHello.ServerHelloMessage hrrm = (ServerHello.ServerHelloMessage) message;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_COOKIE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable cookie extension", new Object[0]);
                    return null;
                }
                return null;
            }
            HelloCookieManager hcm = shc.sslContext.getHelloCookieManager(shc.negotiatedProtocol);
            byte[] cookie = hcm.createCookie(shc, hrrm.clientHello);
            byte[] extData = new byte[cookie.length + 2];
            ByteBuffer m = ByteBuffer.wrap(extData);
            Record.putBytes16(m, cookie);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$HRRCookieConsumer.class */
    private static final class HRRCookieConsumer implements SSLExtension.ExtensionConsumer {
        private HRRCookieConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslConfig.isAvailable(SSLExtension.HRR_COOKIE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable cookie extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                CookieSpec spec = new CookieSpec(buffer);
                chc.handshakeExtensions.put(SSLExtension.HRR_COOKIE, spec);
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CookieExtension$HRRCookieReproducer.class */
    private static final class HRRCookieReproducer implements HandshakeProducer {
        private HRRCookieReproducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.HRR_COOKIE)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable cookie extension", new Object[0]);
                    return null;
                }
                return null;
            }
            CookieSpec spec = (CookieSpec) shc.handshakeExtensions.get(SSLExtension.CH_COOKIE);
            if (spec != null && spec.cookie != null && spec.cookie.length != 0) {
                byte[] extData = new byte[spec.cookie.length + 2];
                ByteBuffer m = ByteBuffer.wrap(extData);
                Record.putBytes16(m, spec.cookie);
                return extData;
            }
            return null;
        }
    }
}