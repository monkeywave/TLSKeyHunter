package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.CertStatusExtension;
import org.openjsse.sun.security.ssl.CertificateMessage;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.ssl.StatusResponseManager;
import sun.security.provider.certpath.OCSPResponse;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateStatus.class */
final class CertificateStatus {
    static final SSLConsumer handshakeConsumer = new CertificateStatusConsumer();
    static final HandshakeProducer handshakeProducer = new CertificateStatusProducer();
    static final HandshakeAbsence handshakeAbsence = new CertificateStatusAbsence();

    CertificateStatus() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateStatus$CertificateStatusMessage.class */
    static final class CertificateStatusMessage extends SSLHandshake.HandshakeMessage {
        final CertStatusExtension.CertStatusRequestType statusType;
        int encodedResponsesLen;
        int messageLength;
        final List<byte[]> encodedResponses;

        CertificateStatusMessage(HandshakeContext handshakeContext) {
            super(handshakeContext);
            this.encodedResponsesLen = 0;
            this.messageLength = -1;
            this.encodedResponses = new ArrayList();
            ServerHandshakeContext shc = (ServerHandshakeContext) handshakeContext;
            StatusResponseManager.StaplingParameters stapleParams = shc.stapleParams;
            if (stapleParams == null) {
                throw new IllegalArgumentException("Unexpected null stapling parameters");
            }
            X509Certificate[] certChain = (X509Certificate[]) shc.handshakeSession.getLocalCertificates();
            if (certChain == null) {
                throw new IllegalArgumentException("Unexpected null certificate chain");
            }
            this.statusType = stapleParams.statReqType;
            if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP) {
                byte[] resp = stapleParams.responseMap.get(certChain[0]);
                resp = resp == null ? new byte[0] : resp;
                this.encodedResponses.add(resp);
                this.encodedResponsesLen += resp.length + 3;
            } else if (this.statusType != CertStatusExtension.CertStatusRequestType.OCSP_MULTI) {
                throw new IllegalArgumentException("Unsupported StatusResponseType: " + this.statusType);
            } else {
                for (X509Certificate cert : certChain) {
                    byte[] resp2 = stapleParams.responseMap.get(cert);
                    if (resp2 == null) {
                        resp2 = new byte[0];
                    }
                    this.encodedResponses.add(resp2);
                    this.encodedResponsesLen += resp2.length + 3;
                }
            }
            this.messageLength = messageLength();
        }

        CertificateStatusMessage(HandshakeContext handshakeContext, ByteBuffer m) throws IOException {
            super(handshakeContext);
            this.encodedResponsesLen = 0;
            this.messageLength = -1;
            this.encodedResponses = new ArrayList();
            this.statusType = CertStatusExtension.CertStatusRequestType.valueOf((byte) Record.getInt8(m));
            if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP) {
                byte[] respDER = Record.getBytes24(m);
                if (respDER.length > 0) {
                    this.encodedResponses.add(respDER);
                    this.encodedResponsesLen = 3 + respDER.length;
                } else {
                    throw handshakeContext.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Zero-length OCSP Response");
                }
            } else if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP_MULTI) {
                int respListLen = Record.getInt24(m);
                this.encodedResponsesLen = respListLen;
                while (respListLen > 0) {
                    byte[] respDER2 = Record.getBytes24(m);
                    this.encodedResponses.add(respDER2);
                    respListLen -= respDER2.length + 3;
                }
                if (respListLen != 0) {
                    throw handshakeContext.conContext.fatal(Alert.INTERNAL_ERROR, "Bad OCSP response list length");
                }
            } else {
                throw handshakeContext.conContext.fatal(Alert.HANDSHAKE_FAILURE, "Unsupported StatusResponseType: " + this.statusType);
            }
            this.messageLength = messageLength();
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_STATUS;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int len = 1;
            if (this.messageLength == -1) {
                if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP) {
                    len = 1 + this.encodedResponsesLen;
                } else if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP_MULTI) {
                    len = 1 + 3 + this.encodedResponsesLen;
                }
                this.messageLength = len;
            }
            return this.messageLength;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream s) throws IOException {
            s.putInt8(this.statusType.f962id);
            if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP) {
                s.putBytes24(this.encodedResponses.get(0));
            } else if (this.statusType == CertStatusExtension.CertStatusRequestType.OCSP_MULTI) {
                s.putInt24(this.encodedResponsesLen);
                for (byte[] respBytes : this.encodedResponses) {
                    if (respBytes != null) {
                        s.putBytes24(respBytes);
                    } else {
                        s.putBytes24(null);
                    }
                }
            } else {
                throw new SSLHandshakeException("Unsupported status_type: " + ((int) this.statusType.f962id));
            }
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (byte[] respDER : this.encodedResponses) {
                if (respDER.length > 0) {
                    try {
                        OCSPResponse oResp = new OCSPResponse(respDER);
                        sb.append(oResp.toString()).append("\n");
                    } catch (IOException ioe) {
                        sb.append("OCSP Response Exception: ").append(ioe).append("\n");
                    }
                } else {
                    sb.append("<Zero-length entry>\n");
                }
            }
            MessageFormat messageFormat = new MessageFormat("\"CertificateStatus\": '{'\n  \"type\"                : \"{0}\",\n  \"responses \"          : [\n{1}\n  ]\n'}'", Locale.ENGLISH);
            Object[] messageFields = {this.statusType.name, Utilities.indent(Utilities.indent(sb.toString()))};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateStatus$CertificateStatusConsumer.class */
    private static final class CertificateStatusConsumer implements SSLConsumer {
        private CertificateStatusConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CertificateStatusMessage cst = new CertificateStatusMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming server CertificateStatus handshake message", cst);
            }
            chc.handshakeSession.setStatusResponses(cst.encodedResponses);
            CertificateMessage.T12CertificateConsumer.checkServerCerts(chc, chc.deferredCerts);
            chc.handshakeConsumers.remove(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateStatus$CertificateStatusProducer.class */
    private static final class CertificateStatusProducer implements HandshakeProducer {
        private CertificateStatusProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.staplingActive) {
                return null;
            }
            CertificateStatusMessage csm = new CertificateStatusMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced server CertificateStatus handshake message", csm);
            }
            csm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertificateStatus$CertificateStatusAbsence.class */
    private static final class CertificateStatusAbsence implements HandshakeAbsence {
        private CertificateStatusAbsence() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeAbsence
        public void absent(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (chc.staplingActive) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Server did not send CertificateStatus, checking cert chain without status info.", new Object[0]);
                }
                CertificateMessage.T12CertificateConsumer.checkServerCerts(chc, chc.deferredCerts);
            }
        }
    }
}