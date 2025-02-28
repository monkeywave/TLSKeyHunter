package org.openjsse.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLProtocolException;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;
import org.openjsse.sun.security.util.HexDumpEncoder;
import sun.security.provider.certpath.OCSPResponse;
import sun.security.provider.certpath.ResponderId;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension.class */
final class CertStatusExtension {
    static final HandshakeProducer chNetworkProducer = new CHCertStatusReqProducer();
    static final SSLExtension.ExtensionConsumer chOnLoadConsumer = new CHCertStatusReqConsumer();
    static final HandshakeProducer shNetworkProducer = new SHCertStatusReqProducer();
    static final SSLExtension.ExtensionConsumer shOnLoadConsumer = new SHCertStatusReqConsumer();
    static final HandshakeProducer ctNetworkProducer = new CTCertStatusResponseProducer();
    static final SSLExtension.ExtensionConsumer ctOnLoadConsumer = new CTCertStatusResponseConsumer();
    static final SSLStringizer certStatusReqStringizer = new CertStatusRequestStringizer();
    static final HandshakeProducer chV2NetworkProducer = new CHCertStatusReqV2Producer();
    static final SSLExtension.ExtensionConsumer chV2OnLoadConsumer = new CHCertStatusReqV2Consumer();
    static final HandshakeProducer shV2NetworkProducer = new SHCertStatusReqV2Producer();
    static final SSLExtension.ExtensionConsumer shV2OnLoadConsumer = new SHCertStatusReqV2Consumer();
    static final SSLStringizer certStatusReqV2Stringizer = new CertStatusRequestsStringizer();
    static final SSLStringizer certStatusRespStringizer = new CertStatusRespStringizer();

    CertStatusExtension() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequestSpec.class */
    public static final class CertStatusRequestSpec implements SSLExtension.SSLExtensionSpec {
        static final CertStatusRequestSpec DEFAULT = new CertStatusRequestSpec(OCSPStatusRequest.EMPTY_OCSP);
        final CertStatusRequest statusRequest;

        private CertStatusRequestSpec(CertStatusRequest statusRequest) {
            this.statusRequest = statusRequest;
        }

        private CertStatusRequestSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() == 0) {
                this.statusRequest = null;
            } else if (buffer.remaining() < 1) {
                throw new SSLProtocolException("Invalid status_request extension: insufficient data");
            } else {
                byte statusType = (byte) Record.getInt8(buffer);
                byte[] encoded = new byte[buffer.remaining()];
                if (encoded.length != 0) {
                    buffer.get(encoded);
                }
                if (statusType == CertStatusRequestType.OCSP.f962id) {
                    this.statusRequest = new OCSPStatusRequest(statusType, encoded);
                    return;
                }
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.info("Unknown certificate status request (status type: " + ((int) statusType) + ")", new Object[0]);
                }
                this.statusRequest = new CertStatusRequest(statusType, encoded);
            }
        }

        public String toString() {
            return this.statusRequest == null ? "<empty>" : this.statusRequest.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusResponseSpec.class */
    static final class CertStatusResponseSpec implements SSLExtension.SSLExtensionSpec {
        final CertStatusResponse statusResponse;

        private CertStatusResponseSpec(CertStatusResponse resp) {
            this.statusResponse = resp;
        }

        private CertStatusResponseSpec(ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw new SSLProtocolException("Invalid status_request extension: insufficient data");
            }
            byte type = (byte) Record.getInt8(buffer);
            byte[] respData = Record.getBytes24(buffer);
            if (type == CertStatusRequestType.OCSP.f962id) {
                this.statusResponse = new OCSPStatusResponse(type, respData);
                return;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.info("Unknown certificate status response (status type: " + ((int) type) + ")", new Object[0]);
            }
            this.statusResponse = new CertStatusResponse(type, respData);
        }

        public String toString() {
            return this.statusResponse == null ? "<empty>" : this.statusResponse.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequestStringizer.class */
    private static final class CertStatusRequestStringizer implements SSLStringizer {
        private CertStatusRequestStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CertStatusRequestSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRespStringizer.class */
    private static final class CertStatusRespStringizer implements SSLStringizer {
        private CertStatusRespStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CertStatusResponseSpec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequestType.class */
    public enum CertStatusRequestType {
        OCSP((byte) 1, "ocsp"),
        OCSP_MULTI((byte) 2, "ocsp_multi");
        

        /* renamed from: id */
        final byte f962id;
        final String name;

        CertStatusRequestType(byte id, String name) {
            this.f962id = id;
            this.name = name;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static CertStatusRequestType valueOf(byte id) {
            CertStatusRequestType[] values;
            for (CertStatusRequestType srt : values()) {
                if (srt.f962id == id) {
                    return srt;
                }
            }
            return null;
        }

        static String nameOf(byte id) {
            CertStatusRequestType[] values;
            for (CertStatusRequestType srt : values()) {
                if (srt.f962id == id) {
                    return srt.name;
                }
            }
            return "UNDEFINED-CERT-STATUS-TYPE(" + ((int) id) + ")";
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequest.class */
    public static class CertStatusRequest {
        final byte statusType;
        final byte[] encodedRequest;

        protected CertStatusRequest(byte statusType, byte[] encodedRequest) {
            this.statusType = statusType;
            this.encodedRequest = encodedRequest;
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"certificate status type\": {0}\n\"encoded certificate status\": '{'\n{1}\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            String encoded = hexEncoder.encodeBuffer(this.encodedRequest);
            Object[] messageFields = {CertStatusRequestType.nameOf(this.statusType), Utilities.indent(encoded)};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$OCSPStatusRequest.class */
    public static final class OCSPStatusRequest extends CertStatusRequest {
        static final OCSPStatusRequest EMPTY_OCSP;
        static final OCSPStatusRequest EMPTY_OCSP_MULTI;
        final List<ResponderId> responderIds;
        final List<Extension> extensions;
        private final int ridListLen;
        private final int extListLen;

        static {
            OCSPStatusRequest ocspReq = null;
            OCSPStatusRequest multiReq = null;
            try {
                ocspReq = new OCSPStatusRequest(CertStatusRequestType.OCSP.f962id, new byte[]{0, 0, 0, 0});
                multiReq = new OCSPStatusRequest(CertStatusRequestType.OCSP_MULTI.f962id, new byte[]{0, 0, 0, 0});
            } catch (IOException e) {
            }
            EMPTY_OCSP = ocspReq;
            EMPTY_OCSP_MULTI = multiReq;
        }

        private OCSPStatusRequest(byte statusType, byte[] encoded) throws IOException {
            super(statusType, encoded);
            int ridListBytesRemaining;
            if (encoded == null || encoded.length < 4) {
                throw new SSLProtocolException("Invalid OCSP status request: insufficient data");
            }
            List<ResponderId> rids = new ArrayList<>();
            List<Extension> exts = new ArrayList<>();
            ByteBuffer m = ByteBuffer.wrap(encoded);
            this.ridListLen = Record.getInt16(m);
            if (m.remaining() < this.ridListLen + 2) {
                throw new SSLProtocolException("Invalid OCSP status request: insufficient data");
            }
            int i = this.ridListLen;
            while (true) {
                ridListBytesRemaining = i;
                if (ridListBytesRemaining < 2) {
                    break;
                }
                byte[] ridBytes = Record.getBytes16(m);
                try {
                    rids.add(new ResponderId(ridBytes));
                    i = ridListBytesRemaining - (ridBytes.length + 2);
                } catch (IOException e) {
                    throw new SSLProtocolException("Invalid OCSP status request: invalid responder ID");
                }
            }
            if (ridListBytesRemaining != 0) {
                throw new SSLProtocolException("Invalid OCSP status request: incomplete data");
            }
            byte[] extListBytes = Record.getBytes16(m);
            this.extListLen = extListBytes.length;
            if (this.extListLen > 0) {
                try {
                    DerInputStream dis = new DerInputStream(extListBytes);
                    DerValue[] extSeqContents = dis.getSequence(extListBytes.length);
                    for (DerValue extDerVal : extSeqContents) {
                        exts.add(new sun.security.x509.Extension(extDerVal));
                    }
                } catch (IOException e2) {
                    throw new SSLProtocolException("Invalid OCSP status request: invalid extension");
                }
            }
            this.responderIds = rids;
            this.extensions = exts;
        }

        @Override // org.openjsse.sun.security.ssl.CertStatusExtension.CertStatusRequest
        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"certificate status type\": {0}\n\"OCSP status request\": '{'\n{1}\n'}'", Locale.ENGLISH);
            MessageFormat requestFormat = new MessageFormat("\"responder_id\": {0}\n\"request extensions\": '{'\n{1}\n'}'", Locale.ENGLISH);
            String ridStr = "<empty>";
            if (!this.responderIds.isEmpty()) {
                ridStr = this.responderIds.toString();
            }
            String extsStr = "<empty>";
            if (!this.extensions.isEmpty()) {
                StringBuilder extBuilder = new StringBuilder(512);
                boolean isFirst = true;
                for (Extension ext : this.extensions) {
                    if (isFirst) {
                        isFirst = false;
                    } else {
                        extBuilder.append(",\n");
                    }
                    extBuilder.append("{\n").append(Utilities.indent(ext.toString())).append("}");
                }
                extsStr = extBuilder.toString();
            }
            Object[] requestFields = {ridStr, Utilities.indent(extsStr)};
            String ocspStatusRequest = requestFormat.format(requestFields);
            Object[] messageFields = {CertStatusRequestType.nameOf(this.statusType), Utilities.indent(ocspStatusRequest)};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusResponse.class */
    public static class CertStatusResponse {
        final byte statusType;
        final byte[] encodedResponse;

        protected CertStatusResponse(byte statusType, byte[] respDer) {
            this.statusType = statusType;
            this.encodedResponse = respDer;
        }

        byte[] toByteArray() throws IOException {
            byte[] outData = new byte[this.encodedResponse.length + 4];
            ByteBuffer buf = ByteBuffer.wrap(outData);
            Record.putInt8(buf, this.statusType);
            Record.putBytes24(buf, this.encodedResponse);
            return buf.array();
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"certificate status response type\": {0}\n\"encoded certificate status\": '{'\n{1}\n'}'", Locale.ENGLISH);
            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            String encoded = hexEncoder.encodeBuffer(this.encodedResponse);
            Object[] messageFields = {CertStatusRequestType.nameOf(this.statusType), Utilities.indent(encoded)};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$OCSPStatusResponse.class */
    static final class OCSPStatusResponse extends CertStatusResponse {
        final OCSPResponse ocspResponse;

        private OCSPStatusResponse(byte statusType, byte[] encoded) throws IOException {
            super(statusType, encoded);
            if (encoded == null || encoded.length < 1) {
                throw new SSLProtocolException("Invalid OCSP status response: insufficient data");
            }
            this.ocspResponse = new OCSPResponse(encoded);
        }

        @Override // org.openjsse.sun.security.ssl.CertStatusExtension.CertStatusResponse
        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"certificate status response type\": {0}\n\"OCSP status response\": '{'\n{1}\n'}'", Locale.ENGLISH);
            Object[] messageFields = {CertStatusRequestType.nameOf(this.statusType), Utilities.indent(this.ocspResponse.toString())};
            return messageFormat.format(messageFields);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CHCertStatusReqProducer.class */
    private static final class CHCertStatusReqProducer implements HandshakeProducer {
        private CHCertStatusReqProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslContext.isStaplingEnabled(true)) {
                return null;
            }
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_STATUS_REQUEST)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_STATUS_REQUEST.name, new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] extData = {1, 0, 0, 0, 0};
            chc.handshakeExtensions.put(SSLExtension.CH_STATUS_REQUEST, CertStatusRequestSpec.DEFAULT);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CHCertStatusReqConsumer.class */
    private static final class CHCertStatusReqConsumer implements SSLExtension.ExtensionConsumer {
        private CHCertStatusReqConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_STATUS_REQUEST)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Ignore unavailable extension: " + SSLExtension.CH_STATUS_REQUEST.name, new Object[0]);
                    return;
                }
                return;
            }
            try {
                CertStatusRequestSpec spec = new CertStatusRequestSpec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_STATUS_REQUEST, spec);
                if (!shc.isResumption && !shc.negotiatedProtocol.useTLS13PlusSpec()) {
                    shc.handshakeProducers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id), SSLHandshake.CERTIFICATE_STATUS);
                }
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$SHCertStatusReqProducer.class */
    private static final class SHCertStatusReqProducer implements HandshakeProducer {
        private SHCertStatusReqProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.stapleParams == null || shc.stapleParams.statusRespExt != SSLExtension.CH_STATUS_REQUEST) {
                return null;
            }
            CertStatusRequestSpec spec = (CertStatusRequestSpec) shc.handshakeExtensions.get(SSLExtension.CH_STATUS_REQUEST);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable extension: " + SSLExtension.CH_STATUS_REQUEST.name, new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.isResumption) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("No status_request response for session resuming", new Object[0]);
                    return null;
                }
                return null;
            } else {
                byte[] extData = new byte[0];
                shc.handshakeExtensions.put(SSLExtension.SH_STATUS_REQUEST, CertStatusRequestSpec.DEFAULT);
                return extData;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$SHCertStatusReqConsumer.class */
    private static final class SHCertStatusReqConsumer implements SSLExtension.ExtensionConsumer {
        private SHCertStatusReqConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CertStatusRequestSpec requestedCsr = (CertStatusRequestSpec) chc.handshakeExtensions.get(SSLExtension.CH_STATUS_REQUEST);
            if (requestedCsr == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected status_request extension in ServerHello");
            }
            if (buffer.hasRemaining()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid status_request extension in ServerHello message: the extension data must be empty");
            }
            chc.handshakeExtensions.put(SSLExtension.SH_STATUS_REQUEST, CertStatusRequestSpec.DEFAULT);
            chc.staplingActive = chc.sslContext.isStaplingEnabled(true);
            if (chc.staplingActive) {
                chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id), SSLHandshake.CERTIFICATE_STATUS);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequestV2Spec.class */
    public static final class CertStatusRequestV2Spec implements SSLExtension.SSLExtensionSpec {
        static final CertStatusRequestV2Spec DEFAULT = new CertStatusRequestV2Spec(new CertStatusRequest[]{OCSPStatusRequest.EMPTY_OCSP_MULTI});
        final CertStatusRequest[] certStatusRequests;

        private CertStatusRequestV2Spec(CertStatusRequest[] certStatusRequests) {
            this.certStatusRequests = certStatusRequests;
        }

        private CertStatusRequestV2Spec(ByteBuffer message) throws IOException {
            if (message.remaining() == 0) {
                this.certStatusRequests = new CertStatusRequest[0];
            } else if (message.remaining() < 5) {
                throw new SSLProtocolException("Invalid status_request_v2 extension: insufficient data");
            } else {
                int listLen = Record.getInt16(message);
                if (listLen <= 0) {
                    throw new SSLProtocolException("certificate_status_req_list length must be positive (received length: " + listLen + ")");
                }
                int remaining = listLen;
                List<CertStatusRequest> statusRequests = new ArrayList<>();
                while (remaining > 0) {
                    byte statusType = (byte) Record.getInt8(message);
                    int requestLen = Record.getInt16(message);
                    if (message.remaining() < requestLen) {
                        throw new SSLProtocolException("Invalid status_request_v2 extension: insufficient data (request_length=" + requestLen + ", remining=" + message.remaining() + ")");
                    }
                    byte[] encoded = new byte[requestLen];
                    if (encoded.length != 0) {
                        message.get(encoded);
                    }
                    remaining = (remaining - 3) - requestLen;
                    if (statusType == CertStatusRequestType.OCSP.f962id || statusType == CertStatusRequestType.OCSP_MULTI.f962id) {
                        if (encoded.length < 4) {
                            throw new SSLProtocolException("Invalid status_request_v2 extension: insufficient data");
                        }
                        statusRequests.add(new OCSPStatusRequest(statusType, encoded));
                    } else {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                            SSLLogger.info("Unknown certificate status request (status type: " + ((int) statusType) + ")", new Object[0]);
                        }
                        statusRequests.add(new CertStatusRequest(statusType, encoded));
                    }
                }
                this.certStatusRequests = (CertStatusRequest[]) statusRequests.toArray(new CertStatusRequest[0]);
            }
        }

        public String toString() {
            CertStatusRequest[] certStatusRequestArr;
            if (this.certStatusRequests == null || this.certStatusRequests.length == 0) {
                return "<empty>";
            }
            MessageFormat messageFormat = new MessageFormat("\"cert status request\": '{'\n{0}\n'}'", Locale.ENGLISH);
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (CertStatusRequest csr : this.certStatusRequests) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(", ");
                }
                Object[] messageFields = {Utilities.indent(csr.toString())};
                builder.append(messageFormat.format(messageFields));
            }
            return builder.toString();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CertStatusRequestsStringizer.class */
    private static final class CertStatusRequestsStringizer implements SSLStringizer {
        private CertStatusRequestsStringizer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLStringizer
        public String toString(ByteBuffer buffer) {
            try {
                return new CertStatusRequestV2Spec(buffer).toString();
            } catch (IOException ioe) {
                return ioe.getMessage();
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CHCertStatusReqV2Producer.class */
    private static final class CHCertStatusReqV2Producer implements HandshakeProducer {
        private CHCertStatusReqV2Producer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            if (!chc.sslContext.isStaplingEnabled(true)) {
                return null;
            }
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_STATUS_REQUEST_V2)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable status_request_v2 extension", new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] extData = {0, 7, 2, 0, 4, 0, 0, 0, 0};
            chc.handshakeExtensions.put(SSLExtension.CH_STATUS_REQUEST_V2, CertStatusRequestV2Spec.DEFAULT);
            return extData;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CHCertStatusReqV2Consumer.class */
    private static final class CHCertStatusReqV2Consumer implements SSLExtension.ExtensionConsumer {
        private CHCertStatusReqV2Consumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.sslConfig.isAvailable(SSLExtension.CH_STATUS_REQUEST_V2)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable status_request_v2 extension", new Object[0]);
                    return;
                }
                return;
            }
            try {
                CertStatusRequestV2Spec spec = new CertStatusRequestV2Spec(buffer);
                shc.handshakeExtensions.put(SSLExtension.CH_STATUS_REQUEST_V2, spec);
                if (!shc.isResumption) {
                    shc.handshakeProducers.putIfAbsent(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id), SSLHandshake.CERTIFICATE_STATUS);
                }
            } catch (IOException ioe) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$SHCertStatusReqV2Producer.class */
    private static final class SHCertStatusReqV2Producer implements HandshakeProducer {
        private SHCertStatusReqV2Producer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.stapleParams == null || shc.stapleParams.statusRespExt != SSLExtension.CH_STATUS_REQUEST_V2) {
                return null;
            }
            CertStatusRequestV2Spec spec = (CertStatusRequestV2Spec) shc.handshakeExtensions.get(SSLExtension.CH_STATUS_REQUEST_V2);
            if (spec == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Ignore unavailable status_request_v2 extension", new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.isResumption) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("No status_request_v2 response for session resumption", new Object[0]);
                    return null;
                }
                return null;
            } else {
                byte[] extData = new byte[0];
                shc.handshakeExtensions.put(SSLExtension.SH_STATUS_REQUEST_V2, CertStatusRequestV2Spec.DEFAULT);
                return extData;
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$SHCertStatusReqV2Consumer.class */
    private static final class SHCertStatusReqV2Consumer implements SSLExtension.ExtensionConsumer {
        private SHCertStatusReqV2Consumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            CertStatusRequestV2Spec requestedCsr = (CertStatusRequestV2Spec) chc.handshakeExtensions.get(SSLExtension.CH_STATUS_REQUEST_V2);
            if (requestedCsr == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Unexpected status_request_v2 extension in ServerHello");
            }
            if (buffer.hasRemaining()) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE, "Invalid status_request_v2 extension in ServerHello: the extension data must be empty");
            }
            chc.handshakeExtensions.put(SSLExtension.SH_STATUS_REQUEST_V2, CertStatusRequestV2Spec.DEFAULT);
            chc.staplingActive = chc.sslContext.isStaplingEnabled(true);
            if (chc.staplingActive) {
                chc.handshakeConsumers.put(Byte.valueOf(SSLHandshake.CERTIFICATE_STATUS.f987id), SSLHandshake.CERTIFICATE_STATUS);
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CTCertStatusResponseProducer.class */
    private static final class CTCertStatusResponseProducer implements HandshakeProducer {
        private CTCertStatusResponseProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (shc.stapleParams == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Stapling is disabled for this connection", new Object[0]);
                    return null;
                }
                return null;
            } else if (shc.currentCertEntry == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Found null CertificateEntry in context", new Object[0]);
                    return null;
                }
                return null;
            } else {
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(shc.currentCertEntry.encoded));
                    byte[] respBytes = shc.stapleParams.responseMap.get(x509Cert);
                    if (respBytes == null) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("No status response found for " + x509Cert.getSubjectX500Principal(), new Object[0]);
                        }
                        shc.currentCertEntry = null;
                        return null;
                    }
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Found status response for " + x509Cert.getSubjectX500Principal() + ", response length: " + respBytes.length, new Object[0]);
                    }
                    CertStatusResponse certResp = shc.stapleParams.statReqType == CertStatusRequestType.OCSP ? new OCSPStatusResponse(shc.stapleParams.statReqType.f962id, respBytes) : new CertStatusResponse(shc.stapleParams.statReqType.f962id, respBytes);
                    byte[] producedData = certResp.toByteArray();
                    shc.currentCertEntry = null;
                    return producedData;
                } catch (IOException ioe) {
                    throw shc.conContext.fatal(Alert.BAD_CERT_STATUS_RESPONSE, "Failed to parse certificate status response", ioe);
                } catch (CertificateException ce) {
                    throw shc.conContext.fatal(Alert.BAD_CERTIFICATE, "Failed to parse server certificates", ce);
                }
            }
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/CertStatusExtension$CTCertStatusResponseConsumer.class */
    private static final class CTCertStatusResponseConsumer implements SSLExtension.ExtensionConsumer {
        private CTCertStatusResponseConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLExtension.ExtensionConsumer
        public void consume(ConnectionContext context, SSLHandshake.HandshakeMessage message, ByteBuffer buffer) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;
            try {
                CertStatusResponseSpec spec = new CertStatusResponseSpec(buffer);
                if (chc.sslContext.isStaplingEnabled(true)) {
                    chc.staplingActive = true;
                    if (chc.handshakeSession != null && !chc.isResumption) {
                        List<byte[]> respList = new ArrayList<>(chc.handshakeSession.getStatusResponses());
                        respList.add(spec.statusResponse.encodedResponse);
                        chc.handshakeSession.setStatusResponses(respList);
                    } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Ignoring stapled data on resumed session", new Object[0]);
                    }
                }
            } catch (IOException ioe) {
                throw chc.conContext.fatal(Alert.DECODE_ERROR, ioe);
            }
        }
    }
}