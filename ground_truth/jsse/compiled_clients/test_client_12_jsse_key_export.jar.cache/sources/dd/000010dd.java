package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.PskKeyExchangeModesExtension;
import org.openjsse.sun.security.ssl.SSLHandshake;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/NewSessionTicket.class */
public final class NewSessionTicket {
    private static final int MAX_TICKET_LIFETIME = 604800;
    static final SSLConsumer handshakeConsumer = new NewSessionTicketConsumer();
    static final SSLProducer kickstartProducer = new NewSessionTicketKickstartProducer();
    static final HandshakeProducer handshakeProducer = new NewSessionTicketProducer();

    NewSessionTicket() {
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/NewSessionTicket$NewSessionTicketMessage.class */
    static final class NewSessionTicketMessage extends SSLHandshake.HandshakeMessage {
        final int ticketLifetime;
        final int ticketAgeAdd;
        final byte[] ticketNonce;
        final byte[] ticket;
        final SSLExtensions extensions;

        NewSessionTicketMessage(HandshakeContext context, int ticketLifetime, SecureRandom generator, byte[] ticketNonce, byte[] ticket) {
            super(context);
            this.ticketLifetime = ticketLifetime;
            this.ticketAgeAdd = generator.nextInt();
            this.ticketNonce = ticketNonce;
            this.ticket = ticket;
            this.extensions = new SSLExtensions(this);
        }

        NewSessionTicketMessage(HandshakeContext context, ByteBuffer m) throws IOException {
            super(context);
            if (m.remaining() < 14) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid NewSessionTicket message: no sufficient data");
            }
            this.ticketLifetime = Record.getInt32(m);
            this.ticketAgeAdd = Record.getInt32(m);
            this.ticketNonce = Record.getBytes8(m);
            if (m.remaining() < 5) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid NewSessionTicket message: no sufficient data");
            }
            this.ticket = Record.getBytes16(m);
            if (this.ticket.length == 0) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "No ticket in the NewSessionTicket handshake message");
            }
            if (m.remaining() < 2) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER, "Invalid NewSessionTicket message: no sufficient data");
            }
            SSLExtension[] supportedExtensions = context.sslConfig.getEnabledExtensions(SSLHandshake.NEW_SESSION_TICKET);
            this.extensions = new SSLExtensions(this, m, supportedExtensions);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public SSLHandshake handshakeType() {
            return SSLHandshake.NEW_SESSION_TICKET;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public int messageLength() {
            int extLen = this.extensions.length();
            if (extLen == 0) {
                extLen = 2;
            }
            return 8 + this.ticketNonce.length + 1 + this.ticket.length + 2 + extLen;
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshake.HandshakeMessage
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt32(this.ticketLifetime);
            hos.putInt32(this.ticketAgeAdd);
            hos.putBytes8(this.ticketNonce);
            hos.putBytes16(this.ticket);
            if (this.extensions.length() == 0) {
                hos.putInt16(0);
            } else {
                this.extensions.send(hos);
            }
        }

        public String toString() {
            MessageFormat messageFormat = new MessageFormat("\"NewSessionTicket\": '{'\n  \"ticket_lifetime\"      : \"{0}\",\n  \"ticket_age_add\"       : \"{1}\",\n  \"ticket_nonce\"         : \"{2}\",\n  \"ticket\"               : \"{3}\",\n  \"extensions\"           : [\n{4}\n  ]\n'}'", Locale.ENGLISH);
            Object[] messageFields = {Integer.valueOf(this.ticketLifetime), "<omitted>", Utilities.toHexString(this.ticketNonce), Utilities.toHexString(this.ticket), Utilities.indent(this.extensions.toString(), "    ")};
            return messageFormat.format(messageFields);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static SecretKey derivePreSharedKey(CipherSuite.HashAlg hashAlg, SecretKey resumptionMasterSecret, byte[] nonce) throws IOException {
        try {
            HKDF hkdf = new HKDF(hashAlg.name);
            byte[] hkdfInfo = SSLSecretDerivation.createHkdfInfo("tls13 resumption".getBytes(), nonce, hashAlg.hashLength);
            return hkdf.expand(resumptionMasterSecret, hkdfInfo, hashAlg.hashLength, "TlsPreSharedKey");
        } catch (GeneralSecurityException gse) {
            throw ((SSLHandshakeException) new SSLHandshakeException("Could not derive PSK").initCause(gse));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/NewSessionTicket$NewSessionTicketKickstartProducer.class */
    private static final class NewSessionTicketKickstartProducer implements SSLProducer {
        private NewSessionTicketKickstartProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLProducer
        public byte[] produce(ConnectionContext context) throws IOException {
            PskKeyExchangeModesExtension.PskKeyExchangeModesSpec pkemSpec;
            ServerHandshakeContext shc = (ServerHandshakeContext) context;
            if (!shc.handshakeSession.isRejoinable() || (pkemSpec = (PskKeyExchangeModesExtension.PskKeyExchangeModesSpec) shc.handshakeExtensions.get(SSLExtension.PSK_KEY_EXCHANGE_MODES)) == null || !pkemSpec.contains(PskKeyExchangeModesExtension.PskKeyExchangeMode.PSK_DHE_KE)) {
                return null;
            }
            SSLSessionContextImpl sessionCache = (SSLSessionContextImpl) shc.sslContext.engineGetServerSessionContext();
            SessionId newId = new SessionId(true, shc.sslContext.getSecureRandom());
            SecretKey resumptionMasterSecret = shc.handshakeSession.getResumptionMasterSecret();
            if (resumptionMasterSecret == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Session has no resumption secret. No ticket sent.", new Object[0]);
                    return null;
                }
                return null;
            }
            BigInteger nonce = shc.handshakeSession.incrTicketNonceCounter();
            byte[] nonceArr = nonce.toByteArray();
            SecretKey psk = NewSessionTicket.derivePreSharedKey(shc.negotiatedCipherSuite.hashAlg, resumptionMasterSecret, nonceArr);
            int sessionTimeoutSeconds = sessionCache.getSessionTimeout();
            if (sessionTimeoutSeconds > NewSessionTicket.MAX_TICKET_LIFETIME) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Session timeout is too long. No ticket sent.", new Object[0]);
                    return null;
                }
                return null;
            }
            NewSessionTicketMessage nstm = new NewSessionTicketMessage(shc, sessionTimeoutSeconds, shc.sslContext.getSecureRandom(), nonceArr, newId.getId());
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced NewSessionTicket handshake message", nstm);
            }
            SSLSessionImpl sessionCopy = new SSLSessionImpl(shc.handshakeSession, newId);
            shc.handshakeSession.addChild(sessionCopy);
            sessionCopy.setPreSharedKey(psk);
            sessionCopy.setPskIdentity(newId.getId());
            sessionCopy.setTicketAgeAdd(nstm.ticketAgeAdd);
            sessionCache.put(sessionCopy);
            nstm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();
            return null;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/NewSessionTicket$NewSessionTicketProducer.class */
    private static final class NewSessionTicketProducer implements HandshakeProducer {
        private NewSessionTicketProducer() {
        }

        @Override // org.openjsse.sun.security.ssl.HandshakeProducer
        public byte[] produce(ConnectionContext context, SSLHandshake.HandshakeMessage message) throws IOException {
            throw new ProviderException("NewSessionTicket handshake producer not implemented");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/NewSessionTicket$NewSessionTicketConsumer.class */
    private static final class NewSessionTicketConsumer implements SSLConsumer {
        private NewSessionTicketConsumer() {
        }

        @Override // org.openjsse.sun.security.ssl.SSLConsumer
        public void consume(ConnectionContext context, ByteBuffer message) throws IOException {
            HandshakeContext hc = (HandshakeContext) context;
            NewSessionTicketMessage nstm = new NewSessionTicketMessage(hc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming NewSessionTicket message", nstm);
            }
            if (nstm.ticketLifetime <= 0 || nstm.ticketLifetime > NewSessionTicket.MAX_TICKET_LIFETIME) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Discarding NewSessionTicket with lifetime " + nstm.ticketLifetime, nstm);
                    return;
                }
                return;
            }
            SSLSessionContextImpl sessionCache = (SSLSessionContextImpl) hc.sslContext.engineGetClientSessionContext();
            if (sessionCache.getSessionTimeout() > NewSessionTicket.MAX_TICKET_LIFETIME) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Session cache lifetime is too long. Discarding ticket.", new Object[0]);
                    return;
                }
                return;
            }
            SSLSessionImpl sessionToSave = hc.conContext.conSession;
            SecretKey resumptionMasterSecret = sessionToSave.getResumptionMasterSecret();
            if (resumptionMasterSecret != null) {
                SecretKey psk = NewSessionTicket.derivePreSharedKey(sessionToSave.getSuite().hashAlg, resumptionMasterSecret, nstm.ticketNonce);
                SessionId newId = new SessionId(true, hc.sslContext.getSecureRandom());
                SSLSessionImpl sessionCopy = new SSLSessionImpl(sessionToSave, newId);
                sessionToSave.addChild(sessionCopy);
                sessionCopy.setPreSharedKey(psk);
                sessionCopy.setTicketAgeAdd(nstm.ticketAgeAdd);
                sessionCopy.setPskIdentity(nstm.ticket);
                sessionCache.put(sessionCopy);
                hc.conContext.finishPostHandshake();
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Session has no resumption master secret. Ignoring ticket.", new Object[0]);
            }
        }
    }
}