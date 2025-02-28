package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.openjsse.sun.security.ssl.CipherSuite;
import org.openjsse.sun.security.ssl.DHKeyExchange;
import org.openjsse.sun.security.ssl.ECDHKeyExchange;
import org.openjsse.sun.security.ssl.SupportedGroupsExtension;
import org.openjsse.sun.security.ssl.X509Authentication;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange.class */
public final class SSLKeyExchange implements SSLKeyAgreementGenerator, SSLHandshakeBinding {
    private final SSLAuthentication authentication;
    private final SSLKeyAgreement keyAgreement;

    SSLKeyExchange(X509Authentication authentication, SSLKeyAgreement keyAgreement) {
        this.authentication = authentication;
        this.keyAgreement = keyAgreement;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLPossession[] createPossessions(HandshakeContext context) {
        SSLPossession authPossession = null;
        if (this.authentication != null) {
            authPossession = this.authentication.createPossession(context);
            if (authPossession == null) {
                return new SSLPossession[0];
            }
            if (context instanceof ServerHandshakeContext) {
                ServerHandshakeContext shc = (ServerHandshakeContext) context;
                shc.interimAuthn = authPossession;
            }
        }
        if (this.keyAgreement == T12KeyAgreement.RSA_EXPORT) {
            X509Authentication.X509Possession x509Possession = (X509Authentication.X509Possession) authPossession;
            if (JsseJce.getRSAKeyLength(x509Possession.popCerts[0].getPublicKey()) <= 512) {
                return this.authentication != null ? new SSLPossession[]{authPossession} : new SSLPossession[0];
            }
            SSLPossession kaPossession = this.keyAgreement.createPossession(context);
            if (kaPossession == null) {
                return new SSLPossession[0];
            }
            return this.authentication != null ? new SSLPossession[]{authPossession, kaPossession} : new SSLPossession[]{kaPossession};
        }
        SSLPossession kaPossession2 = this.keyAgreement.createPossession(context);
        if (kaPossession2 != null) {
            return this.authentication != null ? new SSLPossession[]{authPossession, kaPossession2} : new SSLPossession[]{kaPossession2};
        } else if (this.keyAgreement == T12KeyAgreement.RSA || this.keyAgreement == T12KeyAgreement.ECDH) {
            return this.authentication != null ? new SSLPossession[]{authPossession} : new SSLPossession[0];
        } else {
            return new SSLPossession[0];
        }
    }

    @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
    public SSLKeyDerivation createKeyDerivation(HandshakeContext handshakeContext) throws IOException {
        return this.keyAgreement.createKeyDerivation(handshakeContext);
    }

    @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
    public SSLHandshake[] getRelatedHandshakers(HandshakeContext handshakeContext) {
        SSLHandshake[] auHandshakes;
        if (this.authentication != null) {
            auHandshakes = this.authentication.getRelatedHandshakers(handshakeContext);
        } else {
            auHandshakes = null;
        }
        SSLHandshake[] kaHandshakes = this.keyAgreement.getRelatedHandshakers(handshakeContext);
        if (auHandshakes == null || auHandshakes.length == 0) {
            return kaHandshakes;
        }
        if (kaHandshakes == null || kaHandshakes.length == 0) {
            return auHandshakes;
        }
        SSLHandshake[] producers = (SSLHandshake[]) Arrays.copyOf(auHandshakes, auHandshakes.length + kaHandshakes.length);
        System.arraycopy(kaHandshakes, 0, producers, auHandshakes.length, kaHandshakes.length);
        return producers;
    }

    @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
    public Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(HandshakeContext handshakeContext) {
        Map.Entry<Byte, HandshakeProducer>[] auProducers;
        if (this.authentication != null) {
            auProducers = this.authentication.getHandshakeProducers(handshakeContext);
        } else {
            auProducers = null;
        }
        Map.Entry<Byte, HandshakeProducer>[] kaProducers = this.keyAgreement.getHandshakeProducers(handshakeContext);
        if (auProducers == null || auProducers.length == 0) {
            return kaProducers;
        }
        if (kaProducers == null || kaProducers.length == 0) {
            return auProducers;
        }
        Map.Entry<Byte, HandshakeProducer>[] producers = (Map.Entry[]) Arrays.copyOf(auProducers, auProducers.length + kaProducers.length);
        System.arraycopy(kaProducers, 0, producers, auProducers.length, kaProducers.length);
        return producers;
    }

    @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
    public Map.Entry<Byte, SSLConsumer>[] getHandshakeConsumers(HandshakeContext handshakeContext) {
        Map.Entry<Byte, SSLConsumer>[] auConsumers;
        if (this.authentication != null) {
            auConsumers = this.authentication.getHandshakeConsumers(handshakeContext);
        } else {
            auConsumers = null;
        }
        Map.Entry<Byte, SSLConsumer>[] kaConsumers = this.keyAgreement.getHandshakeConsumers(handshakeContext);
        if (auConsumers == null || auConsumers.length == 0) {
            return kaConsumers;
        }
        if (kaConsumers == null || kaConsumers.length == 0) {
            return auConsumers;
        }
        Map.Entry<Byte, SSLConsumer>[] producers = (Map.Entry[]) Arrays.copyOf(auConsumers, auConsumers.length + kaConsumers.length);
        System.arraycopy(kaConsumers, 0, producers, auConsumers.length, kaConsumers.length);
        return producers;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLKeyExchange valueOf(CipherSuite.KeyExchange keyExchange, ProtocolVersion protocolVersion) {
        if (keyExchange == null || protocolVersion == null) {
            return null;
        }
        switch (keyExchange) {
            case K_RSA:
                return SSLKeyExRSA.f1002KE;
            case K_RSA_EXPORT:
                return SSLKeyExRSAExport.f1003KE;
            case K_DHE_DSS:
                return SSLKeyExDHEDSS.f991KE;
            case K_DHE_DSS_EXPORT:
                return SSLKeyExDHEDSSExport.f992KE;
            case K_DHE_RSA:
                if (!protocolVersion.useTLS12PlusSpec()) {
                    return SSLKeyExDHERSA.f993KE;
                }
                return SSLKeyExDHERSAOrPSS.f995KE;
            case K_DHE_RSA_EXPORT:
                return SSLKeyExDHERSAExport.f994KE;
            case K_DH_ANON:
                return SSLKeyExDHANON.f989KE;
            case K_DH_ANON_EXPORT:
                return SSLKeyExDHANONExport.f990KE;
            case K_ECDH_ECDSA:
                return SSLKeyExECDHECDSA.f997KE;
            case K_ECDH_RSA:
                return SSLKeyExECDHRSA.f1001KE;
            case K_ECDHE_ECDSA:
                return SSLKeyExECDHEECDSA.f998KE;
            case K_ECDHE_RSA:
                if (!protocolVersion.useTLS12PlusSpec()) {
                    return SSLKeyExECDHERSA.f999KE;
                }
                return SSLKeyExECDHERSAOrPSS.f1000KE;
            case K_ECDH_ANON:
                return SSLKeyExECDHANON.f996KE;
            default:
                return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SSLKeyExchange valueOf(SupportedGroupsExtension.NamedGroup namedGroup) {
        SSLKeyAgreement ka = T13KeyAgreement.valueOf(namedGroup);
        if (ka != null) {
            return new SSLKeyExchange(null, T13KeyAgreement.valueOf(namedGroup));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExRSA.class */
    public static class SSLKeyExRSA {

        /* renamed from: KE */
        private static SSLKeyExchange f1002KE = new SSLKeyExchange(X509Authentication.RSA, T12KeyAgreement.RSA);

        private SSLKeyExRSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExRSAExport.class */
    public static class SSLKeyExRSAExport {

        /* renamed from: KE */
        private static SSLKeyExchange f1003KE = new SSLKeyExchange(X509Authentication.RSA, T12KeyAgreement.RSA_EXPORT);

        private SSLKeyExRSAExport() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHEDSS.class */
    public static class SSLKeyExDHEDSS {

        /* renamed from: KE */
        private static SSLKeyExchange f991KE = new SSLKeyExchange(X509Authentication.DSA, T12KeyAgreement.DHE);

        private SSLKeyExDHEDSS() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHEDSSExport.class */
    public static class SSLKeyExDHEDSSExport {

        /* renamed from: KE */
        private static SSLKeyExchange f992KE = new SSLKeyExchange(X509Authentication.DSA, T12KeyAgreement.DHE_EXPORT);

        private SSLKeyExDHEDSSExport() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHERSA.class */
    public static class SSLKeyExDHERSA {

        /* renamed from: KE */
        private static SSLKeyExchange f993KE = new SSLKeyExchange(X509Authentication.RSA, T12KeyAgreement.DHE);

        private SSLKeyExDHERSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHERSAOrPSS.class */
    public static class SSLKeyExDHERSAOrPSS {

        /* renamed from: KE */
        private static SSLKeyExchange f995KE = new SSLKeyExchange(X509Authentication.RSA_OR_PSS, T12KeyAgreement.DHE);

        private SSLKeyExDHERSAOrPSS() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHERSAExport.class */
    public static class SSLKeyExDHERSAExport {

        /* renamed from: KE */
        private static SSLKeyExchange f994KE = new SSLKeyExchange(X509Authentication.RSA, T12KeyAgreement.DHE_EXPORT);

        private SSLKeyExDHERSAExport() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHANON.class */
    public static class SSLKeyExDHANON {

        /* renamed from: KE */
        private static SSLKeyExchange f989KE = new SSLKeyExchange(null, T12KeyAgreement.DHE);

        private SSLKeyExDHANON() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExDHANONExport.class */
    public static class SSLKeyExDHANONExport {

        /* renamed from: KE */
        private static SSLKeyExchange f990KE = new SSLKeyExchange(null, T12KeyAgreement.DHE_EXPORT);

        private SSLKeyExDHANONExport() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHECDSA.class */
    public static class SSLKeyExECDHECDSA {

        /* renamed from: KE */
        private static SSLKeyExchange f997KE = new SSLKeyExchange(X509Authentication.EC, T12KeyAgreement.ECDH);

        private SSLKeyExECDHECDSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHRSA.class */
    public static class SSLKeyExECDHRSA {

        /* renamed from: KE */
        private static SSLKeyExchange f1001KE = new SSLKeyExchange(X509Authentication.EC, T12KeyAgreement.ECDH);

        private SSLKeyExECDHRSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHEECDSA.class */
    public static class SSLKeyExECDHEECDSA {

        /* renamed from: KE */
        private static SSLKeyExchange f998KE = new SSLKeyExchange(X509Authentication.EC, T12KeyAgreement.ECDHE);

        private SSLKeyExECDHEECDSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHERSA.class */
    public static class SSLKeyExECDHERSA {

        /* renamed from: KE */
        private static SSLKeyExchange f999KE = new SSLKeyExchange(X509Authentication.RSA, T12KeyAgreement.ECDHE);

        private SSLKeyExECDHERSA() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHERSAOrPSS.class */
    public static class SSLKeyExECDHERSAOrPSS {

        /* renamed from: KE */
        private static SSLKeyExchange f1000KE = new SSLKeyExchange(X509Authentication.RSA_OR_PSS, T12KeyAgreement.ECDHE);

        private SSLKeyExECDHERSAOrPSS() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$SSLKeyExECDHANON.class */
    public static class SSLKeyExECDHANON {

        /* renamed from: KE */
        private static SSLKeyExchange f996KE = new SSLKeyExchange(null, T12KeyAgreement.ECDHE);

        private SSLKeyExECDHANON() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$T12KeyAgreement.class */
    public enum T12KeyAgreement implements SSLKeyAgreement {
        RSA("rsa", null, RSAKeyExchange.kaGenerator),
        RSA_EXPORT("rsa_export", RSAKeyExchange.poGenerator, RSAKeyExchange.kaGenerator),
        DHE("dhe", DHKeyExchange.poGenerator, DHKeyExchange.kaGenerator),
        DHE_EXPORT("dhe_export", DHKeyExchange.poExportableGenerator, DHKeyExchange.kaGenerator),
        ECDH("ecdh", null, ECDHKeyExchange.ecdhKAGenerator),
        ECDHE("ecdhe", ECDHKeyExchange.poGenerator, ECDHKeyExchange.ecdheKAGenerator);
        
        final String name;
        final SSLPossessionGenerator possessionGenerator;
        final SSLKeyAgreementGenerator keyAgreementGenerator;

        T12KeyAgreement(String name, SSLPossessionGenerator possessionGenerator, SSLKeyAgreementGenerator keyAgreementGenerator) {
            this.name = name;
            this.possessionGenerator = possessionGenerator;
            this.keyAgreementGenerator = keyAgreementGenerator;
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext context) {
            if (this.possessionGenerator != null) {
                return this.possessionGenerator.createPossession(context);
            }
            return null;
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext context) throws IOException {
            return this.keyAgreementGenerator.createKeyDerivation(context);
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
        public SSLHandshake[] getRelatedHandshakers(HandshakeContext handshakeContext) {
            return (handshakeContext.negotiatedProtocol.useTLS13PlusSpec() || this.possessionGenerator == null) ? new SSLHandshake[0] : new SSLHandshake[]{SSLHandshake.SERVER_KEY_EXCHANGE};
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
        public Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(HandshakeContext handshakeContext) {
            if (handshakeContext.negotiatedProtocol.useTLS13PlusSpec()) {
                return new Map.Entry[0];
            }
            if (!handshakeContext.sslConfig.isClientMode) {
                switch (this) {
                    case RSA_EXPORT:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), RSAServerKeyExchange.rsaHandshakeProducer)};
                    case DHE:
                    case DHE_EXPORT:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), DHServerKeyExchange.dhHandshakeProducer)};
                    case ECDHE:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), ECDHServerKeyExchange.ecdheHandshakeProducer)};
                }
            }
            switch (this) {
                case RSA:
                case RSA_EXPORT:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), RSAClientKeyExchange.rsaHandshakeProducer)};
                case DHE:
                case DHE_EXPORT:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), DHClientKeyExchange.dhHandshakeProducer)};
                case ECDH:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), ECDHClientKeyExchange.ecdhHandshakeProducer)};
                case ECDHE:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), ECDHClientKeyExchange.ecdheHandshakeProducer)};
            }
            return new Map.Entry[0];
        }

        @Override // org.openjsse.sun.security.ssl.SSLHandshakeBinding
        public Map.Entry<Byte, SSLConsumer>[] getHandshakeConsumers(HandshakeContext handshakeContext) {
            if (handshakeContext.negotiatedProtocol.useTLS13PlusSpec()) {
                return new Map.Entry[0];
            }
            if (handshakeContext.sslConfig.isClientMode) {
                switch (this) {
                    case RSA_EXPORT:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), RSAServerKeyExchange.rsaHandshakeConsumer)};
                    case DHE:
                    case DHE_EXPORT:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), DHServerKeyExchange.dhHandshakeConsumer)};
                    case ECDHE:
                        return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.SERVER_KEY_EXCHANGE.f987id), ECDHServerKeyExchange.ecdheHandshakeConsumer)};
                }
            }
            switch (this) {
                case RSA:
                case RSA_EXPORT:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), RSAClientKeyExchange.rsaHandshakeConsumer)};
                case DHE:
                case DHE_EXPORT:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), DHClientKeyExchange.dhHandshakeConsumer)};
                case ECDH:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), ECDHClientKeyExchange.ecdhHandshakeConsumer)};
                case ECDHE:
                    return new Map.Entry[]{new AbstractMap.SimpleImmutableEntry(Byte.valueOf(SSLHandshake.CLIENT_KEY_EXCHANGE.f987id), ECDHClientKeyExchange.ecdheHandshakeConsumer)};
            }
            return new Map.Entry[0];
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLKeyExchange$T13KeyAgreement.class */
    private static final class T13KeyAgreement implements SSLKeyAgreement {
        private final SupportedGroupsExtension.NamedGroup namedGroup;
        static final Map<SupportedGroupsExtension.NamedGroup, T13KeyAgreement> supportedKeyShares = new HashMap();

        static {
            SupportedGroupsExtension.NamedGroup[] namedGroupArr;
            for (SupportedGroupsExtension.NamedGroup namedGroup : SupportedGroupsExtension.SupportedGroups.supportedNamedGroups) {
                supportedKeyShares.put(namedGroup, new T13KeyAgreement(namedGroup));
            }
        }

        private T13KeyAgreement(SupportedGroupsExtension.NamedGroup namedGroup) {
            this.namedGroup = namedGroup;
        }

        static T13KeyAgreement valueOf(SupportedGroupsExtension.NamedGroup namedGroup) {
            return supportedKeyShares.get(namedGroup);
        }

        @Override // org.openjsse.sun.security.ssl.SSLPossessionGenerator
        public SSLPossession createPossession(HandshakeContext hc) {
            if (this.namedGroup.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                return new ECDHKeyExchange.ECDHEPossession(this.namedGroup, hc.sslContext.getSecureRandom());
            }
            if (this.namedGroup.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE) {
                return new DHKeyExchange.DHEPossession(this.namedGroup, hc.sslContext.getSecureRandom());
            }
            return null;
        }

        @Override // org.openjsse.sun.security.ssl.SSLKeyAgreementGenerator
        public SSLKeyDerivation createKeyDerivation(HandshakeContext hc) throws IOException {
            if (this.namedGroup.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_ECDHE) {
                return ECDHKeyExchange.ecdheKAGenerator.createKeyDerivation(hc);
            }
            if (this.namedGroup.type == SupportedGroupsExtension.NamedGroupType.NAMED_GROUP_FFDHE) {
                return DHKeyExchange.kaGenerator.createKeyDerivation(hc);
            }
            return null;
        }
    }
}