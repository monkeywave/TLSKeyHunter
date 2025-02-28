package org.openjsse.sun.security.ssl;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator.class */
public abstract class Authenticator {
    protected final byte[] block;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean seqNumOverflow();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean seqNumIsHuge();

    private Authenticator(byte[] block) {
        this.block = block;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Authenticator valueOf(ProtocolVersion protocolVersion) {
        if (protocolVersion.isDTLS) {
            if (protocolVersion.useTLS13PlusSpec()) {
                return new DTLS13Authenticator(protocolVersion);
            }
            return new DTLS10Authenticator(protocolVersion);
        } else if (protocolVersion.useTLS13PlusSpec()) {
            return new TLS13Authenticator(protocolVersion);
        } else {
            if (protocolVersion.useTLS10PlusSpec()) {
                return new TLS10Authenticator(protocolVersion);
            }
            return new SSL30Authenticator();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static <T extends Authenticator & MAC> T valueOf(ProtocolVersion protocolVersion, CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        if (protocolVersion.isDTLS) {
            if (protocolVersion.useTLS13PlusSpec()) {
                throw new RuntimeException("No MacAlg used in DTLS 1.3");
            }
            return new DTLS10Mac(protocolVersion, macAlg, key);
        } else if (protocolVersion.useTLS13PlusSpec()) {
            throw new RuntimeException("No MacAlg used in TLS 1.3");
        } else {
            if (protocolVersion.useTLS10PlusSpec()) {
                return new TLS10Mac(protocolVersion, macAlg, key);
            }
            return new SSL30Mac(protocolVersion, macAlg, key);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Authenticator nullTlsMac() {
        return new SSLNullMac();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Authenticator nullDtlsMac() {
        return new DTLSNullMac();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final byte[] sequenceNumber() {
        return Arrays.copyOf(this.block, 8);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEpochNumber(int epoch) {
        throw new UnsupportedOperationException("Epoch numbers apply to DTLS protocols only");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public final void increaseSequenceNumber() {
        for (int k = 7; k >= 0; k--) {
            byte[] bArr = this.block;
            int i = k;
            byte b = (byte) (bArr[i] + 1);
            bArr[i] = b;
            if (b != 0) {
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
        throw new UnsupportedOperationException("Used by AEAD algorithms only");
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$SSLAuthenticator.class */
    private static class SSLAuthenticator extends Authenticator {
        private SSLAuthenticator(byte[] block) {
            super(block);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        boolean seqNumOverflow() {
            return this.block.length != 0 && this.block[0] == -1 && this.block[1] == -1 && this.block[2] == -1 && this.block[3] == -1 && this.block[4] == -1 && this.block[5] == -1 && this.block[6] == -1;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        boolean seqNumIsHuge() {
            return this.block.length != 0 && this.block[0] == -1 && this.block[1] == -1 && this.block[2] == -1 && this.block[3] == -1;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$SSLNullAuthenticator.class */
    private static class SSLNullAuthenticator extends SSLAuthenticator {
        private SSLNullAuthenticator() {
            super(new byte[8]);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$SSL30Authenticator.class */
    private static class SSL30Authenticator extends SSLAuthenticator {
        private static final int BLOCK_SIZE = 11;

        private SSL30Authenticator() {
            super(new byte[11]);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
            byte[] ad = (byte[]) this.block.clone();
            increaseSequenceNumber();
            ad[8] = type;
            ad[9] = (byte) (length >> 8);
            ad[10] = (byte) length;
            return ad;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$TLS10Authenticator.class */
    private static class TLS10Authenticator extends SSLAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private TLS10Authenticator(ProtocolVersion protocolVersion) {
            super(new byte[13]);
            this.block[9] = protocolVersion.major;
            this.block[10] = protocolVersion.minor;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
            byte[] ad = (byte[]) this.block.clone();
            if (sequence != null) {
                if (sequence.length != 8) {
                    throw new RuntimeException("Insufficient explicit sequence number bytes");
                }
                System.arraycopy(sequence, 0, ad, 0, sequence.length);
            } else {
                increaseSequenceNumber();
            }
            ad[8] = type;
            ad[11] = (byte) (length >> 8);
            ad[12] = (byte) length;
            return ad;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$TLS13Authenticator.class */
    private static final class TLS13Authenticator extends SSLAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private TLS13Authenticator(ProtocolVersion protocolVersion) {
            super(new byte[13]);
            this.block[9] = ProtocolVersion.TLS12.major;
            this.block[10] = ProtocolVersion.TLS12.minor;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
            byte[] ad = Arrays.copyOfRange(this.block, 8, 13);
            increaseSequenceNumber();
            ad[0] = type;
            ad[3] = (byte) (length >> 8);
            ad[4] = (byte) (length & GF2Field.MASK);
            return ad;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLSAuthenticator.class */
    private static class DTLSAuthenticator extends Authenticator {
        private DTLSAuthenticator(byte[] block) {
            super(block);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        boolean seqNumOverflow() {
            return this.block.length != 0 && this.block[2] == -1 && this.block[3] == -1 && this.block[4] == -1 && this.block[5] == -1 && this.block[6] == -1;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        boolean seqNumIsHuge() {
            return this.block.length != 0 && this.block[2] == -1 && this.block[3] == -1;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        void setEpochNumber(int epoch) {
            this.block[0] = (byte) ((epoch >> 8) & GF2Field.MASK);
            this.block[1] = (byte) (epoch & GF2Field.MASK);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLSNullAuthenticator.class */
    private static class DTLSNullAuthenticator extends DTLSAuthenticator {
        private DTLSNullAuthenticator() {
            super(new byte[8]);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLS10Authenticator.class */
    private static class DTLS10Authenticator extends DTLSAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private DTLS10Authenticator(ProtocolVersion protocolVersion) {
            super(new byte[13]);
            this.block[9] = protocolVersion.major;
            this.block[10] = protocolVersion.minor;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
            byte[] ad = (byte[]) this.block.clone();
            if (sequence != null) {
                if (sequence.length != 8) {
                    throw new RuntimeException("Insufficient explicit sequence number bytes");
                }
                System.arraycopy(sequence, 0, ad, 0, sequence.length);
            } else {
                increaseSequenceNumber();
            }
            ad[8] = type;
            ad[11] = (byte) (length >> 8);
            ad[12] = (byte) length;
            return ad;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLS13Authenticator.class */
    private static final class DTLS13Authenticator extends DTLSAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private DTLS13Authenticator(ProtocolVersion protocolVersion) {
            super(new byte[13]);
            this.block[9] = ProtocolVersion.TLS12.major;
            this.block[10] = ProtocolVersion.TLS12.minor;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator
        byte[] acquireAuthenticationBytes(byte type, int length, byte[] sequence) {
            byte[] ad = Arrays.copyOfRange(this.block, 8, 13);
            increaseSequenceNumber();
            ad[0] = type;
            ad[3] = (byte) (length >> 8);
            ad[4] = (byte) (length & GF2Field.MASK);
            return ad;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$MAC.class */
    public interface MAC {
        CipherSuite.MacAlg macAlg();

        byte[] compute(byte b, ByteBuffer byteBuffer, byte[] bArr, boolean z);

        default byte[] compute(byte type, ByteBuffer bb, boolean isSimulated) {
            return compute(type, bb, null, isSimulated);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$MacImpl.class */
    private class MacImpl implements MAC {
        private final CipherSuite.MacAlg macAlg;
        private final Mac mac;

        private MacImpl() {
            this.macAlg = CipherSuite.MacAlg.M_NULL;
            this.mac = null;
        }

        private MacImpl(ProtocolVersion protocolVersion, CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
            String algorithm;
            if (macAlg == null) {
                throw new RuntimeException("Null MacAlg");
            }
            boolean useSSLMac = protocolVersion.f978id < ProtocolVersion.TLS10.f978id;
            switch (macAlg) {
                case M_MD5:
                    algorithm = useSSLMac ? "SslMacMD5" : "HmacMD5";
                    break;
                case M_SHA:
                    algorithm = useSSLMac ? "SslMacSHA1" : "HmacSHA1";
                    break;
                case M_SHA256:
                    algorithm = "HmacSHA256";
                    break;
                case M_SHA384:
                    algorithm = "HmacSHA384";
                    break;
                default:
                    throw new RuntimeException("Unknown MacAlg " + macAlg);
            }
            Mac m = JsseJce.getMac(algorithm);
            m.init(key);
            this.macAlg = macAlg;
            this.mac = m;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            if (this.macAlg.size == 0) {
                return new byte[0];
            }
            if (!isSimulated) {
                byte[] additional = Authenticator.this.acquireAuthenticationBytes(type, bb.remaining(), sequence);
                this.mac.update(additional);
            }
            this.mac.update(bb);
            return this.mac.doFinal();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$SSLNullMac.class */
    public static final class SSLNullMac extends SSLNullAuthenticator implements MAC {
        private final MacImpl macImpl;

        public SSLNullMac() {
            super();
            this.macImpl = new MacImpl();
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macImpl.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            return this.macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$SSL30Mac.class */
    private static final class SSL30Mac extends SSL30Authenticator implements MAC {
        private final MacImpl macImpl;

        public SSL30Mac(ProtocolVersion protocolVersion, CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
            super();
            this.macImpl = new MacImpl(protocolVersion, macAlg, key);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macImpl.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            return this.macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$TLS10Mac.class */
    private static final class TLS10Mac extends TLS10Authenticator implements MAC {
        private final MacImpl macImpl;

        public TLS10Mac(ProtocolVersion protocolVersion, CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
            super(protocolVersion);
            this.macImpl = new MacImpl(protocolVersion, macAlg, key);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macImpl.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            return this.macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLSNullMac.class */
    public static final class DTLSNullMac extends DTLSNullAuthenticator implements MAC {
        private final MacImpl macImpl;

        public DTLSNullMac() {
            super();
            this.macImpl = new MacImpl();
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macImpl.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            return this.macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Authenticator$DTLS10Mac.class */
    private static final class DTLS10Mac extends DTLS10Authenticator implements MAC {
        private final MacImpl macImpl;

        public DTLS10Mac(ProtocolVersion protocolVersion, CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
            super(protocolVersion);
            this.macImpl = new MacImpl(protocolVersion, macAlg, key);
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public CipherSuite.MacAlg macAlg() {
            return this.macImpl.macAlg;
        }

        @Override // org.openjsse.sun.security.ssl.Authenticator.MAC
        public byte[] compute(byte type, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
            return this.macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final long toLong(byte[] recordEnS) {
        if (recordEnS != null && recordEnS.length == 8) {
            return ((recordEnS[0] & 255) << 56) | ((recordEnS[1] & 255) << 48) | ((recordEnS[2] & 255) << 40) | ((recordEnS[3] & 255) << 32) | ((recordEnS[4] & 255) << 24) | ((recordEnS[5] & 255) << 16) | ((recordEnS[6] & 255) << 8) | (recordEnS[7] & 255);
        }
        return -1L;
    }
}