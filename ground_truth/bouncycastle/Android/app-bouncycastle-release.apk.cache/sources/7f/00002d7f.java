package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public final class SessionParameters {
    private int cipherSuite;
    private byte[] encodedServerExtensions;
    private boolean extendedMasterSecret;
    private Certificate localCertificate;
    private TlsSecret masterSecret;
    private ProtocolVersion negotiatedVersion;
    private Certificate peerCertificate;
    private byte[] pskIdentity;
    private byte[] srpIdentity;

    /* loaded from: classes2.dex */
    public static final class Builder {
        private ProtocolVersion negotiatedVersion;
        private int cipherSuite = -1;
        private Certificate localCertificate = null;
        private TlsSecret masterSecret = null;
        private Certificate peerCertificate = null;
        private byte[] pskIdentity = null;
        private byte[] srpIdentity = null;
        private byte[] encodedServerExtensions = null;
        private boolean extendedMasterSecret = false;

        private void validate(boolean z, String str) {
            if (!z) {
                throw new IllegalStateException("Required session parameter '" + str + "' not configured");
            }
        }

        public SessionParameters build() {
            validate(this.cipherSuite >= 0, "cipherSuite");
            validate(this.masterSecret != null, "masterSecret");
            return new SessionParameters(this.cipherSuite, this.localCertificate, this.masterSecret, this.negotiatedVersion, this.peerCertificate, this.pskIdentity, this.srpIdentity, this.encodedServerExtensions, this.extendedMasterSecret);
        }

        public Builder setCipherSuite(int i) {
            this.cipherSuite = i;
            return this;
        }

        public Builder setExtendedMasterSecret(boolean z) {
            this.extendedMasterSecret = z;
            return this;
        }

        public Builder setLocalCertificate(Certificate certificate) {
            this.localCertificate = certificate;
            return this;
        }

        public Builder setMasterSecret(TlsSecret tlsSecret) {
            this.masterSecret = tlsSecret;
            return this;
        }

        public Builder setNegotiatedVersion(ProtocolVersion protocolVersion) {
            this.negotiatedVersion = protocolVersion;
            return this;
        }

        public Builder setPSKIdentity(byte[] bArr) {
            this.pskIdentity = bArr;
            return this;
        }

        public Builder setPeerCertificate(Certificate certificate) {
            this.peerCertificate = certificate;
            return this;
        }

        public Builder setSRPIdentity(byte[] bArr) {
            this.srpIdentity = bArr;
            return this;
        }

        public Builder setServerExtensions(Hashtable hashtable) throws IOException {
            if (hashtable == null || hashtable.isEmpty()) {
                this.encodedServerExtensions = null;
            } else {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                TlsProtocol.writeExtensions(byteArrayOutputStream, hashtable);
                this.encodedServerExtensions = byteArrayOutputStream.toByteArray();
            }
            return this;
        }
    }

    private SessionParameters(int i, Certificate certificate, TlsSecret tlsSecret, ProtocolVersion protocolVersion, Certificate certificate2, byte[] bArr, byte[] bArr2, byte[] bArr3, boolean z) {
        this.pskIdentity = null;
        this.srpIdentity = null;
        this.cipherSuite = i;
        this.localCertificate = certificate;
        this.masterSecret = tlsSecret;
        this.negotiatedVersion = protocolVersion;
        this.peerCertificate = certificate2;
        this.pskIdentity = Arrays.clone(bArr);
        this.srpIdentity = Arrays.clone(bArr2);
        this.encodedServerExtensions = bArr3;
        this.extendedMasterSecret = z;
    }

    public void clear() {
        TlsSecret tlsSecret = this.masterSecret;
        if (tlsSecret != null) {
            tlsSecret.destroy();
        }
    }

    public SessionParameters copy() {
        return new SessionParameters(this.cipherSuite, this.localCertificate, this.masterSecret, this.negotiatedVersion, this.peerCertificate, this.pskIdentity, this.srpIdentity, this.encodedServerExtensions, this.extendedMasterSecret);
    }

    public int getCipherSuite() {
        return this.cipherSuite;
    }

    public Certificate getLocalCertificate() {
        return this.localCertificate;
    }

    public TlsSecret getMasterSecret() {
        return this.masterSecret;
    }

    public ProtocolVersion getNegotiatedVersion() {
        return this.negotiatedVersion;
    }

    public byte[] getPSKIdentity() {
        return this.pskIdentity;
    }

    public Certificate getPeerCertificate() {
        return this.peerCertificate;
    }

    public byte[] getSRPIdentity() {
        return this.srpIdentity;
    }

    public boolean isExtendedMasterSecret() {
        return this.extendedMasterSecret;
    }

    public Hashtable readServerExtensions() throws IOException {
        if (this.encodedServerExtensions == null) {
            return null;
        }
        return TlsProtocol.readExtensions(new ByteArrayInputStream(this.encodedServerExtensions));
    }
}