package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class SignatureAndHashAlgorithm {
    protected final short hash;
    protected final short signature;
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP256r1tls13_sha256 = create(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP384r1tls13_sha384 = create(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP512r1tls13_sha512 = create(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512);
    public static final SignatureAndHashAlgorithm ed25519 = create(SignatureScheme.ed25519);
    public static final SignatureAndHashAlgorithm ed448 = create(SignatureScheme.ed448);
    public static final SignatureAndHashAlgorithm gostr34102012_256 = create(8, 64);
    public static final SignatureAndHashAlgorithm gostr34102012_512 = create(8, 65);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha256 = create(SignatureScheme.rsa_pss_rsae_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha384 = create(SignatureScheme.rsa_pss_rsae_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha512 = create(SignatureScheme.rsa_pss_rsae_sha512);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha256 = create(SignatureScheme.rsa_pss_pss_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha384 = create(SignatureScheme.rsa_pss_pss_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha512 = create(SignatureScheme.rsa_pss_pss_sha512);

    public SignatureAndHashAlgorithm(short s, short s2) {
        if ((s & 255) != s) {
            throw new IllegalArgumentException("'hash' should be a uint8");
        }
        if ((s2 & 255) != s2) {
            throw new IllegalArgumentException("'signature' should be a uint8");
        }
        this.hash = s;
        this.signature = s2;
    }

    private static SignatureAndHashAlgorithm create(int i) {
        return create(SignatureScheme.getHashAlgorithm(i), SignatureScheme.getSignatureAlgorithm(i));
    }

    private static SignatureAndHashAlgorithm create(short s, short s2) {
        return new SignatureAndHashAlgorithm(s, s2);
    }

    public static SignatureAndHashAlgorithm getInstance(short s, short s2) {
        return s != 8 ? create(s, s2) : getInstanceIntrinsic(s2);
    }

    private static SignatureAndHashAlgorithm getInstanceIntrinsic(short s) {
        if (s != 64) {
            if (s != 65) {
                switch (s) {
                    case 4:
                        return rsa_pss_rsae_sha256;
                    case 5:
                        return rsa_pss_rsae_sha384;
                    case 6:
                        return rsa_pss_rsae_sha512;
                    case 7:
                        return ed25519;
                    case 8:
                        return ed448;
                    case 9:
                        return rsa_pss_pss_sha256;
                    case 10:
                        return rsa_pss_pss_sha384;
                    case 11:
                        return rsa_pss_pss_sha512;
                    default:
                        switch (s) {
                            case 26:
                                return ecdsa_brainpoolP256r1tls13_sha256;
                            case 27:
                                return ecdsa_brainpoolP384r1tls13_sha384;
                            case 28:
                                return ecdsa_brainpoolP512r1tls13_sha512;
                            default:
                                return create((short) 8, s);
                        }
                }
            }
            return gostr34102012_512;
        }
        return gostr34102012_256;
    }

    public static SignatureAndHashAlgorithm parse(InputStream inputStream) throws IOException {
        return getInstance(TlsUtils.readUint8(inputStream), TlsUtils.readUint8(inputStream));
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint8(getHash(), outputStream);
        TlsUtils.writeUint8(getSignature(), outputStream);
    }

    public boolean equals(Object obj) {
        if (obj instanceof SignatureAndHashAlgorithm) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) obj;
            return signatureAndHashAlgorithm.getHash() == getHash() && signatureAndHashAlgorithm.getSignature() == getSignature();
        }
        return false;
    }

    public short getHash() {
        return this.hash;
    }

    public short getSignature() {
        return this.signature;
    }

    public int hashCode() {
        return (getHash() << 16) | getSignature();
    }

    public String toString() {
        return "{" + HashAlgorithm.getText(this.hash) + "," + SignatureAlgorithm.getText(this.signature) + "}";
    }
}