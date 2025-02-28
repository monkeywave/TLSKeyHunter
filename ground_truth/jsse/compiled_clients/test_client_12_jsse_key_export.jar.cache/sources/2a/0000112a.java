package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLBasicKeyDerivation.class */
final class SSLBasicKeyDerivation implements SSLKeyDerivation {
    private final String hashAlg;
    private final SecretKey secret;
    private final byte[] hkdfInfo;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SSLBasicKeyDerivation(SecretKey secret, String hashAlg, byte[] label, byte[] context, int length) {
        this.hashAlg = hashAlg.replace("-", "");
        this.secret = secret;
        this.hkdfInfo = createHkdfInfo(label, context, length);
    }

    @Override // org.openjsse.sun.security.ssl.SSLKeyDerivation
    public SecretKey deriveKey(String algorithm, AlgorithmParameterSpec keySpec) throws IOException {
        try {
            HKDF hkdf = new HKDF(this.hashAlg);
            return hkdf.expand(this.secret, this.hkdfInfo, ((SecretSizeSpec) keySpec).length, algorithm);
        } catch (GeneralSecurityException gse) {
            throw ((SSLHandshakeException) new SSLHandshakeException("Could not generate secret").initCause(gse));
        }
    }

    private static byte[] createHkdfInfo(byte[] label, byte[] context, int length) {
        byte[] info = new byte[4 + label.length + context.length];
        ByteBuffer m = ByteBuffer.wrap(info);
        try {
            Record.putInt16(m, length);
            Record.putBytes8(m, label);
            Record.putBytes8(m, context);
        } catch (IOException e) {
        }
        return info;
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLBasicKeyDerivation$SecretSizeSpec.class */
    static class SecretSizeSpec implements AlgorithmParameterSpec {
        final int length;

        /* JADX INFO: Access modifiers changed from: package-private */
        public SecretSizeSpec(int length) {
            this.length = length;
        }
    }
}