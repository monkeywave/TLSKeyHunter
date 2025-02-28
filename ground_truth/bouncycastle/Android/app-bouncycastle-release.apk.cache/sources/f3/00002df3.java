package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/* loaded from: classes2.dex */
public final class LegacyTls13Verifier implements TlsVerifier {
    private final int signatureScheme;
    private final Tls13Verifier tls13Verifier;

    public LegacyTls13Verifier(int i, Tls13Verifier tls13Verifier) {
        if (!TlsUtils.isValidUint16(i)) {
            throw new IllegalArgumentException("'signatureScheme'");
        }
        if (tls13Verifier == null) {
            throw new NullPointerException("'tls13Verifier' cannot be null");
        }
        this.signatureScheme = i;
        this.tls13Verifier = tls13Verifier;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != this.signatureScheme) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }
        final byte[] signature = digitallySigned.getSignature();
        return new TlsStreamVerifier() { // from class: org.bouncycastle.tls.crypto.impl.LegacyTls13Verifier.1
            @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
            public OutputStream getOutputStream() throws IOException {
                return LegacyTls13Verifier.this.tls13Verifier.getOutputStream();
            }

            @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
            public boolean isVerified() throws IOException {
                return LegacyTls13Verifier.this.tls13Verifier.verifySignature(signature);
            }
        };
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) throws IOException {
        throw new UnsupportedOperationException();
    }
}