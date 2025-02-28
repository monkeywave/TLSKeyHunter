package org.bouncycastle.tls.crypto;

import java.io.IOException;
import org.bouncycastle.tls.DigitallySigned;

/* loaded from: classes2.dex */
public interface TlsVerifier {
    TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException;

    boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) throws IOException;
}