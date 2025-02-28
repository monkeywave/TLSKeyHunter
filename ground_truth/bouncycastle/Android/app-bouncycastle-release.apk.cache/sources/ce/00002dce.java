package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public interface Tls13Verifier {
    OutputStream getOutputStream() throws IOException;

    boolean verifySignature(byte[] bArr) throws IOException;
}