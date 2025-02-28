package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public interface TlsStreamVerifier {
    OutputStream getOutputStream() throws IOException;

    boolean isVerified() throws IOException;
}