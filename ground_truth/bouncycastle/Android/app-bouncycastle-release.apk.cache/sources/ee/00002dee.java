package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public interface TlsStreamSigner {
    OutputStream getOutputStream() throws IOException;

    byte[] getSignature() throws IOException;
}