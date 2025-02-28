package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsHash;

/* loaded from: classes2.dex */
public interface TlsHandshakeHash extends TlsHash {
    void copyBufferTo(OutputStream outputStream) throws IOException;

    void forceBuffering();

    TlsHash forkPRFHash();

    byte[] getFinalHash(int i);

    void notifyPRFDetermined();

    void sealHashAlgorithms();

    void stopTracking();

    void trackHashAlgorithm(int i);
}