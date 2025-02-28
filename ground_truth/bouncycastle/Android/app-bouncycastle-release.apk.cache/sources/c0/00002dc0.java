package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TlsSessionImpl implements TlsSession {
    boolean resumable;
    final byte[] sessionID;
    final SessionParameters sessionParameters;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsSessionImpl(byte[] bArr, SessionParameters sessionParameters) {
        if (bArr == null) {
            throw new IllegalArgumentException("'sessionID' cannot be null");
        }
        if (bArr.length > 32) {
            throw new IllegalArgumentException("'sessionID' cannot be longer than 32 bytes");
        }
        this.sessionID = Arrays.clone(bArr);
        this.sessionParameters = sessionParameters;
        this.resumable = bArr.length > 0 && sessionParameters != null;
    }

    @Override // org.bouncycastle.tls.TlsSession
    public synchronized SessionParameters exportSessionParameters() {
        SessionParameters sessionParameters;
        sessionParameters = this.sessionParameters;
        return sessionParameters == null ? null : sessionParameters.copy();
    }

    @Override // org.bouncycastle.tls.TlsSession
    public synchronized byte[] getSessionID() {
        return this.sessionID;
    }

    @Override // org.bouncycastle.tls.TlsSession
    public synchronized void invalidate() {
        this.resumable = false;
    }

    @Override // org.bouncycastle.tls.TlsSession
    public synchronized boolean isResumable() {
        return this.resumable;
    }
}