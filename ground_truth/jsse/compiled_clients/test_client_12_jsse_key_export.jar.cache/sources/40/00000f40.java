package org.bouncycastle.x509.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/util/StreamParsingException.class */
public class StreamParsingException extends Exception {

    /* renamed from: _e */
    Throwable f949_e;

    public StreamParsingException(String str, Throwable th) {
        super(str);
        this.f949_e = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f949_e;
    }
}