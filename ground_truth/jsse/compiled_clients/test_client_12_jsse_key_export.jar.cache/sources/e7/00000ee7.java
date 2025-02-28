package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/StreamParsingException.class */
public class StreamParsingException extends Exception {

    /* renamed from: _e */
    Throwable f947_e;

    public StreamParsingException(String str, Throwable th) {
        super(str);
        this.f947_e = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f947_e;
    }
}