package org.bouncycastle.util;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/StoreException.class */
public class StoreException extends RuntimeException {

    /* renamed from: _e */
    private Throwable f946_e;

    public StoreException(String str, Throwable th) {
        super(str);
        this.f946_e = th;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f946_e;
    }
}