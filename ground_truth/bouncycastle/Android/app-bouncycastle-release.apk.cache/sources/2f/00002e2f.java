package org.bouncycastle.tls.crypto.impl.p018bc;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.Exceptions */
/* loaded from: classes2.dex */
class Exceptions {
    Exceptions() {
    }

    static IllegalArgumentException illegalArgumentException(String str, Throwable th) {
        return new IllegalArgumentException(str, th);
    }
}