package org.bouncycastle.tls.crypto.impl.jcajce;

/* loaded from: classes2.dex */
class Exceptions {
    Exceptions() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static IllegalArgumentException illegalArgumentException(String str, Throwable th) {
        return new IllegalArgumentException(str, th);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static IllegalStateException illegalStateException(String str, Throwable th) {
        return new IllegalStateException(str, th);
    }
}