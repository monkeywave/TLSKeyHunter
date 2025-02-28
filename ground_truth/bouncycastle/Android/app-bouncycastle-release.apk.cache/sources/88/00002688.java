package org.bouncycastle.jsse.provider;

import java.security.KeyStore;

/* loaded from: classes2.dex */
class KeyStoreConfig {
    final KeyStore keyStore;
    final char[] password;

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeyStoreConfig(KeyStore keyStore, char[] cArr) {
        this.keyStore = keyStore;
        this.password = cArr;
    }
}