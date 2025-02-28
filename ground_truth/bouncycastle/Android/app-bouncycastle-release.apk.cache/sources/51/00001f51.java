package org.bouncycastle.jcajce;

import java.io.OutputStream;
import java.security.KeyStore;
import org.bouncycastle.crypto.util.PBKDFConfig;

/* loaded from: classes2.dex */
public class BCFKSStoreParameter implements KeyStore.LoadStoreParameter {
    private OutputStream out;
    private final KeyStore.ProtectionParameter protectionParameter;
    private final PBKDFConfig storeConfig;

    public BCFKSStoreParameter(OutputStream outputStream, PBKDFConfig pBKDFConfig, KeyStore.ProtectionParameter protectionParameter) {
        this.out = outputStream;
        this.storeConfig = pBKDFConfig;
        this.protectionParameter = protectionParameter;
    }

    public BCFKSStoreParameter(OutputStream outputStream, PBKDFConfig pBKDFConfig, char[] cArr) {
        this(outputStream, pBKDFConfig, new KeyStore.PasswordProtection(cArr));
    }

    public OutputStream getOutputStream() {
        return this.out;
    }

    @Override // java.security.KeyStore.LoadStoreParameter
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public PBKDFConfig getStorePBKDFConfig() {
        return this.storeConfig;
    }
}