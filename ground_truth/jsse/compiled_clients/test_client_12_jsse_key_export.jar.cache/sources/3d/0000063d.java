package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/BCLoadStoreParameter.class */
public class BCLoadStoreParameter implements KeyStore.LoadStoreParameter {

    /* renamed from: in */
    private final InputStream f590in;
    private final OutputStream out;
    private final KeyStore.ProtectionParameter protectionParameter;

    public BCLoadStoreParameter(OutputStream outputStream, char[] cArr) {
        this(outputStream, new KeyStore.PasswordProtection(cArr));
    }

    public BCLoadStoreParameter(InputStream inputStream, char[] cArr) {
        this(inputStream, new KeyStore.PasswordProtection(cArr));
    }

    public BCLoadStoreParameter(InputStream inputStream, KeyStore.ProtectionParameter protectionParameter) {
        this(inputStream, null, protectionParameter);
    }

    public BCLoadStoreParameter(OutputStream outputStream, KeyStore.ProtectionParameter protectionParameter) {
        this(null, outputStream, protectionParameter);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCLoadStoreParameter(InputStream inputStream, OutputStream outputStream, KeyStore.ProtectionParameter protectionParameter) {
        this.f590in = inputStream;
        this.out = outputStream;
        this.protectionParameter = protectionParameter;
    }

    @Override // java.security.KeyStore.LoadStoreParameter
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return this.protectionParameter;
    }

    public OutputStream getOutputStream() {
        if (this.out == null) {
            throw new UnsupportedOperationException("parameter not configured for storage - no OutputStream");
        }
        return this.out;
    }

    public InputStream getInputStream() {
        if (this.out != null) {
            throw new UnsupportedOperationException("parameter configured for storage OutputStream present");
        }
        return this.f590in;
    }
}