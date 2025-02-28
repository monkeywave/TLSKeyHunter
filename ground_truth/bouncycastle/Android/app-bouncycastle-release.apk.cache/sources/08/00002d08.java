package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class BasicTlsSRPIdentity implements TlsSRPIdentity {
    protected byte[] identity;
    protected byte[] password;

    public BasicTlsSRPIdentity(String str, String str2) {
        this.identity = Strings.toUTF8ByteArray(str);
        this.password = Strings.toUTF8ByteArray(str2);
    }

    public BasicTlsSRPIdentity(byte[] bArr, byte[] bArr2) {
        this.identity = Arrays.clone(bArr);
        this.password = Arrays.clone(bArr2);
    }

    @Override // org.bouncycastle.tls.TlsSRPIdentity
    public byte[] getSRPIdentity() {
        return this.identity;
    }

    @Override // org.bouncycastle.tls.TlsSRPIdentity
    public byte[] getSRPPassword() {
        return this.password;
    }
}