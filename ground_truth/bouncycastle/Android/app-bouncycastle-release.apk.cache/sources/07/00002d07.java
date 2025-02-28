package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class BasicTlsPSKIdentity implements TlsPSKIdentity {
    protected byte[] identity;
    protected byte[] psk;

    public BasicTlsPSKIdentity(String str, byte[] bArr) {
        this.identity = Strings.toUTF8ByteArray(str);
        this.psk = Arrays.clone(bArr);
    }

    public BasicTlsPSKIdentity(byte[] bArr, byte[] bArr2) {
        this.identity = Arrays.clone(bArr);
        this.psk = Arrays.clone(bArr2);
    }

    @Override // org.bouncycastle.tls.TlsPSKIdentity
    public byte[] getPSK() {
        return Arrays.clone(this.psk);
    }

    @Override // org.bouncycastle.tls.TlsPSKIdentity
    public byte[] getPSKIdentity() {
        return this.identity;
    }

    @Override // org.bouncycastle.tls.TlsPSKIdentity
    public void notifyIdentityHint(byte[] bArr) {
    }

    @Override // org.bouncycastle.tls.TlsPSKIdentity
    public void skipIdentityHint() {
    }
}