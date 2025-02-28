package org.bouncycastle.jsse;

import org.bouncycastle.tls.NameType;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public abstract class BCSNIServerName {
    private final byte[] encoded;
    private final int nameType;

    /* JADX INFO: Access modifiers changed from: protected */
    public BCSNIServerName(int i, byte[] bArr) {
        if (!TlsUtils.isValidUint8(i)) {
            throw new IllegalArgumentException("'nameType' should be between 0 and 255");
        }
        if (bArr == null) {
            throw new NullPointerException("'encoded' cannot be null");
        }
        this.nameType = i;
        this.encoded = TlsUtils.clone(bArr);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof BCSNIServerName) {
            BCSNIServerName bCSNIServerName = (BCSNIServerName) obj;
            return this.nameType == bCSNIServerName.nameType && Arrays.areEqual(this.encoded, bCSNIServerName.encoded);
        }
        return false;
    }

    public final byte[] getEncoded() {
        return TlsUtils.clone(this.encoded);
    }

    public final int getType() {
        return this.nameType;
    }

    public int hashCode() {
        return this.nameType ^ Arrays.hashCode(this.encoded);
    }

    public String toString() {
        return "{type=" + NameType.getText((short) this.nameType) + ", value=" + Hex.toHexString(this.encoded) + "}";
    }
}