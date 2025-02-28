package org.bouncycastle.pqc.crypto.xmss;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/WOTSPlusPrivateKeyParameters.class */
final class WOTSPlusPrivateKeyParameters {
    private final byte[][] privateKey;

    /* JADX INFO: Access modifiers changed from: protected */
    public WOTSPlusPrivateKeyParameters(WOTSPlusParameters wOTSPlusParameters, byte[][] bArr) {
        if (wOTSPlusParameters == null) {
            throw new NullPointerException("params == null");
        }
        if (bArr == null) {
            throw new NullPointerException("privateKey == null");
        }
        if (XMSSUtil.hasNullPointer(bArr)) {
            throw new NullPointerException("privateKey byte array == null");
        }
        if (bArr.length != wOTSPlusParameters.getLen()) {
            throw new IllegalArgumentException("wrong privateKey format");
        }
        for (byte[] bArr2 : bArr) {
            if (bArr2.length != wOTSPlusParameters.getTreeDigestSize()) {
                throw new IllegalArgumentException("wrong privateKey format");
            }
        }
        this.privateKey = XMSSUtil.cloneArray(bArr);
    }

    protected byte[][] toByteArray() {
        return XMSSUtil.cloneArray(this.privateKey);
    }
}