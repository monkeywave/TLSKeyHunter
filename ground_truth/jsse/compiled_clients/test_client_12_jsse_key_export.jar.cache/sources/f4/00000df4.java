package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/WOTSPlusParameters.class */
final class WOTSPlusParameters {
    private final XMSSOid oid;
    private final int digestSize;
    private final int winternitzParameter;
    private final int len;
    private final int len1;
    private final int len2;
    private final ASN1ObjectIdentifier treeDigest;

    /* JADX INFO: Access modifiers changed from: protected */
    public WOTSPlusParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (aSN1ObjectIdentifier == null) {
            throw new NullPointerException("treeDigest == null");
        }
        this.treeDigest = aSN1ObjectIdentifier;
        Digest digest = DigestUtil.getDigest(aSN1ObjectIdentifier);
        this.digestSize = XMSSUtil.getDigestSize(digest);
        this.winternitzParameter = 16;
        this.len1 = (int) Math.ceil((8 * this.digestSize) / XMSSUtil.log2(this.winternitzParameter));
        this.len2 = ((int) Math.floor(XMSSUtil.log2(this.len1 * (this.winternitzParameter - 1)) / XMSSUtil.log2(this.winternitzParameter))) + 1;
        this.len = this.len1 + this.len2;
        this.oid = WOTSPlusOid.lookup(digest.getAlgorithmName(), this.digestSize, this.winternitzParameter, this.len);
        if (this.oid == null) {
            throw new IllegalArgumentException("cannot find OID for digest algorithm: " + digest.getAlgorithmName());
        }
    }

    protected XMSSOid getOid() {
        return this.oid;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getTreeDigestSize() {
        return this.digestSize;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getWinternitzParameter() {
        return this.winternitzParameter;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getLen() {
        return this.len;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getLen1() {
        return this.len1;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getLen2() {
        return this.len2;
    }

    public ASN1ObjectIdentifier getTreeDigest() {
        return this.treeDigest;
    }
}