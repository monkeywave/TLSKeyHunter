package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/xmss/XMSSParameters.class */
public final class XMSSParameters {
    private static final Map<Integer, XMSSParameters> paramsLookupTable;
    private final XMSSOid oid;
    private final int height;

    /* renamed from: k */
    private final int f923k;
    private final ASN1ObjectIdentifier treeDigestOID;
    private final int winternitzParameter;
    private final String treeDigest;
    private final int treeDigestSize;
    private final WOTSPlusParameters wotsPlusParams;

    public XMSSParameters(int i, Digest digest) {
        this(i, DigestUtil.getDigestOID(digest.getAlgorithmName()));
    }

    public XMSSParameters(int i, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (i < 2) {
            throw new IllegalArgumentException("height must be >= 2");
        }
        if (aSN1ObjectIdentifier == null) {
            throw new NullPointerException("digest == null");
        }
        this.height = i;
        this.f923k = determineMinK();
        this.treeDigest = DigestUtil.getDigestName(aSN1ObjectIdentifier);
        this.treeDigestOID = aSN1ObjectIdentifier;
        this.wotsPlusParams = new WOTSPlusParameters(aSN1ObjectIdentifier);
        this.treeDigestSize = this.wotsPlusParams.getTreeDigestSize();
        this.winternitzParameter = this.wotsPlusParams.getWinternitzParameter();
        this.oid = DefaultXMSSOid.lookup(this.treeDigest, this.treeDigestSize, this.winternitzParameter, this.wotsPlusParams.getLen(), i);
    }

    private int determineMinK() {
        for (int i = 2; i <= this.height; i++) {
            if ((this.height - i) % 2 == 0) {
                return i;
            }
        }
        throw new IllegalStateException("should never happen...");
    }

    public int getTreeDigestSize() {
        return this.treeDigestSize;
    }

    public ASN1ObjectIdentifier getTreeDigestOID() {
        return this.treeDigestOID;
    }

    public int getHeight() {
        return this.height;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getTreeDigest() {
        return this.treeDigest;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLen() {
        return this.wotsPlusParams.getLen();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getWinternitzParameter() {
        return this.winternitzParameter;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlus getWOTSPlus() {
        return new WOTSPlus(this.wotsPlusParams);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public XMSSOid getOid() {
        return this.oid;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getK() {
        return this.f923k;
    }

    public static XMSSParameters lookupByOID(int i) {
        return paramsLookupTable.get(Integers.valueOf(i));
    }

    static {
        HashMap hashMap = new HashMap();
        hashMap.put(Integers.valueOf(1), new XMSSParameters(10, NISTObjectIdentifiers.id_sha256));
        hashMap.put(Integers.valueOf(2), new XMSSParameters(16, NISTObjectIdentifiers.id_sha256));
        hashMap.put(Integers.valueOf(3), new XMSSParameters(20, NISTObjectIdentifiers.id_sha256));
        hashMap.put(Integers.valueOf(4), new XMSSParameters(10, NISTObjectIdentifiers.id_sha512));
        hashMap.put(Integers.valueOf(5), new XMSSParameters(16, NISTObjectIdentifiers.id_sha512));
        hashMap.put(Integers.valueOf(6), new XMSSParameters(20, NISTObjectIdentifiers.id_sha512));
        hashMap.put(Integers.valueOf(7), new XMSSParameters(10, NISTObjectIdentifiers.id_shake128));
        hashMap.put(Integers.valueOf(8), new XMSSParameters(16, NISTObjectIdentifiers.id_shake128));
        hashMap.put(Integers.valueOf(9), new XMSSParameters(20, NISTObjectIdentifiers.id_shake128));
        hashMap.put(Integers.valueOf(10), new XMSSParameters(10, NISTObjectIdentifiers.id_shake256));
        hashMap.put(Integers.valueOf(11), new XMSSParameters(16, NISTObjectIdentifiers.id_shake256));
        hashMap.put(Integers.valueOf(12), new XMSSParameters(20, NISTObjectIdentifiers.id_shake256));
        paramsLookupTable = Collections.unmodifiableMap(hashMap);
    }
}