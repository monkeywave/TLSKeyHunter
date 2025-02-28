package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public final class XMSSParameters {
    private static final Map<Integer, XMSSParameters> paramsLookupTable;
    private final int height;

    /* renamed from: k */
    private final int f1456k;
    private final XMSSOid oid;
    private final String treeDigest;
    private final ASN1ObjectIdentifier treeDigestOID;
    private final int treeDigestSize;
    private final int winternitzParameter;
    private final WOTSPlusParameters wotsPlusParams;

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

    public XMSSParameters(int i, ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (i < 2) {
            throw new IllegalArgumentException("height must be >= 2");
        }
        if (aSN1ObjectIdentifier == null) {
            throw new NullPointerException("digest == null");
        }
        this.height = i;
        this.f1456k = determineMinK();
        String digestName = DigestUtil.getDigestName(aSN1ObjectIdentifier);
        this.treeDigest = digestName;
        this.treeDigestOID = aSN1ObjectIdentifier;
        WOTSPlusParameters wOTSPlusParameters = new WOTSPlusParameters(aSN1ObjectIdentifier);
        this.wotsPlusParams = wOTSPlusParameters;
        int treeDigestSize = wOTSPlusParameters.getTreeDigestSize();
        this.treeDigestSize = treeDigestSize;
        int winternitzParameter = wOTSPlusParameters.getWinternitzParameter();
        this.winternitzParameter = winternitzParameter;
        this.oid = DefaultXMSSOid.lookup(digestName, treeDigestSize, winternitzParameter, wOTSPlusParameters.getLen(), i);
    }

    public XMSSParameters(int i, Digest digest) {
        this(i, DigestUtil.getDigestOID(digest.getAlgorithmName()));
    }

    private int determineMinK() {
        int i = 2;
        while (true) {
            int i2 = this.height;
            if (i > i2) {
                throw new IllegalStateException("should never happen...");
            }
            if ((i2 - i) % 2 == 0) {
                return i;
            }
            i++;
        }
    }

    public static XMSSParameters lookupByOID(int i) {
        return paramsLookupTable.get(Integers.valueOf(i));
    }

    public int getHeight() {
        return this.height;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getK() {
        return this.f1456k;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLen() {
        return this.wotsPlusParams.getLen();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public XMSSOid getOid() {
        return this.oid;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getTreeDigest() {
        return this.treeDigest;
    }

    public ASN1ObjectIdentifier getTreeDigestOID() {
        return this.treeDigestOID;
    }

    public int getTreeDigestSize() {
        return this.treeDigestSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WOTSPlus getWOTSPlus() {
        return new WOTSPlus(this.wotsPlusParams);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getWinternitzParameter() {
        return this.winternitzParameter;
    }
}