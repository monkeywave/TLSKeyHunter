package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincs/SPHINCSKeyParameters.class */
public class SPHINCSKeyParameters extends AsymmetricKeyParameter {
    public static final String SHA512_256 = "SHA-512/256";
    public static final String SHA3_256 = "SHA3-256";
    private final String treeDigest;

    /* JADX INFO: Access modifiers changed from: protected */
    public SPHINCSKeyParameters(boolean z, String str) {
        super(z);
        this.treeDigest = str;
    }

    public String getTreeDigest() {
        return this.treeDigest;
    }
}