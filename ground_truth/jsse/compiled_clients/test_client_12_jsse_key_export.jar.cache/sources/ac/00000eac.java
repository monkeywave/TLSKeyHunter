package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/SPHINCS256KeyGenParameterSpec.class */
public class SPHINCS256KeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final String SHA512_256 = "SHA512-256";
    public static final String SHA3_256 = "SHA3-256";
    private final String treeHash;

    public SPHINCS256KeyGenParameterSpec() {
        this(SHA512_256);
    }

    public SPHINCS256KeyGenParameterSpec(String str) {
        this.treeHash = str;
    }

    public String getTreeDigest() {
        return this.treeHash;
    }
}