package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/GOST28147ParameterSpec.class */
public class GOST28147ParameterSpec implements AlgorithmParameterSpec {

    /* renamed from: iv */
    private byte[] f625iv;
    private byte[] sBox;
    private static Map oidMappings = new HashMap();

    public GOST28147ParameterSpec(byte[] bArr) {
        this.f625iv = null;
        this.sBox = null;
        this.sBox = new byte[bArr.length];
        System.arraycopy(bArr, 0, this.sBox, 0, bArr.length);
    }

    public GOST28147ParameterSpec(byte[] bArr, byte[] bArr2) {
        this(bArr);
        this.f625iv = new byte[bArr2.length];
        System.arraycopy(bArr2, 0, this.f625iv, 0, bArr2.length);
    }

    public GOST28147ParameterSpec(String str) {
        this.f625iv = null;
        this.sBox = null;
        this.sBox = GOST28147Engine.getSBox(str);
    }

    public GOST28147ParameterSpec(String str, byte[] bArr) {
        this(str);
        this.f625iv = new byte[bArr.length];
        System.arraycopy(bArr, 0, this.f625iv, 0, bArr.length);
    }

    public GOST28147ParameterSpec(ASN1ObjectIdentifier aSN1ObjectIdentifier, byte[] bArr) {
        this(getName(aSN1ObjectIdentifier));
        this.f625iv = Arrays.clone(bArr);
    }

    public byte[] getSbox() {
        return Arrays.clone(this.sBox);
    }

    public byte[] getSBox() {
        return Arrays.clone(this.sBox);
    }

    public byte[] getIV() {
        return Arrays.clone(this.f625iv);
    }

    private static String getName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        String str = (String) oidMappings.get(aSN1ObjectIdentifier);
        if (str == null) {
            throw new IllegalArgumentException("unknown OID: " + aSN1ObjectIdentifier);
        }
        return str;
    }

    static {
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
        oidMappings.put(RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, "Param-Z");
    }
}