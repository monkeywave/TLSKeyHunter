package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.PublicKey;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.RainbowPublicKey;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.pqc.jcajce.spec.RainbowPublicKeySpec;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/rainbow/BCRainbowPublicKey.class */
public class BCRainbowPublicKey implements PublicKey {
    private static final long serialVersionUID = 1;
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;
    private int docLength;
    private RainbowParameters rainbowParams;

    public BCRainbowPublicKey(int i, short[][] sArr, short[][] sArr2, short[] sArr3) {
        this.docLength = i;
        this.coeffquadratic = sArr;
        this.coeffsingular = sArr2;
        this.coeffscalar = sArr3;
    }

    public BCRainbowPublicKey(RainbowPublicKeySpec rainbowPublicKeySpec) {
        this(rainbowPublicKeySpec.getDocLength(), rainbowPublicKeySpec.getCoeffQuadratic(), rainbowPublicKeySpec.getCoeffSingular(), rainbowPublicKeySpec.getCoeffScalar());
    }

    public BCRainbowPublicKey(RainbowPublicKeyParameters rainbowPublicKeyParameters) {
        this(rainbowPublicKeyParameters.getDocLength(), rainbowPublicKeyParameters.getCoeffQuadratic(), rainbowPublicKeyParameters.getCoeffSingular(), rainbowPublicKeyParameters.getCoeffScalar());
    }

    public int getDocLength() {
        return this.docLength;
    }

    public short[][] getCoeffQuadratic() {
        return this.coeffquadratic;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [short[], short[][]] */
    public short[][] getCoeffSingular() {
        ?? r0 = new short[this.coeffsingular.length];
        for (int i = 0; i != this.coeffsingular.length; i++) {
            r0[i] = Arrays.clone(this.coeffsingular[i]);
        }
        return r0;
    }

    public short[] getCoeffScalar() {
        return Arrays.clone(this.coeffscalar);
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof BCRainbowPublicKey)) {
            return false;
        }
        BCRainbowPublicKey bCRainbowPublicKey = (BCRainbowPublicKey) obj;
        return this.docLength == bCRainbowPublicKey.getDocLength() && RainbowUtil.equals(this.coeffquadratic, bCRainbowPublicKey.getCoeffQuadratic()) && RainbowUtil.equals(this.coeffsingular, bCRainbowPublicKey.getCoeffSingular()) && RainbowUtil.equals(this.coeffscalar, bCRainbowPublicKey.getCoeffScalar());
    }

    public int hashCode() {
        return (((((this.docLength * 37) + Arrays.hashCode(this.coeffquadratic)) * 37) + Arrays.hashCode(this.coeffsingular)) * 37) + Arrays.hashCode(this.coeffscalar);
    }

    @Override // java.security.Key
    public final String getAlgorithm() {
        return "Rainbow";
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.rainbow, DERNull.INSTANCE), new RainbowPublicKey(this.docLength, this.coeffquadratic, this.coeffsingular, this.coeffscalar));
    }
}