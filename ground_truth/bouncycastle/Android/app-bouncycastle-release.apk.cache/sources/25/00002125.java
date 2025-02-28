package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class BCMLDSAPrivateKey implements MLDSAPrivateKey {
    private static final long serialVersionUID = 1;
    private transient String algorithm;
    private transient ASN1Set attributes;
    private transient byte[] encoding;
    private transient MLDSAPrivateKeyParameters params;

    public BCMLDSAPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        init(privateKeyInfo);
    }

    public BCMLDSAPrivateKey(MLDSAPrivateKeyParameters mLDSAPrivateKeyParameters) {
        this.params = mLDSAPrivateKeyParameters;
        this.algorithm = Strings.toUpperCase(MLDSAParameterSpec.fromName(mLDSAPrivateKeyParameters.getParameters().getName()).getName());
    }

    private void init(PrivateKeyInfo privateKeyInfo) throws IOException {
        init((MLDSAPrivateKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo), privateKeyInfo.getAttributes());
    }

    private void init(MLDSAPrivateKeyParameters mLDSAPrivateKeyParameters, ASN1Set aSN1Set) {
        this.attributes = aSN1Set;
        this.params = mLDSAPrivateKeyParameters;
        this.algorithm = MLDSAParameterSpec.fromName(mLDSAPrivateKeyParameters.getParameters().getName()).getName().toUpperCase();
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        init(PrivateKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof BCMLDSAPrivateKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCMLDSAPrivateKey) obj).params.getEncoded());
        }
        return false;
    }

    @Override // java.security.Key
    public final String getAlgorithm() {
        return this.algorithm;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = KeyUtil.getEncodedPrivateKeyInfo(this.params, this.attributes);
        }
        return Arrays.clone(this.encoding);
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLDSAPrivateKeyParameters getKeyParams() {
        return this.params;
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLDSAKey
    public MLDSAParameterSpec getParameterSpec() {
        return MLDSAParameterSpec.fromName(this.params.getParameters().getName());
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey
    public MLDSAPublicKey getPublicKey() {
        return new BCMLDSAPublicKey(this.params.getPublicKeyParameters());
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getEncoded());
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        String lineSeparator = Strings.lineSeparator();
        byte[] publicKey = this.params.getPublicKey();
        sb.append(getAlgorithm()).append(" Private Key [").append(new Fingerprint(publicKey).toString()).append("]").append(lineSeparator).append("    public data: ").append(Hex.toHexString(publicKey)).append(lineSeparator);
        return sb.toString();
    }
}