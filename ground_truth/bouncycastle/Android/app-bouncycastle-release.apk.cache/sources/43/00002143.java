package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class BCMLKEMPrivateKey implements MLKEMPrivateKey {
    private static final long serialVersionUID = 1;
    private transient String algorithm;
    private transient ASN1Set attributes;
    private transient MLKEMPrivateKeyParameters params;

    public BCMLKEMPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        init(privateKeyInfo);
    }

    public BCMLKEMPrivateKey(MLKEMPrivateKeyParameters mLKEMPrivateKeyParameters) {
        this.params = mLKEMPrivateKeyParameters;
        this.algorithm = Strings.toUpperCase(mLKEMPrivateKeyParameters.getParameters().getName());
    }

    private void init(PrivateKeyInfo privateKeyInfo) throws IOException {
        this.attributes = privateKeyInfo.getAttributes();
        MLKEMPrivateKeyParameters mLKEMPrivateKeyParameters = (MLKEMPrivateKeyParameters) PrivateKeyFactory.createKey(privateKeyInfo);
        this.params = mLKEMPrivateKeyParameters;
        this.algorithm = Strings.toUpperCase(MLKEMParameterSpec.fromName(mLKEMPrivateKeyParameters.getParameters().getName()).getName());
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
        if (obj instanceof BCMLKEMPrivateKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCMLKEMPrivateKey) obj).params.getEncoded());
        }
        return false;
    }

    @Override // java.security.Key
    public final String getAlgorithm() {
        return this.algorithm;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        try {
            return PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes).getEncoded();
        } catch (IOException unused) {
            return null;
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLKEMPrivateKeyParameters getKeyParams() {
        return this.params;
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLKEMKey
    public MLKEMParameterSpec getParameterSpec() {
        return MLKEMParameterSpec.fromName(this.params.getParameters().getName());
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey
    public MLKEMPublicKey getPublicKey() {
        return new BCMLKEMPublicKey(this.params.getPublicKeyParameters());
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