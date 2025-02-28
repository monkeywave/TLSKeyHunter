package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class BCMLDSAPublicKey implements MLDSAPublicKey {
    private static final long serialVersionUID = 1;
    private transient String algorithm;
    private transient MLDSAPublicKeyParameters params;

    public BCMLDSAPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        init(subjectPublicKeyInfo);
    }

    public BCMLDSAPublicKey(MLDSAPublicKeyParameters mLDSAPublicKeyParameters) {
        this.params = mLDSAPublicKeyParameters;
        this.algorithm = Strings.toUpperCase(MLDSAParameterSpec.fromName(mLDSAPublicKeyParameters.getParameters().getName()).getName());
    }

    private void init(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        MLDSAPublicKeyParameters mLDSAPublicKeyParameters = (MLDSAPublicKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
        this.params = mLDSAPublicKeyParameters;
        this.algorithm = Strings.toUpperCase(MLDSAParameterSpec.fromName(mLDSAPublicKeyParameters.getParameters().getName()).getName());
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        init(SubjectPublicKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof BCMLDSAPublicKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCMLDSAPublicKey) obj).params.getEncoded());
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
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.params).getEncoded();
        } catch (IOException unused) {
            return null;
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLDSAPublicKeyParameters getKeyParams() {
        return this.params;
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLDSAKey
    public MLDSAParameterSpec getParameterSpec() {
        return MLDSAParameterSpec.fromName(this.params.getParameters().getName());
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLDSAPublicKey
    public byte[] getPublicData() {
        return this.params.getEncoded();
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getEncoded());
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        String lineSeparator = Strings.lineSeparator();
        byte[] encoded = this.params.getEncoded();
        sb.append(getAlgorithm()).append(" Public Key [").append(new Fingerprint(encoded).toString()).append("]").append(lineSeparator).append("    public data: ").append(Hex.toHexString(encoded)).append(lineSeparator);
        return sb.toString();
    }
}