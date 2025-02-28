package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class BCMLKEMPublicKey implements MLKEMPublicKey {
    private static final long serialVersionUID = 1;
    private transient String algorithm;
    private transient MLKEMPublicKeyParameters params;

    public BCMLKEMPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        init(subjectPublicKeyInfo);
    }

    public BCMLKEMPublicKey(MLKEMPublicKeyParameters mLKEMPublicKeyParameters) {
        init(mLKEMPublicKeyParameters);
    }

    private void init(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        MLKEMPublicKeyParameters mLKEMPublicKeyParameters = (MLKEMPublicKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
        this.params = mLKEMPublicKeyParameters;
        this.algorithm = Strings.toUpperCase(MLKEMParameterSpec.fromName(mLKEMPublicKeyParameters.getParameters().getName()).getName());
    }

    private void init(MLKEMPublicKeyParameters mLKEMPublicKeyParameters) {
        this.params = mLKEMPublicKeyParameters;
        this.algorithm = Strings.toUpperCase(MLKEMParameterSpec.fromName(mLKEMPublicKeyParameters.getParameters().getName()).getName());
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
        if (obj instanceof BCMLKEMPublicKey) {
            return Arrays.areEqual(getEncoded(), ((BCMLKEMPublicKey) obj).getEncoded());
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
    public MLKEMPublicKeyParameters getKeyParams() {
        return this.params;
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLKEMKey
    public MLKEMParameterSpec getParameterSpec() {
        return MLKEMParameterSpec.fromName(this.params.getParameters().getName());
    }

    @Override // org.bouncycastle.jcajce.interfaces.MLKEMPublicKey
    public byte[] getPublicData() {
        return this.params.getEncoded();
    }

    public int hashCode() {
        return Arrays.hashCode(getEncoded());
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        String lineSeparator = Strings.lineSeparator();
        byte[] encoded = this.params.getEncoded();
        sb.append(getAlgorithm()).append(" Public Key [").append(new Fingerprint(encoded).toString()).append("]").append(lineSeparator).append("    public data: ").append(Hex.toHexString(encoded)).append(lineSeparator);
        return sb.toString();
    }
}