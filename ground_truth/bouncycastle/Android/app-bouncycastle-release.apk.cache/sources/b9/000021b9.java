package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public class BCSLHDSAPublicKey implements SLHDSAPublicKey {
    private static final long serialVersionUID = 1;
    private transient SLHDSAPublicKeyParameters params;

    public BCSLHDSAPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        init(subjectPublicKeyInfo);
    }

    public BCSLHDSAPublicKey(SLHDSAPublicKeyParameters sLHDSAPublicKeyParameters) {
        this.params = sLHDSAPublicKeyParameters;
    }

    private void init(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        this.params = (SLHDSAPublicKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
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
        if (obj instanceof BCSLHDSAPublicKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCSLHDSAPublicKey) obj).params.getEncoded());
        }
        return false;
    }

    @Override // java.security.Key
    public final String getAlgorithm() {
        return "SLH-DSA-" + Strings.toUpperCase(this.params.getParameters().getName());
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
    public SLHDSAPublicKeyParameters getKeyParams() {
        return this.params;
    }

    @Override // org.bouncycastle.jcajce.interfaces.SLHDSAKey
    public SLHDSAParameterSpec getParameterSpec() {
        return SLHDSAParameterSpec.fromName(this.params.getParameters().getName());
    }

    @Override // org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey
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