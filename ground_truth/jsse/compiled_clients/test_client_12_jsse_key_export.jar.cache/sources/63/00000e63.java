package org.bouncycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NHPublicKey;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/provider/newhope/BCNHPublicKey.class */
public class BCNHPublicKey implements NHPublicKey {
    private static final long serialVersionUID = 1;
    private transient NHPublicKeyParameters params;

    public BCNHPublicKey(NHPublicKeyParameters nHPublicKeyParameters) {
        this.params = nHPublicKeyParameters;
    }

    public BCNHPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        init(subjectPublicKeyInfo);
    }

    private void init(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException {
        this.params = (NHPublicKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof BCNHPublicKey)) {
            return false;
        }
        return Arrays.areEqual(this.params.getPubData(), ((BCNHPublicKey) obj).params.getPubData());
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getPubData());
    }

    @Override // java.security.Key
    public final String getAlgorithm() {
        return "NH";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        try {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.params).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    @Override // org.bouncycastle.pqc.jcajce.interfaces.NHPublicKey
    public byte[] getPublicData() {
        return this.params.getPubData();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        init(SubjectPublicKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }
}