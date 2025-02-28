package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/edec/BCXDHPrivateKey.class */
public class BCXDHPrivateKey implements XDHPrivateKey {
    static final long serialVersionUID = 1;
    transient AsymmetricKeyParameter xdhPrivateKey;
    private final boolean hasPublicKey;
    private final byte[] attributes;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCXDHPrivateKey(AsymmetricKeyParameter asymmetricKeyParameter) {
        this.hasPublicKey = true;
        this.attributes = null;
        this.xdhPrivateKey = asymmetricKeyParameter;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCXDHPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        this.hasPublicKey = privateKeyInfo.hasPublicKey();
        this.attributes = privateKeyInfo.getAttributes() != null ? privateKeyInfo.getAttributes().getEncoded() : null;
        populateFromPrivateKeyInfo(privateKeyInfo);
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) throws IOException {
        byte[] octets = privateKeyInfo.getPrivateKey().getOctets();
        if (octets.length != 32 && octets.length != 56) {
            octets = ASN1OctetString.getInstance(privateKeyInfo.parsePrivateKey()).getOctets();
        }
        if (EdECObjectIdentifiers.id_X448.equals((ASN1Primitive) privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
            this.xdhPrivateKey = new X448PrivateKeyParameters(octets);
        } else {
            this.xdhPrivateKey = new X25519PrivateKeyParameters(octets);
        }
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return this.xdhPrivateKey instanceof X448PrivateKeyParameters ? XDHParameterSpec.X448 : XDHParameterSpec.X25519;
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        try {
            ASN1Set aSN1Set = ASN1Set.getInstance(this.attributes);
            PrivateKeyInfo createPrivateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.xdhPrivateKey, aSN1Set);
            return (!this.hasPublicKey || Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? new PrivateKeyInfo(createPrivateKeyInfo.getPrivateKeyAlgorithm(), createPrivateKeyInfo.parsePrivateKey(), aSN1Set).getEncoded() : createPrivateKeyInfo.getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    @Override // org.bouncycastle.jcajce.interfaces.XDHPrivateKey
    public XDHPublicKey getPublicKey() {
        return this.xdhPrivateKey instanceof X448PrivateKeyParameters ? new BCXDHPublicKey(((X448PrivateKeyParameters) this.xdhPrivateKey).generatePublicKey()) : new BCXDHPublicKey(((X25519PrivateKeyParameters) this.xdhPrivateKey).generatePublicKey());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AsymmetricKeyParameter engineGetKeyParameters() {
        return this.xdhPrivateKey;
    }

    public String toString() {
        return Utils.keyToString("Private Key", getAlgorithm(), this.xdhPrivateKey instanceof X448PrivateKeyParameters ? ((X448PrivateKeyParameters) this.xdhPrivateKey).generatePublicKey() : ((X25519PrivateKeyParameters) this.xdhPrivateKey).generatePublicKey());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof PrivateKey) {
            return Arrays.areEqual(((PrivateKey) obj).getEncoded(), getEncoded());
        }
        return false;
    }

    public int hashCode() {
        return Arrays.hashCode(getEncoded());
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }
}