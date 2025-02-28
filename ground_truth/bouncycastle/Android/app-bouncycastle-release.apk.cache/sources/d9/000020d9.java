package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* loaded from: classes2.dex */
public class BCEdDSAPrivateKey implements EdDSAPrivateKey {
    static final long serialVersionUID = 1;
    private final byte[] attributes;
    transient AsymmetricKeyParameter eddsaPrivateKey;
    transient AsymmetricKeyParameter eddsaPublicKey;
    private final boolean hasPublicKey;
    transient int hashCode;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCEdDSAPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        this.hasPublicKey = privateKeyInfo.hasPublicKey();
        this.attributes = privateKeyInfo.getAttributes() != null ? privateKeyInfo.getAttributes().getEncoded() : null;
        populateFromPrivateKeyInfo(privateKeyInfo);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCEdDSAPrivateKey(AsymmetricKeyParameter asymmetricKeyParameter) {
        this.hasPublicKey = true;
        this.attributes = null;
        this.eddsaPrivateKey = asymmetricKeyParameter;
        this.eddsaPublicKey = asymmetricKeyParameter instanceof Ed448PrivateKeyParameters ? ((Ed448PrivateKeyParameters) asymmetricKeyParameter).generatePublicKey() : ((Ed25519PrivateKeyParameters) asymmetricKeyParameter).generatePublicKey();
        this.hashCode = calculateHashCode();
    }

    private int calculateHashCode() {
        AsymmetricKeyParameter asymmetricKeyParameter = this.eddsaPublicKey;
        return (getAlgorithm().hashCode() * 31) + Arrays.hashCode(asymmetricKeyParameter instanceof Ed448PublicKeyParameters ? ((Ed448PublicKeyParameters) asymmetricKeyParameter).getEncoded() : ((Ed25519PublicKeyParameters) asymmetricKeyParameter).getEncoded());
    }

    private PrivateKeyInfo getPrivateKeyInfo() {
        try {
            ASN1Set aSN1Set = ASN1Set.getInstance(this.attributes);
            PrivateKeyInfo createPrivateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.eddsaPrivateKey, aSN1Set);
            return (!this.hasPublicKey || Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? new PrivateKeyInfo(createPrivateKeyInfo.getPrivateKeyAlgorithm(), createPrivateKeyInfo.parsePrivateKey(), aSN1Set) : createPrivateKeyInfo;
        } catch (IOException unused) {
            return null;
        }
    }

    private void populateFromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) throws IOException {
        AsymmetricKeyParameter generatePublicKey;
        byte[] octets = ASN1OctetString.getInstance(privateKeyInfo.parsePrivateKey()).getOctets();
        if (EdECObjectIdentifiers.id_Ed448.equals((ASN1Primitive) privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
            Ed448PrivateKeyParameters ed448PrivateKeyParameters = new Ed448PrivateKeyParameters(octets);
            this.eddsaPrivateKey = ed448PrivateKeyParameters;
            generatePublicKey = ed448PrivateKeyParameters.generatePublicKey();
        } else {
            Ed25519PrivateKeyParameters ed25519PrivateKeyParameters = new Ed25519PrivateKeyParameters(octets);
            this.eddsaPrivateKey = ed25519PrivateKeyParameters;
            generatePublicKey = ed25519PrivateKeyParameters.generatePublicKey();
        }
        this.eddsaPublicKey = generatePublicKey;
        this.hashCode = calculateHashCode();
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AsymmetricKeyParameter engineGetKeyParameters() {
        return this.eddsaPrivateKey;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof PrivateKey) {
            PrivateKey privateKey = (PrivateKey) obj;
            PrivateKeyInfo privateKeyInfo = getPrivateKeyInfo();
            PrivateKeyInfo privateKeyInfo2 = privateKey instanceof BCEdDSAPrivateKey ? ((BCEdDSAPrivateKey) privateKey).getPrivateKeyInfo() : PrivateKeyInfo.getInstance(privateKey.getEncoded());
            if (privateKeyInfo != null && privateKeyInfo2 != null) {
                try {
                    return Arrays.constantTimeAreEqual(privateKeyInfo.getPrivateKey().getEncoded(), privateKeyInfo2.getPrivateKey().getEncoded()) & Arrays.constantTimeAreEqual(privateKeyInfo.getPrivateKeyAlgorithm().getEncoded(), privateKeyInfo2.getPrivateKeyAlgorithm().getEncoded());
                } catch (IOException unused) {
                }
            }
            return false;
        }
        return false;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return Properties.isOverrideSet(Properties.EMULATE_ORACLE) ? "EdDSA" : this.eddsaPrivateKey instanceof Ed448PrivateKeyParameters ? EdDSAParameterSpec.Ed448 : EdDSAParameterSpec.Ed25519;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        try {
            PrivateKeyInfo privateKeyInfo = getPrivateKeyInfo();
            if (privateKeyInfo == null) {
                return null;
            }
            return privateKeyInfo.getEncoded();
        } catch (IOException unused) {
            return null;
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    @Override // org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey
    public EdDSAPublicKey getPublicKey() {
        return new BCEdDSAPublicKey(this.eddsaPublicKey);
    }

    public int hashCode() {
        return this.hashCode;
    }

    public String toString() {
        return Utils.keyToString("Private Key", getAlgorithm(), this.eddsaPublicKey);
    }
}