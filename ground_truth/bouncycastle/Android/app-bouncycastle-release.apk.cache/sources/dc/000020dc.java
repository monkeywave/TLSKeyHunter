package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* loaded from: classes2.dex */
public class BCXDHPublicKey implements XDHPublicKey {
    static final long serialVersionUID = 1;
    transient AsymmetricKeyParameter xdhPublicKey;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCXDHPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        populateFromPubKeyInfo(subjectPublicKeyInfo);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCXDHPublicKey(AsymmetricKeyParameter asymmetricKeyParameter) {
        this.xdhPublicKey = asymmetricKeyParameter;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCXDHPublicKey(byte[] bArr, byte[] bArr2) throws InvalidKeySpecException {
        AsymmetricKeyParameter x25519PublicKeyParameters;
        int length = bArr.length;
        if (!Utils.isValidPrefix(bArr, bArr2)) {
            throw new InvalidKeySpecException("raw key data not recognised");
        }
        if (bArr2.length - length == 56) {
            x25519PublicKeyParameters = new X448PublicKeyParameters(bArr2, length);
        } else if (bArr2.length - length != 32) {
            throw new InvalidKeySpecException("raw key data not recognised");
        } else {
            x25519PublicKeyParameters = new X25519PublicKeyParameters(bArr2, length);
        }
        this.xdhPublicKey = x25519PublicKeyParameters;
    }

    private void populateFromPubKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        byte[] octets = subjectPublicKeyInfo.getPublicKeyData().getOctets();
        this.xdhPublicKey = EdECObjectIdentifiers.id_X448.equals((ASN1Primitive) subjectPublicKeyInfo.getAlgorithm().getAlgorithm()) ? new X448PublicKeyParameters(octets) : new X25519PublicKeyParameters(octets);
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance((byte[]) objectInputStream.readObject()));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(getEncoded());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AsymmetricKeyParameter engineGetKeyParameters() {
        return this.xdhPublicKey;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof PublicKey) {
            return Arrays.areEqual(((PublicKey) obj).getEncoded(), getEncoded());
        }
        return false;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return Properties.isOverrideSet(Properties.EMULATE_ORACLE) ? "XDH" : this.xdhPublicKey instanceof X448PublicKeyParameters ? XDHParameterSpec.X448 : XDHParameterSpec.X25519;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        if (this.xdhPublicKey instanceof X448PublicKeyParameters) {
            byte[] bArr = new byte[KeyFactorySpi.x448Prefix.length + 56];
            System.arraycopy(KeyFactorySpi.x448Prefix, 0, bArr, 0, KeyFactorySpi.x448Prefix.length);
            ((X448PublicKeyParameters) this.xdhPublicKey).encode(bArr, KeyFactorySpi.x448Prefix.length);
            return bArr;
        }
        byte[] bArr2 = new byte[KeyFactorySpi.x25519Prefix.length + 32];
        System.arraycopy(KeyFactorySpi.x25519Prefix, 0, bArr2, 0, KeyFactorySpi.x25519Prefix.length);
        ((X25519PublicKeyParameters) this.xdhPublicKey).encode(bArr2, KeyFactorySpi.x25519Prefix.length);
        return bArr2;
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    @Override // org.bouncycastle.jcajce.interfaces.XDHPublicKey
    public BigInteger getU() {
        byte[] uEncoding = getUEncoding();
        Arrays.reverseInPlace(uEncoding);
        return new BigInteger(1, uEncoding);
    }

    @Override // org.bouncycastle.jcajce.interfaces.XDHPublicKey
    public byte[] getUEncoding() {
        AsymmetricKeyParameter asymmetricKeyParameter = this.xdhPublicKey;
        return asymmetricKeyParameter instanceof X448PublicKeyParameters ? ((X448PublicKeyParameters) asymmetricKeyParameter).getEncoded() : ((X25519PublicKeyParameters) asymmetricKeyParameter).getEncoded();
    }

    public int hashCode() {
        return Arrays.hashCode(getEncoded());
    }

    public String toString() {
        return Utils.keyToString("Public Key", getAlgorithm(), this.xdhPublicKey);
    }
}