package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class BCRSAPublicKey implements RSAPublicKey {
    static final AlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    static final long serialVersionUID = 2675817738516720772L;
    private transient AlgorithmIdentifier algorithmIdentifier;
    private BigInteger modulus;
    private BigInteger publicExponent;
    private transient RSAKeyParameters rsaPublicKey;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCRSAPublicKey(RSAPublicKey rSAPublicKey) {
        this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        this.modulus = rSAPublicKey.getModulus();
        this.publicExponent = rSAPublicKey.getPublicExponent();
        this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCRSAPublicKey(RSAPublicKeySpec rSAPublicKeySpec) {
        this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        this.modulus = rSAPublicKeySpec.getModulus();
        this.publicExponent = rSAPublicKeySpec.getPublicExponent();
        this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCRSAPublicKey(AlgorithmIdentifier algorithmIdentifier, RSAKeyParameters rSAKeyParameters) {
        this.algorithmIdentifier = algorithmIdentifier;
        this.modulus = rSAKeyParameters.getModulus();
        this.publicExponent = rSAKeyParameters.getExponent();
        this.rsaPublicKey = rSAKeyParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCRSAPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        populateFromPublicKeyInfo(subjectPublicKeyInfo);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCRSAPublicKey(RSAKeyParameters rSAKeyParameters) {
        this(DEFAULT_ALGORITHM_IDENTIFIER, rSAKeyParameters);
    }

    private void populateFromPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        try {
            org.bouncycastle.asn1.pkcs.RSAPublicKey rSAPublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());
            this.algorithmIdentifier = subjectPublicKeyInfo.getAlgorithm();
            this.modulus = rSAPublicKey.getModulus();
            this.publicExponent = rSAPublicKey.getPublicExponent();
            this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
        } catch (IOException unused) {
            throw new IllegalArgumentException("invalid info structure in RSA public key");
        }
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        try {
            this.algorithmIdentifier = AlgorithmIdentifier.getInstance(objectInputStream.readObject());
        } catch (Exception unused) {
            this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        }
        this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        if (this.algorithmIdentifier.equals(DEFAULT_ALGORITHM_IDENTIFIER)) {
            return;
        }
        objectOutputStream.writeObject(this.algorithmIdentifier.getEncoded());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RSAKeyParameters engineGetKeyParameters() {
        return this.rsaPublicKey;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof RSAPublicKey) {
            RSAPublicKey rSAPublicKey = (RSAPublicKey) obj;
            return getModulus().equals(rSAPublicKey.getModulus()) && getPublicExponent().equals(rSAPublicKey.getPublicExponent());
        }
        return false;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return this.algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) PKCSObjectIdentifiers.id_RSASSA_PSS) ? "RSASSA-PSS" : "RSA";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(this.algorithmIdentifier, new org.bouncycastle.asn1.pkcs.RSAPublicKey(getModulus(), getPublicExponent()));
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    @Override // java.security.interfaces.RSAKey
    public BigInteger getModulus() {
        return this.modulus;
    }

    @Override // java.security.interfaces.RSAPublicKey
    public BigInteger getPublicExponent() {
        return this.publicExponent;
    }

    public int hashCode() {
        return getModulus().hashCode() ^ getPublicExponent().hashCode();
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer("RSA Public Key [");
        String lineSeparator = Strings.lineSeparator();
        stringBuffer.append(RSAUtil.generateKeyFingerprint(getModulus())).append("],[").append(RSAUtil.generateExponentFingerprint(getPublicExponent())).append("]").append(lineSeparator);
        stringBuffer.append("        modulus: ").append(getModulus().toString(16)).append(lineSeparator);
        stringBuffer.append("public exponent: ").append(getPublicExponent().toString(16)).append(lineSeparator);
        return stringBuffer.toString();
    }
}