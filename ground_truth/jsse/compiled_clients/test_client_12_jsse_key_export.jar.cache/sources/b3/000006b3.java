package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.p003x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dsa/BCDSAPublicKey.class */
public class BCDSAPublicKey implements DSAPublicKey {
    private static final long serialVersionUID = 1752452449903495175L;
    private static BigInteger ZERO = BigInteger.valueOf(0);

    /* renamed from: y */
    private BigInteger f598y;
    private transient DSAPublicKeyParameters lwKeyParams;
    private transient DSAParams dsaSpec;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDSAPublicKey(DSAPublicKeySpec dSAPublicKeySpec) {
        this.f598y = dSAPublicKeySpec.getY();
        this.dsaSpec = new DSAParameterSpec(dSAPublicKeySpec.getP(), dSAPublicKeySpec.getQ(), dSAPublicKeySpec.getG());
        this.lwKeyParams = new DSAPublicKeyParameters(this.f598y, DSAUtil.toDSAParameters(this.dsaSpec));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDSAPublicKey(DSAPublicKey dSAPublicKey) {
        this.f598y = dSAPublicKey.getY();
        this.dsaSpec = dSAPublicKey.getParams();
        this.lwKeyParams = new DSAPublicKeyParameters(this.f598y, DSAUtil.toDSAParameters(this.dsaSpec));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDSAPublicKey(DSAPublicKeyParameters dSAPublicKeyParameters) {
        this.f598y = dSAPublicKeyParameters.getY();
        if (dSAPublicKeyParameters.getParameters() != null) {
            this.dsaSpec = new DSAParameterSpec(dSAPublicKeyParameters.getParameters().getP(), dSAPublicKeyParameters.getParameters().getQ(), dSAPublicKeyParameters.getParameters().getG());
        } else {
            this.dsaSpec = null;
        }
        this.lwKeyParams = dSAPublicKeyParameters;
    }

    public BCDSAPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        try {
            this.f598y = ((ASN1Integer) subjectPublicKeyInfo.parsePublicKey()).getValue();
            if (isNotNull(subjectPublicKeyInfo.getAlgorithm().getParameters())) {
                DSAParameter dSAParameter = DSAParameter.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters());
                this.dsaSpec = new DSAParameterSpec(dSAParameter.getP(), dSAParameter.getQ(), dSAParameter.getG());
            } else {
                this.dsaSpec = null;
            }
            this.lwKeyParams = new DSAPublicKeyParameters(this.f598y, DSAUtil.toDSAParameters(this.dsaSpec));
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }
    }

    private boolean isNotNull(ASN1Encodable aSN1Encodable) {
        return (aSN1Encodable == null || DERNull.INSTANCE.equals(aSN1Encodable.toASN1Primitive())) ? false : true;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return "DSA";
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DSAPublicKeyParameters engineGetKeyParameters() {
        return this.lwKeyParams;
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        return this.dsaSpec == null ? KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new ASN1Integer(this.f598y)) : KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(this.dsaSpec.getP(), this.dsaSpec.getQ(), this.dsaSpec.getG()).toASN1Primitive()), new ASN1Integer(this.f598y));
    }

    @Override // java.security.interfaces.DSAKey
    public DSAParams getParams() {
        return this.dsaSpec;
    }

    @Override // java.security.interfaces.DSAPublicKey
    public BigInteger getY() {
        return this.f598y;
    }

    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        String lineSeparator = Strings.lineSeparator();
        stringBuffer.append("DSA Public Key [").append(DSAUtil.generateKeyFingerprint(this.f598y, getParams())).append("]").append(lineSeparator);
        stringBuffer.append("            Y: ").append(getY().toString(16)).append(lineSeparator);
        return stringBuffer.toString();
    }

    public int hashCode() {
        return this.dsaSpec != null ? ((getY().hashCode() ^ getParams().getG().hashCode()) ^ getParams().getP().hashCode()) ^ getParams().getQ().hashCode() : getY().hashCode();
    }

    public boolean equals(Object obj) {
        if (obj instanceof DSAPublicKey) {
            DSAPublicKey dSAPublicKey = (DSAPublicKey) obj;
            return this.dsaSpec != null ? getY().equals(dSAPublicKey.getY()) && dSAPublicKey.getParams() != null && getParams().getG().equals(dSAPublicKey.getParams().getG()) && getParams().getP().equals(dSAPublicKey.getParams().getP()) && getParams().getQ().equals(dSAPublicKey.getParams().getQ()) : getY().equals(dSAPublicKey.getY()) && dSAPublicKey.getParams() == null;
        }
        return false;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        BigInteger bigInteger = (BigInteger) objectInputStream.readObject();
        if (bigInteger.equals(ZERO)) {
            this.dsaSpec = null;
        } else {
            this.dsaSpec = new DSAParameterSpec(bigInteger, (BigInteger) objectInputStream.readObject(), (BigInteger) objectInputStream.readObject());
        }
        this.lwKeyParams = new DSAPublicKeyParameters(this.f598y, DSAUtil.toDSAParameters(this.dsaSpec));
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        if (this.dsaSpec == null) {
            objectOutputStream.writeObject(ZERO);
            return;
        }
        objectOutputStream.writeObject(this.dsaSpec.getP());
        objectOutputStream.writeObject(this.dsaSpec.getQ());
        objectOutputStream.writeObject(this.dsaSpec.getG());
    }
}