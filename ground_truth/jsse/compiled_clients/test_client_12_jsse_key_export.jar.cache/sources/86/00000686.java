package org.bouncycastle.jcajce.provider.asymmetric.p007dh;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.p003x9.DomainParameters;
import org.bouncycastle.asn1.p003x9.ValidationParams;
import org.bouncycastle.asn1.p003x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPrivateKeySpec;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

/* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPrivateKey */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/dh/BCDHPrivateKey.class */
public class BCDHPrivateKey implements DHPrivateKey, PKCS12BagAttributeCarrier {
    static final long serialVersionUID = 311058815616901812L;

    /* renamed from: x */
    private BigInteger f592x;
    private transient DHParameterSpec dhSpec;
    private transient PrivateKeyInfo info;
    private transient DHPrivateKeyParameters dhPrivateKey;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCDHPrivateKey() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKey dHPrivateKey) {
        this.f592x = dHPrivateKey.getX();
        this.dhSpec = dHPrivateKey.getParams();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKeySpec dHPrivateKeySpec) {
        this.f592x = dHPrivateKeySpec.getX();
        if (dHPrivateKeySpec instanceof DHExtendedPrivateKeySpec) {
            this.dhSpec = ((DHExtendedPrivateKeySpec) dHPrivateKeySpec).getParams();
        } else {
            this.dhSpec = new DHParameterSpec(dHPrivateKeySpec.getP(), dHPrivateKeySpec.getG());
        }
    }

    public BCDHPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(privateKeyInfo.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer aSN1Integer = (ASN1Integer) privateKeyInfo.parsePrivateKey();
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        this.info = privateKeyInfo;
        this.f592x = aSN1Integer.getValue();
        if (!algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement)) {
            if (!algorithm.equals((ASN1Primitive) X9ObjectIdentifiers.dhpublicnumber)) {
                throw new IllegalArgumentException("unknown algorithm type: " + algorithm);
            }
            DomainParameters domainParameters = DomainParameters.getInstance(aSN1Sequence);
            this.dhSpec = new DHDomainParameterSpec(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), domainParameters.getJ(), 0);
            this.dhPrivateKey = new DHPrivateKeyParameters(this.f592x, new DHParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), (DHValidationParameters) null));
            return;
        }
        DHParameter dHParameter = DHParameter.getInstance(aSN1Sequence);
        if (dHParameter.getL() != null) {
            this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG(), dHParameter.getL().intValue());
            this.dhPrivateKey = new DHPrivateKeyParameters(this.f592x, new DHParameters(dHParameter.getP(), dHParameter.getG(), null, dHParameter.getL().intValue()));
            return;
        }
        this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG());
        this.dhPrivateKey = new DHPrivateKeyParameters(this.f592x, new DHParameters(dHParameter.getP(), dHParameter.getG()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKeyParameters dHPrivateKeyParameters) {
        this.f592x = dHPrivateKeyParameters.getX();
        this.dhSpec = new DHDomainParameterSpec(dHPrivateKeyParameters.getParameters());
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return "DH";
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        PrivateKeyInfo privateKeyInfo;
        try {
            if (this.info != null) {
                return this.info.getEncoded(ASN1Encoding.DER);
            }
            if (!(this.dhSpec instanceof DHDomainParameterSpec) || ((DHDomainParameterSpec) this.dhSpec).getQ() == null) {
                privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL()).toASN1Primitive()), new ASN1Integer(getX()));
            } else {
                DHParameters domainParameters = ((DHDomainParameterSpec) this.dhSpec).getDomainParameters();
                DHValidationParameters validationParameters = domainParameters.getValidationParameters();
                ValidationParams validationParams = null;
                if (validationParameters != null) {
                    validationParams = new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter());
                }
                privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), validationParams).toASN1Primitive()), new ASN1Integer(getX()));
            }
            return privateKeyInfo.getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            return null;
        }
    }

    public String toString() {
        return DHUtil.privateKeyToString("DH", this.f592x, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG()));
    }

    @Override // javax.crypto.interfaces.DHKey
    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    @Override // javax.crypto.interfaces.DHPrivateKey
    public BigInteger getX() {
        return this.f592x;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DHPrivateKeyParameters engineGetKeyParameters() {
        return this.dhPrivateKey != null ? this.dhPrivateKey : this.dhSpec instanceof DHDomainParameterSpec ? new DHPrivateKeyParameters(this.f592x, ((DHDomainParameterSpec) this.dhSpec).getDomainParameters()) : new DHPrivateKeyParameters(this.f592x, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG(), null, this.dhSpec.getL()));
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHPrivateKey) {
            DHPrivateKey dHPrivateKey = (DHPrivateKey) obj;
            return getX().equals(dHPrivateKey.getX()) && getParams().getG().equals(dHPrivateKey.getParams().getG()) && getParams().getP().equals(dHPrivateKey.getParams().getP()) && getParams().getL() == dHPrivateKey.getParams().getL();
        }
        return false;
    }

    public int hashCode() {
        return ((getX().hashCode() ^ getParams().getG().hashCode()) ^ getParams().getP().hashCode()) ^ getParams().getL();
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public void setBagAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1Encodable aSN1Encodable) {
        this.attrCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Encodable);
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return this.attrCarrier.getBagAttribute(aSN1ObjectIdentifier);
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public Enumeration getBagAttributeKeys() {
        return this.attrCarrier.getBagAttributeKeys();
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        this.dhSpec = new DHParameterSpec((BigInteger) objectInputStream.readObject(), (BigInteger) objectInputStream.readObject(), objectInputStream.readInt());
        this.info = null;
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(this.dhSpec.getP());
        objectOutputStream.writeObject(this.dhSpec.getG());
        objectOutputStream.writeInt(this.dhSpec.getL());
    }
}