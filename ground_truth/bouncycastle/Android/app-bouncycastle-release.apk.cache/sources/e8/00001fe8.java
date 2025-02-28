package org.bouncycastle.jcajce.provider.asymmetric.p013dh;

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
import org.bouncycastle.asn1.p009x9.DomainParameters;
import org.bouncycastle.asn1.p009x9.ValidationParams;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
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
/* loaded from: classes2.dex */
public class BCDHPrivateKey implements DHPrivateKey, PKCS12BagAttributeCarrier {
    static final long serialVersionUID = 311058815616901812L;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
    private transient DHPrivateKeyParameters dhPrivateKey;
    private transient DHParameterSpec dhSpec;
    private transient PrivateKeyInfo info;

    /* renamed from: x */
    private BigInteger f919x;

    protected BCDHPrivateKey() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKey dHPrivateKey) {
        this.f919x = dHPrivateKey.getX();
        this.dhSpec = dHPrivateKey.getParams();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKeySpec dHPrivateKeySpec) {
        this.f919x = dHPrivateKeySpec.getX();
        if (dHPrivateKeySpec instanceof DHExtendedPrivateKeySpec) {
            this.dhSpec = ((DHExtendedPrivateKeySpec) dHPrivateKeySpec).getParams();
        } else {
            this.dhSpec = new DHParameterSpec(dHPrivateKeySpec.getP(), dHPrivateKeySpec.getG());
        }
    }

    public BCDHPrivateKey(PrivateKeyInfo privateKeyInfo) throws IOException {
        DHPrivateKeyParameters dHPrivateKeyParameters;
        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(privateKeyInfo.getPrivateKeyAlgorithm().getParameters());
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        this.info = privateKeyInfo;
        this.f919x = ((ASN1Integer) privateKeyInfo.parsePrivateKey()).getValue();
        if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement)) {
            DHParameter dHParameter = DHParameter.getInstance(aSN1Sequence);
            if (dHParameter.getL() != null) {
                this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG(), dHParameter.getL().intValue());
                dHPrivateKeyParameters = new DHPrivateKeyParameters(this.f919x, new DHParameters(dHParameter.getP(), dHParameter.getG(), null, dHParameter.getL().intValue()));
            } else {
                this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG());
                dHPrivateKeyParameters = new DHPrivateKeyParameters(this.f919x, new DHParameters(dHParameter.getP(), dHParameter.getG()));
            }
        } else if (!algorithm.equals((ASN1Primitive) X9ObjectIdentifiers.dhpublicnumber)) {
            throw new IllegalArgumentException("unknown algorithm type: " + algorithm);
        } else {
            DomainParameters domainParameters = DomainParameters.getInstance(aSN1Sequence);
            this.dhSpec = new DHDomainParameterSpec(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), domainParameters.getJ(), 0);
            dHPrivateKeyParameters = new DHPrivateKeyParameters(this.f919x, new DHParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), (DHValidationParameters) null));
        }
        this.dhPrivateKey = dHPrivateKeyParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPrivateKey(DHPrivateKeyParameters dHPrivateKeyParameters) {
        this.f919x = dHPrivateKeyParameters.getX();
        this.dhSpec = new DHDomainParameterSpec(dHPrivateKeyParameters.getParameters());
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

    /* JADX INFO: Access modifiers changed from: package-private */
    public DHPrivateKeyParameters engineGetKeyParameters() {
        DHPrivateKeyParameters dHPrivateKeyParameters = this.dhPrivateKey;
        return dHPrivateKeyParameters != null ? dHPrivateKeyParameters : this.dhSpec instanceof DHDomainParameterSpec ? new DHPrivateKeyParameters(this.f919x, ((DHDomainParameterSpec) this.dhSpec).getDomainParameters()) : new DHPrivateKeyParameters(this.f919x, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG(), null, this.dhSpec.getL()));
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHPrivateKey) {
            DHPrivateKey dHPrivateKey = (DHPrivateKey) obj;
            return getX().equals(dHPrivateKey.getX()) && getParams().getG().equals(dHPrivateKey.getParams().getG()) && getParams().getP().equals(dHPrivateKey.getParams().getP()) && getParams().getL() == dHPrivateKey.getParams().getL();
        }
        return false;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return "DH";
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return this.attrCarrier.getBagAttribute(aSN1ObjectIdentifier);
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public Enumeration getBagAttributeKeys() {
        return this.attrCarrier.getBagAttributeKeys();
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        PrivateKeyInfo privateKeyInfo;
        try {
            PrivateKeyInfo privateKeyInfo2 = this.info;
            if (privateKeyInfo2 != null) {
                return privateKeyInfo2.getEncoded(ASN1Encoding.DER);
            }
            DHParameterSpec dHParameterSpec = this.dhSpec;
            if (!(dHParameterSpec instanceof DHDomainParameterSpec) || ((DHDomainParameterSpec) dHParameterSpec).getQ() == null) {
                privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL()).toASN1Primitive()), new ASN1Integer(getX()));
            } else {
                DHParameters domainParameters = ((DHDomainParameterSpec) this.dhSpec).getDomainParameters();
                DHValidationParameters validationParameters = domainParameters.getValidationParameters();
                privateKeyInfo = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), validationParameters != null ? new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter()) : null).toASN1Primitive()), new ASN1Integer(getX()));
            }
            return privateKeyInfo.getEncoded(ASN1Encoding.DER);
        } catch (Exception unused) {
            return null;
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "PKCS#8";
    }

    @Override // javax.crypto.interfaces.DHKey
    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    @Override // javax.crypto.interfaces.DHPrivateKey
    public BigInteger getX() {
        return this.f919x;
    }

    public int hashCode() {
        return ((getX().hashCode() ^ getParams().getG().hashCode()) ^ getParams().getP().hashCode()) ^ getParams().getL();
    }

    @Override // org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
    public void setBagAttribute(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1Encodable aSN1Encodable) {
        this.attrCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Encodable);
    }

    public String toString() {
        return DHUtil.privateKeyToString("DH", this.f919x, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG()));
    }
}