package org.bouncycastle.jcajce.provider.asymmetric.p013dh;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.p009x9.DomainParameters;
import org.bouncycastle.asn1.p009x9.ValidationParams;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec;

/* renamed from: org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey */
/* loaded from: classes2.dex */
public class BCDHPublicKey implements DHPublicKey {
    static final long serialVersionUID = -216691575254424324L;
    private transient DHPublicKeyParameters dhPublicKey;
    private transient DHParameterSpec dhSpec;
    private transient SubjectPublicKeyInfo info;

    /* renamed from: y */
    private BigInteger f920y;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPublicKey(BigInteger bigInteger, DHParameterSpec dHParameterSpec) {
        this.f920y = bigInteger;
        this.dhSpec = dHParameterSpec;
        this.dhPublicKey = dHParameterSpec instanceof DHDomainParameterSpec ? new DHPublicKeyParameters(bigInteger, ((DHDomainParameterSpec) dHParameterSpec).getDomainParameters()) : new DHPublicKeyParameters(bigInteger, new DHParameters(dHParameterSpec.getP(), dHParameterSpec.getG()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPublicKey(DHPublicKey dHPublicKey) {
        this.f920y = dHPublicKey.getY();
        DHParameterSpec params = dHPublicKey.getParams();
        this.dhSpec = params;
        if (params instanceof DHDomainParameterSpec) {
            this.dhPublicKey = new DHPublicKeyParameters(this.f920y, ((DHDomainParameterSpec) params).getDomainParameters());
        } else {
            this.dhPublicKey = new DHPublicKeyParameters(this.f920y, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG()));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPublicKey(DHPublicKeySpec dHPublicKeySpec) {
        this.f920y = dHPublicKeySpec.getY();
        this.dhSpec = dHPublicKeySpec instanceof DHExtendedPublicKeySpec ? ((DHExtendedPublicKeySpec) dHPublicKeySpec).getParams() : new DHParameterSpec(dHPublicKeySpec.getP(), dHPublicKeySpec.getG());
        DHParameterSpec dHParameterSpec = this.dhSpec;
        if (dHParameterSpec instanceof DHDomainParameterSpec) {
            this.dhPublicKey = new DHPublicKeyParameters(this.f920y, ((DHDomainParameterSpec) dHParameterSpec).getDomainParameters());
        } else {
            this.dhPublicKey = new DHPublicKeyParameters(this.f920y, new DHParameters(dHPublicKeySpec.getP(), dHPublicKeySpec.getG()));
        }
    }

    public BCDHPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        DHPublicKeyParameters dHPublicKeyParameters;
        this.info = subjectPublicKeyInfo;
        try {
            this.f920y = ((ASN1Integer) subjectPublicKeyInfo.parsePublicKey()).getValue();
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters());
            ASN1ObjectIdentifier algorithm = subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
            if (algorithm.equals((ASN1Primitive) PKCSObjectIdentifiers.dhKeyAgreement) || isPKCSParam(aSN1Sequence)) {
                DHParameter dHParameter = DHParameter.getInstance(aSN1Sequence);
                if (dHParameter.getL() != null) {
                    this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG(), dHParameter.getL().intValue());
                    dHPublicKeyParameters = new DHPublicKeyParameters(this.f920y, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG(), null, this.dhSpec.getL()));
                } else {
                    this.dhSpec = new DHParameterSpec(dHParameter.getP(), dHParameter.getG());
                    dHPublicKeyParameters = new DHPublicKeyParameters(this.f920y, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG()));
                }
                this.dhPublicKey = dHPublicKeyParameters;
            } else if (!algorithm.equals((ASN1Primitive) X9ObjectIdentifiers.dhpublicnumber)) {
                throw new IllegalArgumentException("unknown algorithm type: " + algorithm);
            } else {
                DomainParameters domainParameters = DomainParameters.getInstance(aSN1Sequence);
                ValidationParams validationParams = domainParameters.getValidationParams();
                if (validationParams != null) {
                    this.dhPublicKey = new DHPublicKeyParameters(this.f920y, new DHParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), new DHValidationParameters(validationParams.getSeed(), validationParams.getPgenCounter().intValue())));
                } else {
                    this.dhPublicKey = new DHPublicKeyParameters(this.f920y, new DHParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), (DHValidationParameters) null));
                }
                this.dhSpec = new DHDomainParameterSpec(this.dhPublicKey.getParameters());
            }
        } catch (IOException unused) {
            throw new IllegalArgumentException("invalid info structure in DH public key");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BCDHPublicKey(DHPublicKeyParameters dHPublicKeyParameters) {
        this.f920y = dHPublicKeyParameters.getY();
        this.dhSpec = new DHDomainParameterSpec(dHPublicKeyParameters.getParameters());
        this.dhPublicKey = dHPublicKeyParameters;
    }

    private boolean isPKCSParam(ASN1Sequence aSN1Sequence) {
        if (aSN1Sequence.size() == 2) {
            return true;
        }
        if (aSN1Sequence.size() > 3) {
            return false;
        }
        return ASN1Integer.getInstance(aSN1Sequence.getObjectAt(2)).getValue().compareTo(BigInteger.valueOf((long) ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).getValue().bitLength())) <= 0;
    }

    private void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        this.dhSpec = new DHParameterSpec((BigInteger) objectInputStream.readObject(), (BigInteger) objectInputStream.readObject(), objectInputStream.readInt());
        this.info = null;
    }

    private void writeObject(ObjectOutputStream objectOutputStream) throws IOException {
        objectOutputStream.defaultWriteObject();
        objectOutputStream.writeObject(this.dhSpec.getP());
        objectOutputStream.writeObject(this.dhSpec.getG());
        objectOutputStream.writeInt(this.dhSpec.getL());
    }

    public DHPublicKeyParameters engineGetKeyParameters() {
        return this.dhPublicKey;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHPublicKey) {
            DHPublicKey dHPublicKey = (DHPublicKey) obj;
            return getY().equals(dHPublicKey.getY()) && getParams().getG().equals(dHPublicKey.getParams().getG()) && getParams().getP().equals(dHPublicKey.getParams().getP()) && getParams().getL() == dHPublicKey.getParams().getL();
        }
        return false;
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return "DH";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        SubjectPublicKeyInfo subjectPublicKeyInfo = this.info;
        if (subjectPublicKeyInfo != null) {
            return KeyUtil.getEncodedSubjectPublicKeyInfo(subjectPublicKeyInfo);
        }
        DHParameterSpec dHParameterSpec = this.dhSpec;
        if (!(dHParameterSpec instanceof DHDomainParameterSpec) || ((DHDomainParameterSpec) dHParameterSpec).getQ() == null) {
            return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(this.dhSpec.getP(), this.dhSpec.getG(), this.dhSpec.getL()).toASN1Primitive()), new ASN1Integer(this.f920y));
        }
        DHParameters domainParameters = ((DHDomainParameterSpec) this.dhSpec).getDomainParameters();
        DHValidationParameters validationParameters = domainParameters.getValidationParameters();
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.dhpublicnumber, new DomainParameters(domainParameters.getP(), domainParameters.getG(), domainParameters.getQ(), domainParameters.getJ(), validationParameters != null ? new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter()) : null).toASN1Primitive()), new ASN1Integer(this.f920y));
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }

    @Override // javax.crypto.interfaces.DHKey
    public DHParameterSpec getParams() {
        return this.dhSpec;
    }

    @Override // javax.crypto.interfaces.DHPublicKey
    public BigInteger getY() {
        return this.f920y;
    }

    public int hashCode() {
        return ((getY().hashCode() ^ getParams().getG().hashCode()) ^ getParams().getP().hashCode()) ^ getParams().getL();
    }

    public String toString() {
        return DHUtil.publicKeyToString("DH", this.f920y, new DHParameters(this.dhSpec.getP(), this.dhSpec.getG()));
    }
}