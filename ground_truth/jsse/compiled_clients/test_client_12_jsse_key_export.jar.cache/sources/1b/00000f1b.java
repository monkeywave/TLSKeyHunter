package org.bouncycastle.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.ObjectDigestInfo;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/x509/AttributeCertificateHolder.class */
public class AttributeCertificateHolder implements CertSelector, Selector {
    final Holder holder;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AttributeCertificateHolder(ASN1Sequence aSN1Sequence) {
        this.holder = Holder.getInstance(aSN1Sequence);
    }

    public AttributeCertificateHolder(X509Principal x509Principal, BigInteger bigInteger) {
        this.holder = new Holder(new IssuerSerial(GeneralNames.getInstance(new DERSequence(new GeneralName(x509Principal))), new ASN1Integer(bigInteger)));
    }

    public AttributeCertificateHolder(X500Principal x500Principal, BigInteger bigInteger) {
        this(X509Util.convertPrincipal(x500Principal), bigInteger);
    }

    public AttributeCertificateHolder(X509Certificate x509Certificate) throws CertificateParsingException {
        try {
            this.holder = new Holder(new IssuerSerial(generateGeneralNames(PrincipalUtil.getIssuerX509Principal(x509Certificate)), new ASN1Integer(x509Certificate.getSerialNumber())));
        } catch (Exception e) {
            throw new CertificateParsingException(e.getMessage());
        }
    }

    public AttributeCertificateHolder(X509Principal x509Principal) {
        this.holder = new Holder(generateGeneralNames(x509Principal));
    }

    public AttributeCertificateHolder(X500Principal x500Principal) {
        this(X509Util.convertPrincipal(x500Principal));
    }

    public AttributeCertificateHolder(int i, String str, String str2, byte[] bArr) {
        this.holder = new Holder(new ObjectDigestInfo(i, new ASN1ObjectIdentifier(str2), new AlgorithmIdentifier(new ASN1ObjectIdentifier(str)), Arrays.clone(bArr)));
    }

    public int getDigestedObjectType() {
        if (this.holder.getObjectDigestInfo() != null) {
            return this.holder.getObjectDigestInfo().getDigestedObjectType().intValueExact();
        }
        return -1;
    }

    public String getDigestAlgorithm() {
        if (this.holder.getObjectDigestInfo() != null) {
            return this.holder.getObjectDigestInfo().getDigestAlgorithm().getAlgorithm().getId();
        }
        return null;
    }

    public byte[] getObjectDigest() {
        if (this.holder.getObjectDigestInfo() != null) {
            return this.holder.getObjectDigestInfo().getObjectDigest().getBytes();
        }
        return null;
    }

    public String getOtherObjectTypeID() {
        if (this.holder.getObjectDigestInfo() != null) {
            this.holder.getObjectDigestInfo().getOtherObjectTypeID().getId();
            return null;
        }
        return null;
    }

    private GeneralNames generateGeneralNames(X509Principal x509Principal) {
        return GeneralNames.getInstance(new DERSequence(new GeneralName(x509Principal)));
    }

    private boolean matchesDN(X509Principal x509Principal, GeneralNames generalNames) {
        GeneralName[] names = generalNames.getNames();
        for (int i = 0; i != names.length; i++) {
            GeneralName generalName = names[i];
            if (generalName.getTagNo() == 4) {
                try {
                    if (new X509Principal(generalName.getName().toASN1Primitive().getEncoded()).equals(x509Principal)) {
                        return true;
                    }
                } catch (IOException e) {
                }
            }
        }
        return false;
    }

    private Object[] getNames(GeneralName[] generalNameArr) {
        ArrayList arrayList = new ArrayList(generalNameArr.length);
        for (int i = 0; i != generalNameArr.length; i++) {
            if (generalNameArr[i].getTagNo() == 4) {
                try {
                    arrayList.add(new X500Principal(generalNameArr[i].getName().toASN1Primitive().getEncoded()));
                } catch (IOException e) {
                    throw new RuntimeException("badly formed Name object");
                }
            }
        }
        return arrayList.toArray(new Object[arrayList.size()]);
    }

    private Principal[] getPrincipals(GeneralNames generalNames) {
        Object[] names = getNames(generalNames.getNames());
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i != names.length; i++) {
            if (names[i] instanceof Principal) {
                arrayList.add(names[i]);
            }
        }
        return (Principal[]) arrayList.toArray(new Principal[arrayList.size()]);
    }

    public Principal[] getEntityNames() {
        if (this.holder.getEntityName() != null) {
            return getPrincipals(this.holder.getEntityName());
        }
        return null;
    }

    public Principal[] getIssuer() {
        if (this.holder.getBaseCertificateID() != null) {
            return getPrincipals(this.holder.getBaseCertificateID().getIssuer());
        }
        return null;
    }

    public BigInteger getSerialNumber() {
        if (this.holder.getBaseCertificateID() != null) {
            return this.holder.getBaseCertificateID().getSerial().getValue();
        }
        return null;
    }

    @Override // java.security.cert.CertSelector, org.bouncycastle.util.Selector
    public Object clone() {
        return new AttributeCertificateHolder((ASN1Sequence) this.holder.toASN1Primitive());
    }

    @Override // java.security.cert.CertSelector
    public boolean match(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            try {
                if (this.holder.getBaseCertificateID() != null) {
                    return this.holder.getBaseCertificateID().getSerial().hasValue(x509Certificate.getSerialNumber()) && matchesDN(PrincipalUtil.getIssuerX509Principal(x509Certificate), this.holder.getBaseCertificateID().getIssuer());
                } else if (this.holder.getEntityName() == null || !matchesDN(PrincipalUtil.getSubjectX509Principal(x509Certificate), this.holder.getEntityName())) {
                    if (this.holder.getObjectDigestInfo() != null) {
                        try {
                            MessageDigest messageDigest = MessageDigest.getInstance(getDigestAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
                            switch (getDigestedObjectType()) {
                                case 0:
                                    messageDigest.update(certificate.getPublicKey().getEncoded());
                                    break;
                                case 1:
                                    messageDigest.update(certificate.getEncoded());
                                    break;
                            }
                            return !Arrays.areEqual(messageDigest.digest(), getObjectDigest()) ? false : false;
                        } catch (Exception e) {
                            return false;
                        }
                    }
                    return false;
                } else {
                    return true;
                }
            } catch (CertificateEncodingException e2) {
                return false;
            }
        }
        return false;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof AttributeCertificateHolder) {
            return this.holder.equals(((AttributeCertificateHolder) obj).holder);
        }
        return false;
    }

    public int hashCode() {
        return this.holder.hashCode();
    }

    @Override // org.bouncycastle.util.Selector
    public boolean match(Object obj) {
        if (obj instanceof X509Certificate) {
            return match((Certificate) obj);
        }
        return false;
    }
}