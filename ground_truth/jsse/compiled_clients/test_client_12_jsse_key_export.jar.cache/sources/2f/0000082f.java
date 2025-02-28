package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.p006io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/asymmetric/x509/X509CertificateImpl.class */
abstract class X509CertificateImpl extends X509Certificate implements BCX509Certificate {
    protected JcaJceHelper bcHelper;

    /* renamed from: c */
    protected Certificate f611c;
    protected BasicConstraints basicConstraints;
    protected boolean[] keyUsage;
    protected String sigAlgName;
    protected byte[] sigAlgParams;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509CertificateImpl(JcaJceHelper jcaJceHelper, Certificate certificate, BasicConstraints basicConstraints, boolean[] zArr, String str, byte[] bArr) {
        this.bcHelper = jcaJceHelper;
        this.f611c = certificate;
        this.basicConstraints = basicConstraints;
        this.keyUsage = zArr;
        this.sigAlgName = str;
        this.sigAlgParams = bArr;
    }

    @Override // org.bouncycastle.jcajce.interfaces.BCX509Certificate
    public X500Name getIssuerX500Name() {
        return this.f611c.getIssuer();
    }

    @Override // org.bouncycastle.jcajce.interfaces.BCX509Certificate
    public TBSCertificate getTBSCertificateNative() {
        return this.f611c.getTBSCertificate();
    }

    @Override // org.bouncycastle.jcajce.interfaces.BCX509Certificate
    public X500Name getSubjectX500Name() {
        return this.f611c.getSubject();
    }

    @Override // java.security.cert.X509Certificate
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        checkValidity(new Date());
    }

    @Override // java.security.cert.X509Certificate
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (date.getTime() > getNotAfter().getTime()) {
            throw new CertificateExpiredException("certificate expired on " + this.f611c.getEndDate().getTime());
        }
        if (date.getTime() < getNotBefore().getTime()) {
            throw new CertificateNotYetValidException("certificate not valid till " + this.f611c.getStartDate().getTime());
        }
    }

    @Override // java.security.cert.X509Certificate
    public int getVersion() {
        return this.f611c.getVersionNumber();
    }

    @Override // java.security.cert.X509Certificate
    public BigInteger getSerialNumber() {
        return this.f611c.getSerialNumber().getValue();
    }

    @Override // java.security.cert.X509Certificate
    public Principal getIssuerDN() {
        return new X509Principal(this.f611c.getIssuer());
    }

    @Override // java.security.cert.X509Certificate
    public X500Principal getIssuerX500Principal() {
        try {
            return new X500Principal(this.f611c.getIssuer().getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    @Override // java.security.cert.X509Certificate
    public Principal getSubjectDN() {
        return new X509Principal(this.f611c.getSubject());
    }

    @Override // java.security.cert.X509Certificate
    public X500Principal getSubjectX500Principal() {
        try {
            return new X500Principal(this.f611c.getSubject().getEncoded(ASN1Encoding.DER));
        } catch (IOException e) {
            throw new IllegalStateException("can't encode subject DN");
        }
    }

    @Override // java.security.cert.X509Certificate
    public Date getNotBefore() {
        return this.f611c.getStartDate().getDate();
    }

    @Override // java.security.cert.X509Certificate
    public Date getNotAfter() {
        return this.f611c.getEndDate().getDate();
    }

    @Override // java.security.cert.X509Certificate
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        try {
            return this.f611c.getTBSCertificate().getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    @Override // java.security.cert.X509Certificate
    public byte[] getSignature() {
        return this.f611c.getSignature().getOctets();
    }

    @Override // java.security.cert.X509Certificate
    public String getSigAlgName() {
        return this.sigAlgName;
    }

    @Override // java.security.cert.X509Certificate
    public String getSigAlgOID() {
        return this.f611c.getSignatureAlgorithm().getAlgorithm().getId();
    }

    @Override // java.security.cert.X509Certificate
    public byte[] getSigAlgParams() {
        return Arrays.clone(this.sigAlgParams);
    }

    @Override // java.security.cert.X509Certificate
    public boolean[] getIssuerUniqueID() {
        ASN1BitString issuerUniqueId = this.f611c.getTBSCertificate().getIssuerUniqueId();
        if (issuerUniqueId != null) {
            byte[] bytes = issuerUniqueId.getBytes();
            boolean[] zArr = new boolean[(bytes.length * 8) - issuerUniqueId.getPadBits()];
            for (int i = 0; i != zArr.length; i++) {
                zArr[i] = (bytes[i / 8] & (128 >>> (i % 8))) != 0;
            }
            return zArr;
        }
        return null;
    }

    @Override // java.security.cert.X509Certificate
    public boolean[] getSubjectUniqueID() {
        ASN1BitString subjectUniqueId = this.f611c.getTBSCertificate().getSubjectUniqueId();
        if (subjectUniqueId != null) {
            byte[] bytes = subjectUniqueId.getBytes();
            boolean[] zArr = new boolean[(bytes.length * 8) - subjectUniqueId.getPadBits()];
            for (int i = 0; i != zArr.length; i++) {
                zArr[i] = (bytes[i / 8] & (128 >>> (i % 8))) != 0;
            }
            return zArr;
        }
        return null;
    }

    @Override // java.security.cert.X509Certificate
    public boolean[] getKeyUsage() {
        return Arrays.clone(this.keyUsage);
    }

    @Override // java.security.cert.X509Certificate
    public List getExtendedKeyUsage() throws CertificateParsingException {
        byte[] extensionOctets = getExtensionOctets(this.f611c, "2.5.29.37");
        if (null == extensionOctets) {
            return null;
        }
        try {
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(extensionOctets));
            ArrayList arrayList = new ArrayList();
            for (int i = 0; i != aSN1Sequence.size(); i++) {
                arrayList.add(((ASN1ObjectIdentifier) aSN1Sequence.getObjectAt(i)).getId());
            }
            return Collections.unmodifiableList(arrayList);
        } catch (Exception e) {
            throw new CertificateParsingException("error processing extended key usage extension");
        }
    }

    @Override // java.security.cert.X509Certificate
    public int getBasicConstraints() {
        if (this.basicConstraints == null || !this.basicConstraints.isCA()) {
            return -1;
        }
        if (this.basicConstraints.getPathLenConstraint() == null) {
            return Integer.MAX_VALUE;
        }
        return this.basicConstraints.getPathLenConstraint().intValue();
    }

    @Override // java.security.cert.X509Certificate
    public Collection getSubjectAlternativeNames() throws CertificateParsingException {
        return getAlternativeNames(this.f611c, Extension.subjectAlternativeName.getId());
    }

    @Override // java.security.cert.X509Certificate
    public Collection getIssuerAlternativeNames() throws CertificateParsingException {
        return getAlternativeNames(this.f611c, Extension.issuerAlternativeName.getId());
    }

    @Override // java.security.cert.X509Extension
    public Set getCriticalExtensionOIDs() {
        if (getVersion() == 3) {
            HashSet hashSet = new HashSet();
            Extensions extensions = this.f611c.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Enumeration oids = extensions.oids();
                while (oids.hasMoreElements()) {
                    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                    if (extensions.getExtension(aSN1ObjectIdentifier).isCritical()) {
                        hashSet.add(aSN1ObjectIdentifier.getId());
                    }
                }
                return hashSet;
            }
            return null;
        }
        return null;
    }

    @Override // java.security.cert.X509Extension
    public byte[] getExtensionValue(String str) {
        ASN1OctetString extensionValue = getExtensionValue(this.f611c, str);
        if (null != extensionValue) {
            try {
                return extensionValue.getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException("error parsing " + e.toString());
            }
        }
        return null;
    }

    @Override // java.security.cert.X509Extension
    public Set getNonCriticalExtensionOIDs() {
        if (getVersion() == 3) {
            HashSet hashSet = new HashSet();
            Extensions extensions = this.f611c.getTBSCertificate().getExtensions();
            if (extensions != null) {
                Enumeration oids = extensions.oids();
                while (oids.hasMoreElements()) {
                    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                    if (!extensions.getExtension(aSN1ObjectIdentifier).isCritical()) {
                        hashSet.add(aSN1ObjectIdentifier.getId());
                    }
                }
                return hashSet;
            }
            return null;
        }
        return null;
    }

    @Override // java.security.cert.X509Extension
    public boolean hasUnsupportedCriticalExtension() {
        Extensions extensions;
        if (getVersion() != 3 || (extensions = this.f611c.getTBSCertificate().getExtensions()) == null) {
            return false;
        }
        Enumeration oids = extensions.oids();
        while (oids.hasMoreElements()) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
            if (!aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.keyUsage) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.certificatePolicies) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.policyMappings) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.inhibitAnyPolicy) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.cRLDistributionPoints) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.issuingDistributionPoint) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.deltaCRLIndicator) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.policyConstraints) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.basicConstraints) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.subjectAlternativeName) && !aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.nameConstraints) && extensions.getExtension(aSN1ObjectIdentifier).isCritical()) {
                return true;
            }
        }
        return false;
    }

    @Override // java.security.cert.Certificate
    public PublicKey getPublicKey() {
        try {
            return BouncyCastleProvider.getPublicKey(this.f611c.getSubjectPublicKeyInfo());
        } catch (IOException e) {
            return null;
        }
    }

    @Override // java.security.cert.Certificate
    public String toString() {
        StringBuffer stringBuffer = new StringBuffer();
        String lineSeparator = Strings.lineSeparator();
        stringBuffer.append("  [0]         Version: ").append(getVersion()).append(lineSeparator);
        stringBuffer.append("         SerialNumber: ").append(getSerialNumber()).append(lineSeparator);
        stringBuffer.append("             IssuerDN: ").append(getIssuerDN()).append(lineSeparator);
        stringBuffer.append("           Start Date: ").append(getNotBefore()).append(lineSeparator);
        stringBuffer.append("           Final Date: ").append(getNotAfter()).append(lineSeparator);
        stringBuffer.append("            SubjectDN: ").append(getSubjectDN()).append(lineSeparator);
        stringBuffer.append("           Public Key: ").append(getPublicKey()).append(lineSeparator);
        stringBuffer.append("  Signature Algorithm: ").append(getSigAlgName()).append(lineSeparator);
        X509SignatureUtil.prettyPrintSignature(getSignature(), stringBuffer, lineSeparator);
        Extensions extensions = this.f611c.getTBSCertificate().getExtensions();
        if (extensions != null) {
            Enumeration oids = extensions.oids();
            if (oids.hasMoreElements()) {
                stringBuffer.append("       Extensions: \n");
            }
            while (oids.hasMoreElements()) {
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
                if (extension.getExtnValue() != null) {
                    ASN1InputStream aSN1InputStream = new ASN1InputStream(extension.getExtnValue().getOctets());
                    stringBuffer.append("                       critical(").append(extension.isCritical()).append(") ");
                    try {
                        if (aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.basicConstraints)) {
                            stringBuffer.append(BasicConstraints.getInstance(aSN1InputStream.readObject())).append(lineSeparator);
                        } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.keyUsage)) {
                            stringBuffer.append(KeyUsage.getInstance(aSN1InputStream.readObject())).append(lineSeparator);
                        } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) MiscObjectIdentifiers.netscapeCertType)) {
                            stringBuffer.append(new NetscapeCertType(DERBitString.getInstance((Object) aSN1InputStream.readObject()))).append(lineSeparator);
                        } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) MiscObjectIdentifiers.netscapeRevocationURL)) {
                            stringBuffer.append(new NetscapeRevocationURL(ASN1IA5String.getInstance(aSN1InputStream.readObject()))).append(lineSeparator);
                        } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) MiscObjectIdentifiers.verisignCzagExtension)) {
                            stringBuffer.append(new VerisignCzagExtension(ASN1IA5String.getInstance(aSN1InputStream.readObject()))).append(lineSeparator);
                        } else {
                            stringBuffer.append(aSN1ObjectIdentifier.getId());
                            stringBuffer.append(" value = ").append(ASN1Dump.dumpAsString(aSN1InputStream.readObject())).append(lineSeparator);
                        }
                    } catch (Exception e) {
                        stringBuffer.append(aSN1ObjectIdentifier.getId());
                        stringBuffer.append(" value = ").append("*****").append(lineSeparator);
                    }
                } else {
                    stringBuffer.append(lineSeparator);
                }
            }
        }
        return stringBuffer.toString();
    }

    @Override // java.security.cert.Certificate
    public final void verify(PublicKey publicKey) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        doVerify(publicKey, new SignatureCreator() { // from class: org.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl.1
            @Override // org.bouncycastle.jcajce.provider.asymmetric.x509.SignatureCreator
            public Signature createSignature(String str) throws NoSuchAlgorithmException {
                try {
                    return X509CertificateImpl.this.bcHelper.createSignature(str);
                } catch (Exception e) {
                    return Signature.getInstance(str);
                }
            }
        });
    }

    @Override // java.security.cert.Certificate
    public final void verify(PublicKey publicKey, final String str) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        doVerify(publicKey, new SignatureCreator() { // from class: org.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl.2
            @Override // org.bouncycastle.jcajce.provider.asymmetric.x509.SignatureCreator
            public Signature createSignature(String str2) throws NoSuchAlgorithmException, NoSuchProviderException {
                return str != null ? Signature.getInstance(str2, str) : Signature.getInstance(str2);
            }
        });
    }

    @Override // java.security.cert.X509Certificate, java.security.cert.Certificate
    public final void verify(PublicKey publicKey, final Provider provider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            doVerify(publicKey, new SignatureCreator() { // from class: org.bouncycastle.jcajce.provider.asymmetric.x509.X509CertificateImpl.3
                @Override // org.bouncycastle.jcajce.provider.asymmetric.x509.SignatureCreator
                public Signature createSignature(String str) throws NoSuchAlgorithmException {
                    return provider != null ? Signature.getInstance(str, provider) : Signature.getInstance(str);
                }
            });
        } catch (NoSuchProviderException e) {
            throw new NoSuchAlgorithmException("provider issue: " + e.getMessage());
        }
    }

    private void doVerify(PublicKey publicKey, SignatureCreator signatureCreator) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        if ((publicKey instanceof CompositePublicKey) && X509SignatureUtil.isCompositeAlgorithm(this.f611c.getSignatureAlgorithm())) {
            List<PublicKey> publicKeys = ((CompositePublicKey) publicKey).getPublicKeys();
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(this.f611c.getSignatureAlgorithm().getParameters());
            ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(DERBitString.getInstance((Object) this.f611c.getSignature()).getBytes());
            boolean z = false;
            for (int i = 0; i != publicKeys.size(); i++) {
                if (publicKeys.get(i) != null) {
                    AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(i));
                    SignatureException signatureException = null;
                    try {
                        checkSignature(publicKeys.get(i), signatureCreator.createSignature(X509SignatureUtil.getSignatureName(algorithmIdentifier)), algorithmIdentifier.getParameters(), DERBitString.getInstance((Object) aSN1Sequence2.getObjectAt(i)).getBytes());
                        z = true;
                    } catch (SignatureException e) {
                        signatureException = e;
                    }
                    if (signatureException != null) {
                        throw signatureException;
                    }
                }
            }
            if (!z) {
                throw new InvalidKeyException("no matching key found");
            }
        } else if (!X509SignatureUtil.isCompositeAlgorithm(this.f611c.getSignatureAlgorithm())) {
            Signature createSignature = signatureCreator.createSignature(X509SignatureUtil.getSignatureName(this.f611c.getSignatureAlgorithm()));
            if (!(publicKey instanceof CompositePublicKey)) {
                checkSignature(publicKey, createSignature, this.f611c.getSignatureAlgorithm().getParameters(), getSignature());
                return;
            }
            List<PublicKey> publicKeys2 = ((CompositePublicKey) publicKey).getPublicKeys();
            for (int i2 = 0; i2 != publicKeys2.size(); i2++) {
                try {
                    checkSignature(publicKeys2.get(i2), createSignature, this.f611c.getSignatureAlgorithm().getParameters(), getSignature());
                    return;
                } catch (InvalidKeyException e2) {
                }
            }
            throw new InvalidKeyException("no matching signature found");
        } else {
            ASN1Sequence aSN1Sequence3 = ASN1Sequence.getInstance(this.f611c.getSignatureAlgorithm().getParameters());
            ASN1Sequence aSN1Sequence4 = ASN1Sequence.getInstance(DERBitString.getInstance((Object) this.f611c.getSignature()).getBytes());
            boolean z2 = false;
            for (int i3 = 0; i3 != aSN1Sequence4.size(); i3++) {
                AlgorithmIdentifier algorithmIdentifier2 = AlgorithmIdentifier.getInstance(aSN1Sequence3.getObjectAt(i3));
                SignatureException signatureException2 = null;
                try {
                    checkSignature(publicKey, signatureCreator.createSignature(X509SignatureUtil.getSignatureName(algorithmIdentifier2)), algorithmIdentifier2.getParameters(), DERBitString.getInstance((Object) aSN1Sequence4.getObjectAt(i3)).getBytes());
                    z2 = true;
                } catch (InvalidKeyException e3) {
                } catch (NoSuchAlgorithmException e4) {
                } catch (SignatureException e5) {
                    signatureException2 = e5;
                }
                if (signatureException2 != null) {
                    throw signatureException2;
                }
            }
            if (!z2) {
                throw new InvalidKeyException("no matching key found");
            }
        }
    }

    private void checkSignature(PublicKey publicKey, Signature signature, ASN1Encodable aSN1Encodable, byte[] bArr) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (!isAlgIdEqual(this.f611c.getSignatureAlgorithm(), this.f611c.getTBSCertificate().getSignature())) {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }
        X509SignatureUtil.setSignatureParameters(signature, aSN1Encodable);
        signature.initVerify(publicKey);
        try {
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(OutputStreamFactory.createStream(signature), 512);
            this.f611c.getTBSCertificate().encodeTo(bufferedOutputStream, ASN1Encoding.DER);
            bufferedOutputStream.close();
            if (!signature.verify(bArr)) {
                throw new SignatureException("certificate does not verify with supplied key");
            }
        } catch (IOException e) {
            throw new CertificateEncodingException(e.toString());
        }
    }

    private boolean isAlgIdEqual(AlgorithmIdentifier algorithmIdentifier, AlgorithmIdentifier algorithmIdentifier2) {
        if (algorithmIdentifier.getAlgorithm().equals((ASN1Primitive) algorithmIdentifier2.getAlgorithm())) {
            if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL")) {
                if (algorithmIdentifier.getParameters() == null) {
                    return algorithmIdentifier2.getParameters() == null || algorithmIdentifier2.getParameters().equals(DERNull.INSTANCE);
                } else if (algorithmIdentifier2.getParameters() == null) {
                    return algorithmIdentifier.getParameters() == null || algorithmIdentifier.getParameters().equals(DERNull.INSTANCE);
                }
            }
            if (algorithmIdentifier.getParameters() != null) {
                return algorithmIdentifier.getParameters().equals(algorithmIdentifier2.getParameters());
            }
            if (algorithmIdentifier2.getParameters() != null) {
                return algorithmIdentifier2.getParameters().equals(algorithmIdentifier.getParameters());
            }
            return true;
        }
        return false;
    }

    private static Collection getAlternativeNames(Certificate certificate, String str) throws CertificateParsingException {
        byte[] extensionOctets = getExtensionOctets(certificate, str);
        if (extensionOctets == null) {
            return null;
        }
        try {
            ArrayList arrayList = new ArrayList();
            Enumeration objects = ASN1Sequence.getInstance(extensionOctets).getObjects();
            while (objects.hasMoreElements()) {
                GeneralName generalName = GeneralName.getInstance(objects.nextElement());
                ArrayList arrayList2 = new ArrayList();
                arrayList2.add(Integers.valueOf(generalName.getTagNo()));
                switch (generalName.getTagNo()) {
                    case 0:
                    case 3:
                    case 5:
                        arrayList2.add(generalName.getEncoded());
                        break;
                    case 1:
                    case 2:
                    case 6:
                        arrayList2.add(((ASN1String) generalName.getName()).getString());
                        break;
                    case 4:
                        arrayList2.add(X500Name.getInstance(RFC4519Style.INSTANCE, generalName.getName()).toString());
                        break;
                    case 7:
                        try {
                            arrayList2.add(InetAddress.getByAddress(DEROctetString.getInstance(generalName.getName()).getOctets()).getHostAddress());
                            break;
                        } catch (UnknownHostException e) {
                            break;
                        }
                    case 8:
                        arrayList2.add(ASN1ObjectIdentifier.getInstance(generalName.getName()).getId());
                        break;
                    default:
                        throw new IOException("Bad tag number: " + generalName.getTagNo());
                }
                arrayList.add(Collections.unmodifiableList(arrayList2));
            }
            if (arrayList.size() == 0) {
                return null;
            }
            return Collections.unmodifiableCollection(arrayList);
        } catch (Exception e2) {
            throw new CertificateParsingException(e2.getMessage());
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] getExtensionOctets(Certificate certificate, String str) {
        ASN1OctetString extensionValue = getExtensionValue(certificate, str);
        if (null != extensionValue) {
            return extensionValue.getOctets();
        }
        return null;
    }

    protected static ASN1OctetString getExtensionValue(Certificate certificate, String str) {
        Extension extension;
        Extensions extensions = certificate.getTBSCertificate().getExtensions();
        if (null == extensions || null == (extension = extensions.getExtension(new ASN1ObjectIdentifier(str)))) {
            return null;
        }
        return extension.getExtnValue();
    }
}