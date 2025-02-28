package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
class X509CRLEntryObject extends X509CRLEntry {

    /* renamed from: c */
    private TBSCertList.CRLEntry f936c;
    private X500Name certificateIssuer;
    private volatile int hashValue;
    private volatile boolean hashValueSet;

    protected X509CRLEntryObject(TBSCertList.CRLEntry cRLEntry) {
        this.f936c = cRLEntry;
        this.certificateIssuer = null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public X509CRLEntryObject(TBSCertList.CRLEntry cRLEntry, boolean z, X500Name x500Name) {
        this.f936c = cRLEntry;
        this.certificateIssuer = loadCertificateIssuer(z, x500Name);
    }

    private Extension getExtension(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        Extensions extensions = this.f936c.getExtensions();
        if (extensions != null) {
            return extensions.getExtension(aSN1ObjectIdentifier);
        }
        return null;
    }

    private Set getExtensionOIDs(boolean z) {
        Extensions extensions = this.f936c.getExtensions();
        if (extensions != null) {
            HashSet hashSet = new HashSet();
            Enumeration oids = extensions.oids();
            while (oids.hasMoreElements()) {
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                if (z == extensions.getExtension(aSN1ObjectIdentifier).isCritical()) {
                    hashSet.add(aSN1ObjectIdentifier.getId());
                }
            }
            return hashSet;
        }
        return null;
    }

    private X500Name loadCertificateIssuer(boolean z, X500Name x500Name) {
        if (z) {
            Extension extension = getExtension(Extension.certificateIssuer);
            if (extension == null) {
                return x500Name;
            }
            try {
                GeneralName[] names = GeneralNames.getInstance(extension.getParsedValue()).getNames();
                for (int i = 0; i < names.length; i++) {
                    if (names[i].getTagNo() == 4) {
                        return X500Name.getInstance(names[i].getName());
                    }
                }
            } catch (Exception unused) {
            }
            return null;
        }
        return null;
    }

    @Override // java.security.cert.X509CRLEntry
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof X509CRLEntryObject) {
            X509CRLEntryObject x509CRLEntryObject = (X509CRLEntryObject) obj;
            if (this.hashValueSet && x509CRLEntryObject.hashValueSet && this.hashValue != x509CRLEntryObject.hashValue) {
                return false;
            }
            return this.f936c.equals(x509CRLEntryObject.f936c);
        }
        return super.equals(this);
    }

    @Override // java.security.cert.X509CRLEntry
    public X500Principal getCertificateIssuer() {
        if (this.certificateIssuer == null) {
            return null;
        }
        try {
            return new X500Principal(this.certificateIssuer.getEncoded());
        } catch (IOException unused) {
            return null;
        }
    }

    @Override // java.security.cert.X509Extension
    public Set getCriticalExtensionOIDs() {
        return getExtensionOIDs(true);
    }

    @Override // java.security.cert.X509CRLEntry
    public byte[] getEncoded() throws CRLException {
        try {
            return this.f936c.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new CRLException(e.toString());
        }
    }

    @Override // java.security.cert.X509Extension
    public byte[] getExtensionValue(String str) {
        Extension extension = getExtension(new ASN1ObjectIdentifier(str));
        if (extension != null) {
            try {
                return extension.getExtnValue().getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException("Exception encoding: " + e.toString());
            }
        }
        return null;
    }

    @Override // java.security.cert.X509Extension
    public Set getNonCriticalExtensionOIDs() {
        return getExtensionOIDs(false);
    }

    @Override // java.security.cert.X509CRLEntry
    public Date getRevocationDate() {
        return this.f936c.getRevocationDate().getDate();
    }

    @Override // java.security.cert.X509CRLEntry
    public BigInteger getSerialNumber() {
        return this.f936c.getUserCertificate().getValue();
    }

    @Override // java.security.cert.X509CRLEntry
    public boolean hasExtensions() {
        return this.f936c.getExtensions() != null;
    }

    @Override // java.security.cert.X509Extension
    public boolean hasUnsupportedCriticalExtension() {
        Set criticalExtensionOIDs = getCriticalExtensionOIDs();
        return (criticalExtensionOIDs == null || criticalExtensionOIDs.isEmpty()) ? false : true;
    }

    @Override // java.security.cert.X509CRLEntry
    public int hashCode() {
        if (!this.hashValueSet) {
            this.hashValue = super.hashCode();
            this.hashValueSet = true;
        }
        return this.hashValue;
    }

    @Override // java.security.cert.X509CRLEntry
    public String toString() {
        StringBuffer append;
        StringBuffer stringBuffer = new StringBuffer("      userCertificate: ");
        String lineSeparator = Strings.lineSeparator();
        stringBuffer.append(getSerialNumber()).append(lineSeparator);
        stringBuffer.append("       revocationDate: ").append(getRevocationDate()).append(lineSeparator);
        stringBuffer.append("       certificateIssuer: ").append(getCertificateIssuer()).append(lineSeparator);
        Extensions extensions = this.f936c.getExtensions();
        if (extensions != null) {
            Enumeration oids = extensions.oids();
            if (oids.hasMoreElements()) {
                String str = "   crlEntryExtensions:";
                loop0: while (true) {
                    stringBuffer.append(str).append(lineSeparator);
                    while (oids.hasMoreElements()) {
                        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) oids.nextElement();
                        Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
                        if (extension.getExtnValue() != null) {
                            ASN1InputStream aSN1InputStream = new ASN1InputStream(extension.getExtnValue().getOctets());
                            stringBuffer.append("                       critical(").append(extension.isCritical()).append(") ");
                            try {
                                if (aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.reasonCode)) {
                                    append = stringBuffer.append(CRLReason.getInstance(ASN1Enumerated.getInstance(aSN1InputStream.readObject())));
                                } else if (aSN1ObjectIdentifier.equals((ASN1Primitive) Extension.certificateIssuer)) {
                                    append = stringBuffer.append("Certificate issuer: ").append(GeneralNames.getInstance(aSN1InputStream.readObject()));
                                } else {
                                    stringBuffer.append(aSN1ObjectIdentifier.getId());
                                    append = stringBuffer.append(" value = ").append(ASN1Dump.dumpAsString(aSN1InputStream.readObject()));
                                }
                                append.append(lineSeparator);
                            } catch (Exception unused) {
                                stringBuffer.append(aSN1ObjectIdentifier.getId());
                                str = " value = *****";
                            }
                        } else {
                            stringBuffer.append(lineSeparator);
                        }
                    }
                    break loop0;
                }
            }
        }
        return stringBuffer.toString();
    }
}