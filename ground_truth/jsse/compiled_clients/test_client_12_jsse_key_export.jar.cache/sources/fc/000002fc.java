package org.bouncycastle.asn1.x500;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.style.BCStyle;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x500/X500Name.class */
public class X500Name extends ASN1Object implements ASN1Choice {
    private static X500NameStyle defaultStyle = BCStyle.INSTANCE;
    private boolean isHashCodeCalculated;
    private int hashCodeValue;
    private X500NameStyle style;
    private RDN[] rdns;
    private DERSequence rdnSeq;

    public X500Name(X500NameStyle x500NameStyle, X500Name x500Name) {
        this.style = x500NameStyle;
        this.rdns = x500Name.rdns;
        this.rdnSeq = x500Name.rdnSeq;
    }

    public static X500Name getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, true));
    }

    public static X500Name getInstance(Object obj) {
        if (obj instanceof X500Name) {
            return (X500Name) obj;
        }
        if (obj != null) {
            return new X500Name(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static X500Name getInstance(X500NameStyle x500NameStyle, Object obj) {
        if (obj instanceof X500Name) {
            return new X500Name(x500NameStyle, (X500Name) obj);
        }
        if (obj != null) {
            return new X500Name(x500NameStyle, ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private X500Name(ASN1Sequence aSN1Sequence) {
        this(defaultStyle, aSN1Sequence);
    }

    private X500Name(X500NameStyle x500NameStyle, ASN1Sequence aSN1Sequence) {
        this.style = x500NameStyle;
        this.rdns = new RDN[aSN1Sequence.size()];
        boolean z = true;
        int i = 0;
        Enumeration objects = aSN1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            Object nextElement = objects.nextElement();
            RDN rdn = RDN.getInstance(nextElement);
            z &= rdn == nextElement;
            int i2 = i;
            i++;
            this.rdns[i2] = rdn;
        }
        if (z) {
            this.rdnSeq = DERSequence.convert(aSN1Sequence);
        } else {
            this.rdnSeq = new DERSequence(this.rdns);
        }
    }

    public X500Name(RDN[] rdnArr) {
        this(defaultStyle, rdnArr);
    }

    public X500Name(X500NameStyle x500NameStyle, RDN[] rdnArr) {
        this.style = x500NameStyle;
        this.rdns = (RDN[]) rdnArr.clone();
        this.rdnSeq = new DERSequence(this.rdns);
    }

    public X500Name(String str) {
        this(defaultStyle, str);
    }

    public X500Name(X500NameStyle x500NameStyle, String str) {
        this(x500NameStyle.fromString(str));
        this.style = x500NameStyle;
    }

    public RDN[] getRDNs() {
        return (RDN[]) this.rdns.clone();
    }

    public ASN1ObjectIdentifier[] getAttributeTypes() {
        int length = this.rdns.length;
        int i = 0;
        for (int i2 = 0; i2 < length; i2++) {
            i += this.rdns[i2].size();
        }
        ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr = new ASN1ObjectIdentifier[i];
        int i3 = 0;
        for (int i4 = 0; i4 < length; i4++) {
            i3 += this.rdns[i4].collectAttributeTypes(aSN1ObjectIdentifierArr, i3);
        }
        return aSN1ObjectIdentifierArr;
    }

    public RDN[] getRDNs(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        RDN[] rdnArr = new RDN[this.rdns.length];
        int i = 0;
        for (int i2 = 0; i2 != this.rdns.length; i2++) {
            RDN rdn = this.rdns[i2];
            if (rdn.containsAttributeType(aSN1ObjectIdentifier)) {
                int i3 = i;
                i++;
                rdnArr[i3] = rdn;
            }
        }
        if (i < rdnArr.length) {
            RDN[] rdnArr2 = new RDN[i];
            System.arraycopy(rdnArr, 0, rdnArr2, 0, rdnArr2.length);
            rdnArr = rdnArr2;
        }
        return rdnArr;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.rdnSeq;
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        if (this.isHashCodeCalculated) {
            return this.hashCodeValue;
        }
        this.isHashCodeCalculated = true;
        this.hashCodeValue = this.style.calculateHashCode(this);
        return this.hashCodeValue;
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if ((obj instanceof X500Name) || (obj instanceof ASN1Sequence)) {
            if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
                return true;
            }
            try {
                return this.style.areEqual(this, new X500Name(ASN1Sequence.getInstance(((ASN1Encodable) obj).toASN1Primitive())));
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    public String toString() {
        return this.style.toString(this);
    }

    public static void setDefaultStyle(X500NameStyle x500NameStyle) {
        if (x500NameStyle == null) {
            throw new NullPointerException("cannot set style to null");
        }
        defaultStyle = x500NameStyle;
    }

    public static X500NameStyle getDefaultStyle() {
        return defaultStyle;
    }
}