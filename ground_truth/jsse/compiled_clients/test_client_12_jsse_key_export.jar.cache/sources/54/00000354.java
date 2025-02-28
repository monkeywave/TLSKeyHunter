package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x509/X509Name.class */
public class X509Name extends ASN1Object {

    /* renamed from: C */
    public static final ASN1ObjectIdentifier f66C = new ASN1ObjectIdentifier("2.5.4.6");

    /* renamed from: O */
    public static final ASN1ObjectIdentifier f67O = new ASN1ObjectIdentifier("2.5.4.10");

    /* renamed from: OU */
    public static final ASN1ObjectIdentifier f68OU = new ASN1ObjectIdentifier("2.5.4.11");

    /* renamed from: T */
    public static final ASN1ObjectIdentifier f69T = new ASN1ObjectIdentifier("2.5.4.12");

    /* renamed from: CN */
    public static final ASN1ObjectIdentifier f70CN = new ASN1ObjectIdentifier("2.5.4.3");

    /* renamed from: SN */
    public static final ASN1ObjectIdentifier f71SN = new ASN1ObjectIdentifier("2.5.4.5");
    public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
    public static final ASN1ObjectIdentifier SERIALNUMBER = f71SN;

    /* renamed from: L */
    public static final ASN1ObjectIdentifier f72L = new ASN1ObjectIdentifier("2.5.4.7");

    /* renamed from: ST */
    public static final ASN1ObjectIdentifier f73ST = new ASN1ObjectIdentifier("2.5.4.8");
    public static final ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    public static final ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    public static final ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");
    public static final ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");
    public static final ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");
    public static final ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");
    public static final ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");
    public static final ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");
    public static final ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");
    public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");
    public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");
    public static final ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");
    public static final ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");
    public static final ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");
    public static final ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
    public static final ASN1ObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;
    public static final ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    public static final ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    public static final ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;

    /* renamed from: E */
    public static final ASN1ObjectIdentifier f74E = EmailAddress;

    /* renamed from: DC */
    public static final ASN1ObjectIdentifier f75DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");
    public static final ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");
    public static boolean DefaultReverse = false;
    public static final Hashtable DefaultSymbols = new Hashtable();
    public static final Hashtable RFC2253Symbols = new Hashtable();
    public static final Hashtable RFC1779Symbols = new Hashtable();
    public static final Hashtable DefaultLookUp = new Hashtable();
    public static final Hashtable OIDLookUp = DefaultSymbols;
    public static final Hashtable SymbolLookUp = DefaultLookUp;
    private static final Boolean TRUE = new Boolean(true);
    private static final Boolean FALSE = new Boolean(false);
    private X509NameEntryConverter converter;
    private Vector ordering;
    private Vector values;
    private Vector added;
    private ASN1Sequence seq;
    private boolean isHashCodeCalculated;
    private int hashCodeValue;

    public static X509Name getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public static X509Name getInstance(Object obj) {
        if (obj instanceof X509Name) {
            return (X509Name) obj;
        }
        if (obj instanceof X500Name) {
            return new X509Name(ASN1Sequence.getInstance(((X500Name) obj).toASN1Primitive()));
        }
        if (obj != null) {
            return new X509Name(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected X509Name() {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
    }

    public X509Name(ASN1Sequence aSN1Sequence) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.seq = aSN1Sequence;
        Enumeration objects = aSN1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Set aSN1Set = ASN1Set.getInstance(((ASN1Encodable) objects.nextElement()).toASN1Primitive());
            int i = 0;
            while (i < aSN1Set.size()) {
                ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(aSN1Set.getObjectAt(i).toASN1Primitive());
                if (aSN1Sequence2.size() != 2) {
                    throw new IllegalArgumentException("badly sized pair");
                }
                this.ordering.addElement(ASN1ObjectIdentifier.getInstance(aSN1Sequence2.getObjectAt(0)));
                ASN1Encodable objectAt = aSN1Sequence2.getObjectAt(1);
                if (!(objectAt instanceof ASN1String) || (objectAt instanceof ASN1UniversalString)) {
                    try {
                        this.values.addElement("#" + bytesToString(Hex.encode(objectAt.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
                    } catch (IOException e) {
                        throw new IllegalArgumentException("cannot encode value");
                    }
                } else {
                    String string = ((ASN1String) objectAt).getString();
                    if (string.length() <= 0 || string.charAt(0) != '#') {
                        this.values.addElement(string);
                    } else {
                        this.values.addElement("\\" + string);
                    }
                }
                this.added.addElement(i != 0 ? TRUE : FALSE);
                i++;
            }
        }
    }

    public X509Name(Hashtable hashtable) {
        this((Vector) null, hashtable);
    }

    public X509Name(Vector vector, Hashtable hashtable) {
        this(vector, hashtable, new X509DefaultEntryConverter());
    }

    public X509Name(Vector vector, Hashtable hashtable, X509NameEntryConverter x509NameEntryConverter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        if (vector != null) {
            for (int i = 0; i != vector.size(); i++) {
                this.ordering.addElement(vector.elementAt(i));
                this.added.addElement(FALSE);
            }
        } else {
            Enumeration keys = hashtable.keys();
            while (keys.hasMoreElements()) {
                this.ordering.addElement(keys.nextElement());
                this.added.addElement(FALSE);
            }
        }
        for (int i2 = 0; i2 != this.ordering.size(); i2++) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) this.ordering.elementAt(i2);
            if (hashtable.get(aSN1ObjectIdentifier) == null) {
                throw new IllegalArgumentException("No attribute for object id - " + aSN1ObjectIdentifier.getId() + " - passed to distinguished name");
            }
            this.values.addElement(hashtable.get(aSN1ObjectIdentifier));
        }
    }

    public X509Name(Vector vector, Vector vector2) {
        this(vector, vector2, new X509DefaultEntryConverter());
    }

    public X509Name(Vector vector, Vector vector2, X509NameEntryConverter x509NameEntryConverter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        if (vector.size() != vector2.size()) {
            throw new IllegalArgumentException("oids vector must be same length as values.");
        }
        for (int i = 0; i < vector.size(); i++) {
            this.ordering.addElement(vector.elementAt(i));
            this.values.addElement(vector2.elementAt(i));
            this.added.addElement(FALSE);
        }
    }

    public X509Name(String str) {
        this(DefaultReverse, DefaultLookUp, str);
    }

    public X509Name(String str, X509NameEntryConverter x509NameEntryConverter) {
        this(DefaultReverse, DefaultLookUp, str, x509NameEntryConverter);
    }

    public X509Name(boolean z, String str) {
        this(z, DefaultLookUp, str);
    }

    public X509Name(boolean z, String str, X509NameEntryConverter x509NameEntryConverter) {
        this(z, DefaultLookUp, str, x509NameEntryConverter);
    }

    public X509Name(boolean z, Hashtable hashtable, String str) {
        this(z, hashtable, str, new X509DefaultEntryConverter());
    }

    private ASN1ObjectIdentifier decodeOID(String str, Hashtable hashtable) {
        String trim = str.trim();
        if (Strings.toUpperCase(trim).startsWith("OID.")) {
            return new ASN1ObjectIdentifier(trim.substring(4));
        }
        if (trim.charAt(0) < '0' || trim.charAt(0) > '9') {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) hashtable.get(Strings.toLowerCase(trim));
            if (aSN1ObjectIdentifier == null) {
                throw new IllegalArgumentException("Unknown object id - " + trim + " - passed to distinguished name");
            }
            return aSN1ObjectIdentifier;
        }
        return new ASN1ObjectIdentifier(trim);
    }

    private String unescape(String str) {
        if (str.length() == 0 || (str.indexOf(92) < 0 && str.indexOf(34) < 0)) {
            return str.trim();
        }
        char[] charArray = str.toCharArray();
        boolean z = false;
        boolean z2 = false;
        StringBuffer stringBuffer = new StringBuffer(str.length());
        int i = 0;
        if (charArray[0] == '\\' && charArray[1] == '#') {
            i = 2;
            stringBuffer.append("\\#");
        }
        boolean z3 = false;
        int i2 = 0;
        for (int i3 = i; i3 != charArray.length; i3++) {
            char c = charArray[i3];
            if (c != ' ') {
                z3 = true;
            }
            if (c == '\"') {
                if (z) {
                    stringBuffer.append(c);
                } else {
                    z2 = !z2;
                }
                z = false;
            } else if (c == '\\' && !z && !z2) {
                z = true;
                i2 = stringBuffer.length();
            } else if (c != ' ' || z || z3) {
                stringBuffer.append(c);
                z = false;
            }
        }
        if (stringBuffer.length() > 0) {
            while (stringBuffer.charAt(stringBuffer.length() - 1) == ' ' && i2 != stringBuffer.length() - 1) {
                stringBuffer.setLength(stringBuffer.length() - 1);
            }
        }
        return stringBuffer.toString();
    }

    public X509Name(boolean z, Hashtable hashtable, String str, X509NameEntryConverter x509NameEntryConverter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(str);
        while (x509NameTokenizer.hasMoreTokens()) {
            String nextToken = x509NameTokenizer.nextToken();
            if (nextToken.indexOf(43) > 0) {
                X509NameTokenizer x509NameTokenizer2 = new X509NameTokenizer(nextToken, '+');
                addEntry(hashtable, x509NameTokenizer2.nextToken(), FALSE);
                while (x509NameTokenizer2.hasMoreTokens()) {
                    addEntry(hashtable, x509NameTokenizer2.nextToken(), TRUE);
                }
            } else {
                addEntry(hashtable, nextToken, FALSE);
            }
        }
        if (z) {
            Vector vector = new Vector();
            Vector vector2 = new Vector();
            Vector vector3 = new Vector();
            int i = 1;
            for (int i2 = 0; i2 < this.ordering.size(); i2++) {
                if (((Boolean) this.added.elementAt(i2)).booleanValue()) {
                    vector.insertElementAt(this.ordering.elementAt(i2), i);
                    vector2.insertElementAt(this.values.elementAt(i2), i);
                    vector3.insertElementAt(this.added.elementAt(i2), i);
                    i++;
                } else {
                    vector.insertElementAt(this.ordering.elementAt(i2), 0);
                    vector2.insertElementAt(this.values.elementAt(i2), 0);
                    vector3.insertElementAt(this.added.elementAt(i2), 0);
                    i = 1;
                }
            }
            this.ordering = vector;
            this.values = vector2;
            this.added = vector3;
        }
    }

    private void addEntry(Hashtable hashtable, String str, Boolean bool) {
        X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(str, '=');
        String nextToken = x509NameTokenizer.nextToken();
        if (!x509NameTokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("badly formatted directory string");
        }
        String nextToken2 = x509NameTokenizer.nextToken();
        this.ordering.addElement(decodeOID(nextToken, hashtable));
        this.values.addElement(unescape(nextToken2));
        this.added.addElement(bool);
    }

    public Vector getOIDs() {
        Vector vector = new Vector();
        for (int i = 0; i != this.ordering.size(); i++) {
            vector.addElement(this.ordering.elementAt(i));
        }
        return vector;
    }

    public Vector getValues() {
        Vector vector = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            vector.addElement(this.values.elementAt(i));
        }
        return vector;
    }

    public Vector getValues(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        Vector vector = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            if (this.ordering.elementAt(i).equals(aSN1ObjectIdentifier)) {
                String str = (String) this.values.elementAt(i);
                if (str.length() > 2 && str.charAt(0) == '\\' && str.charAt(1) == '#') {
                    vector.addElement(str.substring(1));
                } else {
                    vector.addElement(str);
                }
            }
        }
        return vector;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        if (this.seq == null) {
            ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
            ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
            ASN1ObjectIdentifier aSN1ObjectIdentifier = null;
            for (int i = 0; i != this.ordering.size(); i++) {
                ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector(2);
                ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) this.ordering.elementAt(i);
                aSN1EncodableVector3.add(aSN1ObjectIdentifier2);
                aSN1EncodableVector3.add(this.converter.getConvertedValue(aSN1ObjectIdentifier2, (String) this.values.elementAt(i)));
                if (aSN1ObjectIdentifier == null || ((Boolean) this.added.elementAt(i)).booleanValue()) {
                    aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector3));
                } else {
                    aSN1EncodableVector.add(new DERSet(aSN1EncodableVector2));
                    aSN1EncodableVector2 = new ASN1EncodableVector();
                    aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector3));
                }
                aSN1ObjectIdentifier = aSN1ObjectIdentifier2;
            }
            aSN1EncodableVector.add(new DERSet(aSN1EncodableVector2));
            this.seq = new DERSequence(aSN1EncodableVector);
        }
        return this.seq;
    }

    public boolean equals(Object obj, boolean z) {
        if (z) {
            if (obj == this) {
                return true;
            }
            if ((obj instanceof X509Name) || (obj instanceof ASN1Sequence)) {
                if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
                    return true;
                }
                try {
                    X509Name x509Name = getInstance(obj);
                    int size = this.ordering.size();
                    if (size != x509Name.ordering.size()) {
                        return false;
                    }
                    for (int i = 0; i < size; i++) {
                        if (!((ASN1ObjectIdentifier) this.ordering.elementAt(i)).equals((ASN1Primitive) ((ASN1ObjectIdentifier) x509Name.ordering.elementAt(i))) || !equivalentStrings((String) this.values.elementAt(i), (String) x509Name.values.elementAt(i))) {
                            return false;
                        }
                    }
                    return true;
                } catch (IllegalArgumentException e) {
                    return false;
                }
            }
            return false;
        }
        return equals(obj);
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        if (this.isHashCodeCalculated) {
            return this.hashCodeValue;
        }
        this.isHashCodeCalculated = true;
        for (int i = 0; i != this.ordering.size(); i++) {
            String stripInternalSpaces = stripInternalSpaces(canonicalize((String) this.values.elementAt(i)));
            this.hashCodeValue ^= this.ordering.elementAt(i).hashCode();
            this.hashCodeValue ^= stripInternalSpaces.hashCode();
        }
        return this.hashCodeValue;
    }

    @Override // org.bouncycastle.asn1.ASN1Object
    public boolean equals(Object obj) {
        int i;
        int i2;
        int i3;
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof X509Name) && !(obj instanceof ASN1Sequence)) {
            return false;
        }
        if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
            return true;
        }
        try {
            X509Name x509Name = getInstance(obj);
            int size = this.ordering.size();
            if (size != x509Name.ordering.size()) {
                return false;
            }
            boolean[] zArr = new boolean[size];
            if (this.ordering.elementAt(0).equals(x509Name.ordering.elementAt(0))) {
                i = 0;
                i2 = size;
                i3 = 1;
            } else {
                i = size - 1;
                i2 = -1;
                i3 = -1;
            }
            int i4 = i;
            while (true) {
                int i5 = i4;
                if (i5 == i2) {
                    return true;
                }
                boolean z = false;
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) this.ordering.elementAt(i5);
                String str = (String) this.values.elementAt(i5);
                int i6 = 0;
                while (true) {
                    if (i6 >= size) {
                        break;
                    } else if (!zArr[i6] && aSN1ObjectIdentifier.equals((ASN1Primitive) ((ASN1ObjectIdentifier) x509Name.ordering.elementAt(i6))) && equivalentStrings(str, (String) x509Name.values.elementAt(i6))) {
                        zArr[i6] = true;
                        z = true;
                        break;
                    } else {
                        i6++;
                    }
                }
                if (!z) {
                    return false;
                }
                i4 = i5 + i3;
            }
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean equivalentStrings(String str, String str2) {
        String canonicalize = canonicalize(str);
        String canonicalize2 = canonicalize(str2);
        return canonicalize.equals(canonicalize2) || stripInternalSpaces(canonicalize).equals(stripInternalSpaces(canonicalize2));
    }

    private String canonicalize(String str) {
        String lowerCase = Strings.toLowerCase(str.trim());
        if (lowerCase.length() > 0 && lowerCase.charAt(0) == '#') {
            ASN1Primitive decodeObject = decodeObject(lowerCase);
            if (decodeObject instanceof ASN1String) {
                lowerCase = Strings.toLowerCase(((ASN1String) decodeObject).getString().trim());
            }
        }
        return lowerCase;
    }

    private ASN1Primitive decodeObject(String str) {
        try {
            return ASN1Primitive.fromByteArray(Hex.decodeStrict(str, 1, str.length() - 1));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    private String stripInternalSpaces(String str) {
        StringBuffer stringBuffer = new StringBuffer();
        if (str.length() != 0) {
            char charAt = str.charAt(0);
            stringBuffer.append(charAt);
            for (int i = 1; i < str.length(); i++) {
                char charAt2 = str.charAt(i);
                if (charAt != ' ' || charAt2 != ' ') {
                    stringBuffer.append(charAt2);
                }
                charAt = charAt2;
            }
        }
        return stringBuffer.toString();
    }

    private void appendValue(StringBuffer stringBuffer, Hashtable hashtable, ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) {
        String str2 = (String) hashtable.get(aSN1ObjectIdentifier);
        if (str2 != null) {
            stringBuffer.append(str2);
        } else {
            stringBuffer.append(aSN1ObjectIdentifier.getId());
        }
        stringBuffer.append('=');
        int length = stringBuffer.length();
        stringBuffer.append(str);
        int length2 = stringBuffer.length();
        if (str.length() >= 2 && str.charAt(0) == '\\' && str.charAt(1) == '#') {
            length += 2;
        }
        while (length < length2 && stringBuffer.charAt(length) == ' ') {
            stringBuffer.insert(length, "\\");
            length += 2;
            length2++;
        }
        while (true) {
            length2--;
            if (length2 <= length || stringBuffer.charAt(length2) != ' ') {
                break;
            }
            stringBuffer.insert(length2, '\\');
        }
        while (length <= length2) {
            switch (stringBuffer.charAt(length)) {
                case Opcode.FLOAD_0 /* 34 */:
                case Opcode.ALOAD_1 /* 43 */:
                case Opcode.ALOAD_2 /* 44 */:
                case Opcode.ISTORE_0 /* 59 */:
                case '<':
                case Opcode.ISTORE_2 /* 61 */:
                case Opcode.ISTORE_3 /* 62 */:
                case Opcode.DUP2 /* 92 */:
                    stringBuffer.insert(length, "\\");
                    length += 2;
                    length2++;
                    break;
                default:
                    length++;
                    break;
            }
        }
    }

    public String toString(boolean z, Hashtable hashtable) {
        StringBuffer stringBuffer = new StringBuffer();
        Vector vector = new Vector();
        boolean z2 = true;
        StringBuffer stringBuffer2 = null;
        for (int i = 0; i < this.ordering.size(); i++) {
            if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                stringBuffer2.append('+');
                appendValue(stringBuffer2, hashtable, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
            } else {
                stringBuffer2 = new StringBuffer();
                appendValue(stringBuffer2, hashtable, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
                vector.addElement(stringBuffer2);
            }
        }
        if (z) {
            for (int size = vector.size() - 1; size >= 0; size--) {
                if (z2) {
                    z2 = false;
                } else {
                    stringBuffer.append(',');
                }
                stringBuffer.append(vector.elementAt(size).toString());
            }
        } else {
            for (int i2 = 0; i2 < vector.size(); i2++) {
                if (z2) {
                    z2 = false;
                } else {
                    stringBuffer.append(',');
                }
                stringBuffer.append(vector.elementAt(i2).toString());
            }
        }
        return stringBuffer.toString();
    }

    private String bytesToString(byte[] bArr) {
        char[] cArr = new char[bArr.length];
        for (int i = 0; i != cArr.length; i++) {
            cArr[i] = (char) (bArr[i] & 255);
        }
        return new String(cArr);
    }

    public String toString() {
        return toString(DefaultReverse, DefaultSymbols);
    }

    static {
        DefaultSymbols.put(f66C, "C");
        DefaultSymbols.put(f67O, "O");
        DefaultSymbols.put(f69T, "T");
        DefaultSymbols.put(f68OU, "OU");
        DefaultSymbols.put(f70CN, "CN");
        DefaultSymbols.put(f72L, "L");
        DefaultSymbols.put(f73ST, "ST");
        DefaultSymbols.put(f71SN, "SERIALNUMBER");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(f75DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");
        RFC2253Symbols.put(f66C, "C");
        RFC2253Symbols.put(f67O, "O");
        RFC2253Symbols.put(f68OU, "OU");
        RFC2253Symbols.put(f70CN, "CN");
        RFC2253Symbols.put(f72L, "L");
        RFC2253Symbols.put(f73ST, "ST");
        RFC2253Symbols.put(STREET, "STREET");
        RFC2253Symbols.put(f75DC, "DC");
        RFC2253Symbols.put(UID, "UID");
        RFC1779Symbols.put(f66C, "C");
        RFC1779Symbols.put(f67O, "O");
        RFC1779Symbols.put(f68OU, "OU");
        RFC1779Symbols.put(f70CN, "CN");
        RFC1779Symbols.put(f72L, "L");
        RFC1779Symbols.put(f73ST, "ST");
        RFC1779Symbols.put(STREET, "STREET");
        DefaultLookUp.put("c", f66C);
        DefaultLookUp.put("o", f67O);
        DefaultLookUp.put("t", f69T);
        DefaultLookUp.put("ou", f68OU);
        DefaultLookUp.put("cn", f70CN);
        DefaultLookUp.put("l", f72L);
        DefaultLookUp.put("st", f73ST);
        DefaultLookUp.put("sn", f71SN);
        DefaultLookUp.put("serialnumber", f71SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", f74E);
        DefaultLookUp.put("dc", f75DC);
        DefaultLookUp.put("e", f74E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
    }
}