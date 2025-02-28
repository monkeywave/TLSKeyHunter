package org.bouncycastle.asn1.x500.style;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x500/style/IETFUtils.class */
public class IETFUtils {
    private static String unescape(String str) {
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
        char c = 0;
        for (int i3 = i; i3 != charArray.length; i3++) {
            char c2 = charArray[i3];
            if (c2 != ' ') {
                z3 = true;
            }
            if (c2 == '\"') {
                if (z) {
                    stringBuffer.append(c2);
                } else {
                    z2 = !z2;
                }
                z = false;
            } else if (c2 == '\\' && !z && !z2) {
                z = true;
                i2 = stringBuffer.length();
            } else if (c2 != ' ' || z || z3) {
                if (!z || !isHexDigit(c2)) {
                    stringBuffer.append(c2);
                    z = false;
                } else if (c != 0) {
                    stringBuffer.append((char) ((convertHex(c) * 16) + convertHex(c2)));
                    z = false;
                    c = 0;
                } else {
                    c = c2;
                }
            }
        }
        if (stringBuffer.length() > 0) {
            while (stringBuffer.charAt(stringBuffer.length() - 1) == ' ' && i2 != stringBuffer.length() - 1) {
                stringBuffer.setLength(stringBuffer.length() - 1);
            }
        }
        return stringBuffer.toString();
    }

    private static boolean isHexDigit(char c) {
        return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
    }

    private static int convertHex(char c) {
        return ('0' > c || c > '9') ? ('a' > c || c > 'f') ? (c - 'A') + 10 : (c - 'a') + 10 : c - '0';
    }

    public static RDN[] rDNsFromString(String str, X500NameStyle x500NameStyle) {
        X500NameTokenizer x500NameTokenizer = new X500NameTokenizer(str);
        X500NameBuilder x500NameBuilder = new X500NameBuilder(x500NameStyle);
        while (x500NameTokenizer.hasMoreTokens()) {
            String nextToken = x500NameTokenizer.nextToken();
            if (nextToken.indexOf(43) > 0) {
                X500NameTokenizer x500NameTokenizer2 = new X500NameTokenizer(nextToken, '+');
                X500NameTokenizer x500NameTokenizer3 = new X500NameTokenizer(x500NameTokenizer2.nextToken(), '=');
                String nextToken2 = x500NameTokenizer3.nextToken();
                if (!x500NameTokenizer3.hasMoreTokens()) {
                    throw new IllegalArgumentException("badly formatted directory string");
                }
                String nextToken3 = x500NameTokenizer3.nextToken();
                ASN1ObjectIdentifier attrNameToOID = x500NameStyle.attrNameToOID(nextToken2.trim());
                if (x500NameTokenizer2.hasMoreTokens()) {
                    Vector vector = new Vector();
                    Vector vector2 = new Vector();
                    vector.addElement(attrNameToOID);
                    vector2.addElement(unescape(nextToken3));
                    while (x500NameTokenizer2.hasMoreTokens()) {
                        X500NameTokenizer x500NameTokenizer4 = new X500NameTokenizer(x500NameTokenizer2.nextToken(), '=');
                        String nextToken4 = x500NameTokenizer4.nextToken();
                        if (!x500NameTokenizer4.hasMoreTokens()) {
                            throw new IllegalArgumentException("badly formatted directory string");
                        }
                        String nextToken5 = x500NameTokenizer4.nextToken();
                        vector.addElement(x500NameStyle.attrNameToOID(nextToken4.trim()));
                        vector2.addElement(unescape(nextToken5));
                    }
                    x500NameBuilder.addMultiValuedRDN(toOIDArray(vector), toValueArray(vector2));
                } else {
                    x500NameBuilder.addRDN(attrNameToOID, unescape(nextToken3));
                }
            } else {
                X500NameTokenizer x500NameTokenizer5 = new X500NameTokenizer(nextToken, '=');
                String nextToken6 = x500NameTokenizer5.nextToken();
                if (!x500NameTokenizer5.hasMoreTokens()) {
                    throw new IllegalArgumentException("badly formatted directory string");
                }
                x500NameBuilder.addRDN(x500NameStyle.attrNameToOID(nextToken6.trim()), unescape(x500NameTokenizer5.nextToken()));
            }
        }
        return x500NameBuilder.build().getRDNs();
    }

    private static String[] toValueArray(Vector vector) {
        String[] strArr = new String[vector.size()];
        for (int i = 0; i != strArr.length; i++) {
            strArr[i] = (String) vector.elementAt(i);
        }
        return strArr;
    }

    private static ASN1ObjectIdentifier[] toOIDArray(Vector vector) {
        ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr = new ASN1ObjectIdentifier[vector.size()];
        for (int i = 0; i != aSN1ObjectIdentifierArr.length; i++) {
            aSN1ObjectIdentifierArr[i] = (ASN1ObjectIdentifier) vector.elementAt(i);
        }
        return aSN1ObjectIdentifierArr;
    }

    public static String[] findAttrNamesForOID(ASN1ObjectIdentifier aSN1ObjectIdentifier, Hashtable hashtable) {
        int i = 0;
        Enumeration elements = hashtable.elements();
        while (elements.hasMoreElements()) {
            if (aSN1ObjectIdentifier.equals(elements.nextElement())) {
                i++;
            }
        }
        String[] strArr = new String[i];
        int i2 = 0;
        Enumeration keys = hashtable.keys();
        while (keys.hasMoreElements()) {
            String str = (String) keys.nextElement();
            if (aSN1ObjectIdentifier.equals(hashtable.get(str))) {
                int i3 = i2;
                i2++;
                strArr[i3] = str;
            }
        }
        return strArr;
    }

    public static ASN1ObjectIdentifier decodeAttrName(String str, Hashtable hashtable) {
        if (Strings.toUpperCase(str).startsWith("OID.")) {
            return new ASN1ObjectIdentifier(str.substring(4));
        }
        if (str.charAt(0) < '0' || str.charAt(0) > '9') {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) hashtable.get(Strings.toLowerCase(str));
            if (aSN1ObjectIdentifier == null) {
                throw new IllegalArgumentException("Unknown object id - " + str + " - passed to distinguished name");
            }
            return aSN1ObjectIdentifier;
        }
        return new ASN1ObjectIdentifier(str);
    }

    public static ASN1Encodable valueFromHexString(String str, int i) throws IOException {
        byte[] bArr = new byte[(str.length() - i) / 2];
        for (int i2 = 0; i2 != bArr.length; i2++) {
            bArr[i2] = (byte) ((convertHex(str.charAt((i2 * 2) + i)) << 4) | convertHex(str.charAt((i2 * 2) + i + 1)));
        }
        return ASN1Primitive.fromByteArray(bArr);
    }

    public static void appendRDN(StringBuffer stringBuffer, RDN rdn, Hashtable hashtable) {
        if (!rdn.isMultiValued()) {
            if (rdn.getFirst() != null) {
                appendTypeAndValue(stringBuffer, rdn.getFirst(), hashtable);
                return;
            }
            return;
        }
        AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
        boolean z = true;
        for (int i = 0; i != typesAndValues.length; i++) {
            if (z) {
                z = false;
            } else {
                stringBuffer.append('+');
            }
            appendTypeAndValue(stringBuffer, typesAndValues[i], hashtable);
        }
    }

    public static void appendTypeAndValue(StringBuffer stringBuffer, AttributeTypeAndValue attributeTypeAndValue, Hashtable hashtable) {
        String str = (String) hashtable.get(attributeTypeAndValue.getType());
        if (str != null) {
            stringBuffer.append(str);
        } else {
            stringBuffer.append(attributeTypeAndValue.getType().getId());
        }
        stringBuffer.append('=');
        stringBuffer.append(valueToString(attributeTypeAndValue.getValue()));
    }

    public static String valueToString(ASN1Encodable aSN1Encodable) {
        StringBuffer stringBuffer = new StringBuffer();
        if (!(aSN1Encodable instanceof ASN1String) || (aSN1Encodable instanceof ASN1UniversalString)) {
            try {
                stringBuffer.append('#');
                stringBuffer.append(Hex.toHexString(aSN1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            } catch (IOException e) {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        } else {
            String string = ((ASN1String) aSN1Encodable).getString();
            if (string.length() > 0 && string.charAt(0) == '#') {
                stringBuffer.append('\\');
            }
            stringBuffer.append(string);
        }
        int length = stringBuffer.length();
        int i = 0;
        if (stringBuffer.length() >= 2 && stringBuffer.charAt(0) == '\\' && stringBuffer.charAt(1) == '#') {
            i = 0 + 2;
        }
        while (i != length) {
            switch (stringBuffer.charAt(i)) {
                case Opcode.FLOAD_0 /* 34 */:
                case Opcode.ALOAD_1 /* 43 */:
                case Opcode.ALOAD_2 /* 44 */:
                case Opcode.ISTORE_0 /* 59 */:
                case '<':
                case Opcode.ISTORE_2 /* 61 */:
                case Opcode.ISTORE_3 /* 62 */:
                case Opcode.DUP2 /* 92 */:
                    stringBuffer.insert(i, "\\");
                    i += 2;
                    length++;
                    break;
                default:
                    i++;
                    break;
            }
        }
        if (stringBuffer.length() > 0) {
            for (int i2 = 0; stringBuffer.length() > i2 && stringBuffer.charAt(i2) == ' '; i2 += 2) {
                stringBuffer.insert(i2, "\\");
            }
        }
        for (int length2 = stringBuffer.length() - 1; length2 >= 0 && stringBuffer.charAt(length2) == ' '; length2--) {
            stringBuffer.insert(length2, '\\');
        }
        return stringBuffer.toString();
    }

    public static String canonicalize(String str) {
        if (str.length() > 0 && str.charAt(0) == '#') {
            ASN1Primitive decodeObject = decodeObject(str);
            if (decodeObject instanceof ASN1String) {
                str = ((ASN1String) decodeObject).getString();
            }
        }
        String lowerCase = Strings.toLowerCase(str);
        int length = lowerCase.length();
        if (length < 2) {
            return lowerCase;
        }
        int i = 0;
        int i2 = length - 1;
        while (i < i2 && lowerCase.charAt(i) == '\\' && lowerCase.charAt(i + 1) == ' ') {
            i += 2;
        }
        int i3 = i2;
        int i4 = i + 1;
        while (i3 > i4 && lowerCase.charAt(i3 - 1) == '\\' && lowerCase.charAt(i3) == ' ') {
            i3 -= 2;
        }
        if (i > 0 || i3 < i2) {
            lowerCase = lowerCase.substring(i, i3 + 1);
        }
        return stripInternalSpaces(lowerCase);
    }

    public static String canonicalString(ASN1Encodable aSN1Encodable) {
        return canonicalize(valueToString(aSN1Encodable));
    }

    private static ASN1Primitive decodeObject(String str) {
        try {
            return ASN1Primitive.fromByteArray(Hex.decodeStrict(str, 1, str.length() - 1));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    public static String stripInternalSpaces(String str) {
        if (str.indexOf("  ") < 0) {
            return str;
        }
        StringBuffer stringBuffer = new StringBuffer();
        char charAt = str.charAt(0);
        stringBuffer.append(charAt);
        for (int i = 1; i < str.length(); i++) {
            char charAt2 = str.charAt(i);
            if (charAt != ' ' || charAt2 != ' ') {
                stringBuffer.append(charAt2);
                charAt = charAt2;
            }
        }
        return stringBuffer.toString();
    }

    public static boolean rDNAreEqual(RDN rdn, RDN rdn2) {
        if (rdn.size() != rdn2.size()) {
            return false;
        }
        AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
        AttributeTypeAndValue[] typesAndValues2 = rdn2.getTypesAndValues();
        if (typesAndValues.length != typesAndValues2.length) {
            return false;
        }
        for (int i = 0; i != typesAndValues.length; i++) {
            if (!atvAreEqual(typesAndValues[i], typesAndValues2[i])) {
                return false;
            }
        }
        return true;
    }

    private static boolean atvAreEqual(AttributeTypeAndValue attributeTypeAndValue, AttributeTypeAndValue attributeTypeAndValue2) {
        if (attributeTypeAndValue == attributeTypeAndValue2) {
            return true;
        }
        return null != attributeTypeAndValue && null != attributeTypeAndValue2 && attributeTypeAndValue.getType().equals((ASN1Primitive) attributeTypeAndValue2.getType()) && canonicalString(attributeTypeAndValue.getValue()).equals(canonicalString(attributeTypeAndValue2.getValue()));
    }
}