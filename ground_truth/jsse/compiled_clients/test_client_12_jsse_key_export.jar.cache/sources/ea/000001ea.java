package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import javassist.bytecode.Opcode;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1RelativeOID.class */
public class ASN1RelativeOID extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1RelativeOID.class, 13) { // from class: org.bouncycastle.asn1.ASN1RelativeOID.1
        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1RelativeOID.createPrimitive(dEROctetString.getOctets(), false);
        }
    };
    private static final long LONG_LIMIT = 72057594037927808L;
    private final String identifier;
    private byte[] contents;

    public static ASN1RelativeOID fromContents(byte[] bArr) {
        return createPrimitive(bArr, true);
    }

    public static ASN1RelativeOID getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1RelativeOID)) {
            return (ASN1RelativeOID) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1RelativeOID) {
                return (ASN1RelativeOID) aSN1Primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1RelativeOID) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct relative OID from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1RelativeOID getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return (ASN1RelativeOID) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    public ASN1RelativeOID(String str) {
        if (str == null) {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (!isValidIdentifier(str, 0)) {
            throw new IllegalArgumentException("string " + str + " not a relative OID");
        }
        this.identifier = str;
    }

    ASN1RelativeOID(ASN1RelativeOID aSN1RelativeOID, String str) {
        if (!isValidIdentifier(str, 0)) {
            throw new IllegalArgumentException("string " + str + " not a valid OID branch");
        }
        this.identifier = aSN1RelativeOID.getId() + "." + str;
    }

    private ASN1RelativeOID(byte[] bArr, boolean z) {
        StringBuffer stringBuffer = new StringBuffer();
        long j = 0;
        BigInteger bigInteger = null;
        boolean z2 = true;
        for (int i = 0; i != bArr.length; i++) {
            int i2 = bArr[i] & 255;
            if (j <= LONG_LIMIT) {
                long j2 = j + (i2 & Opcode.LAND);
                if ((i2 & 128) == 0) {
                    if (z2) {
                        z2 = false;
                    } else {
                        stringBuffer.append('.');
                    }
                    stringBuffer.append(j2);
                    j = 0;
                } else {
                    j = j2 << 7;
                }
            } else {
                BigInteger or = (bigInteger == null ? BigInteger.valueOf(j) : bigInteger).or(BigInteger.valueOf(i2 & Opcode.LAND));
                if ((i2 & 128) == 0) {
                    if (z2) {
                        z2 = false;
                    } else {
                        stringBuffer.append('.');
                    }
                    stringBuffer.append(or);
                    bigInteger = null;
                    j = 0;
                } else {
                    bigInteger = or.shiftLeft(7);
                }
            }
        }
        this.identifier = stringBuffer.toString();
        this.contents = z ? Arrays.clone(bArr) : bArr;
    }

    public ASN1RelativeOID branch(String str) {
        return new ASN1RelativeOID(this, str);
    }

    public String getId() {
        return this.identifier;
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        return this.identifier.hashCode();
    }

    public String toString() {
        return getId();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (this == aSN1Primitive) {
            return true;
        }
        if (aSN1Primitive instanceof ASN1RelativeOID) {
            return this.identifier.equals(((ASN1RelativeOID) aSN1Primitive).identifier);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) {
        return ASN1OutputStream.getLengthOfEncodingDL(z, getContents().length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 13, getContents());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    private void doOutput(ByteArrayOutputStream byteArrayOutputStream) {
        OIDTokenizer oIDTokenizer = new OIDTokenizer(this.identifier);
        while (oIDTokenizer.hasMoreTokens()) {
            String nextToken = oIDTokenizer.nextToken();
            if (nextToken.length() <= 18) {
                writeField(byteArrayOutputStream, Long.parseLong(nextToken));
            } else {
                writeField(byteArrayOutputStream, new BigInteger(nextToken));
            }
        }
    }

    private synchronized byte[] getContents() {
        if (this.contents == null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            doOutput(byteArrayOutputStream);
            this.contents = byteArrayOutputStream.toByteArray();
        }
        return this.contents;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1RelativeOID createPrimitive(byte[] bArr, boolean z) {
        return new ASN1RelativeOID(bArr, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isValidIdentifier(String str, int i) {
        int i2 = 0;
        int length = str.length();
        while (true) {
            length--;
            if (length < i) {
                if (0 != i2) {
                    return i2 <= 1 || str.charAt(length + 1) != '0';
                }
                return false;
            }
            char charAt = str.charAt(length);
            if (charAt == '.') {
                if (0 == i2) {
                    return false;
                }
                if (i2 > 1 && str.charAt(length + 1) == '0') {
                    return false;
                }
                i2 = 0;
            } else if ('0' > charAt || charAt > '9') {
                return false;
            } else {
                i2++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void writeField(ByteArrayOutputStream byteArrayOutputStream, long j) {
        byte[] bArr = new byte[9];
        int i = 8;
        bArr[8] = (byte) (((int) j) & Opcode.LAND);
        while (j >= 128) {
            j >>= 7;
            i--;
            bArr[i] = (byte) (((int) j) | 128);
        }
        byteArrayOutputStream.write(bArr, i, 9 - i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void writeField(ByteArrayOutputStream byteArrayOutputStream, BigInteger bigInteger) {
        int bitLength = (bigInteger.bitLength() + 6) / 7;
        if (bitLength == 0) {
            byteArrayOutputStream.write(0);
            return;
        }
        BigInteger bigInteger2 = bigInteger;
        byte[] bArr = new byte[bitLength];
        for (int i = bitLength - 1; i >= 0; i--) {
            bArr[i] = (byte) (bigInteger2.intValue() | 128);
            bigInteger2 = bigInteger2.shiftRight(7);
        }
        int i2 = bitLength - 1;
        bArr[i2] = (byte) (bArr[i2] & Byte.MAX_VALUE);
        byteArrayOutputStream.write(bArr, 0, bArr.length);
    }
}