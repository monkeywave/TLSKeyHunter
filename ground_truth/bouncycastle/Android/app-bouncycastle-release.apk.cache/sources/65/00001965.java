package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.util.Arrays;

/* loaded from: classes.dex */
public class ASN1ObjectIdentifier extends ASN1Primitive {
    private static final long LONG_LIMIT = 72057594037927808L;
    private static final int MAX_CONTENTS_LENGTH = 4096;
    private static final int MAX_IDENTIFIER_LENGTH = 16385;
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectIdentifier.class, 6) { // from class: org.bouncycastle.asn1.ASN1ObjectIdentifier.1
        @Override // org.bouncycastle.asn1.ASN1UniversalType
        ASN1Primitive fromImplicitPrimitive(DEROctetString dEROctetString) {
            return ASN1ObjectIdentifier.createPrimitive(dEROctetString.getOctets(), false);
        }
    };
    private static final ConcurrentMap<OidHandle, ASN1ObjectIdentifier> pool = new ConcurrentHashMap();
    private final byte[] contents;
    private String identifier;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class OidHandle {
        private final byte[] contents;
        private final int key;

        /* JADX INFO: Access modifiers changed from: package-private */
        public OidHandle(byte[] bArr) {
            this.key = Arrays.hashCode(bArr);
            this.contents = bArr;
        }

        public boolean equals(Object obj) {
            if (obj instanceof OidHandle) {
                return Arrays.areEqual(this.contents, ((OidHandle) obj).contents);
            }
            return false;
        }

        public int hashCode() {
            return this.key;
        }
    }

    public ASN1ObjectIdentifier(String str) {
        checkIdentifier(str);
        byte[] parseIdentifier = parseIdentifier(str);
        checkContentsLength(parseIdentifier.length);
        this.contents = parseIdentifier;
        this.identifier = str;
    }

    private ASN1ObjectIdentifier(byte[] bArr, String str) {
        this.contents = bArr;
        this.identifier = str;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkContentsLength(int i) {
        if (i > 4096) {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
    }

    static void checkIdentifier(String str) {
        if (str == null) {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (str.length() > MAX_IDENTIFIER_LENGTH) {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        if (!isValidIdentifier(str)) {
            throw new IllegalArgumentException("string " + str + " not a valid OID");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier createPrimitive(byte[] bArr, boolean z) {
        checkContentsLength(bArr.length);
        ASN1ObjectIdentifier aSN1ObjectIdentifier = pool.get(new OidHandle(bArr));
        if (aSN1ObjectIdentifier != null) {
            return aSN1ObjectIdentifier;
        }
        if (ASN1RelativeOID.isValidContents(bArr)) {
            if (z) {
                bArr = Arrays.clone(bArr);
            }
            return new ASN1ObjectIdentifier(bArr, null);
        }
        throw new IllegalArgumentException("invalid OID contents");
    }

    public static ASN1ObjectIdentifier fromContents(byte[] bArr) {
        if (bArr != null) {
            return createPrimitive(bArr, true);
        }
        throw new NullPointerException("'contents' cannot be null");
    }

    public static ASN1ObjectIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1ObjectIdentifier)) {
            return (ASN1ObjectIdentifier) obj;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Primitive aSN1Primitive = ((ASN1Encodable) obj).toASN1Primitive();
            if (aSN1Primitive instanceof ASN1ObjectIdentifier) {
                return (ASN1ObjectIdentifier) aSN1Primitive;
            }
        } else if (obj instanceof byte[]) {
            try {
                return (ASN1ObjectIdentifier) TYPE.fromByteArray((byte[]) obj);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        if (!z && !aSN1TaggedObject.isParsed() && aSN1TaggedObject.hasContextTag()) {
            ASN1Primitive aSN1Primitive = aSN1TaggedObject.getBaseObject().toASN1Primitive();
            if (!(aSN1Primitive instanceof ASN1ObjectIdentifier)) {
                return fromContents(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
            }
        }
        return (ASN1ObjectIdentifier) TYPE.getContextInstance(aSN1TaggedObject, z);
    }

    private static boolean isValidIdentifier(String str) {
        char charAt;
        if (str.length() < 3 || str.charAt(1) != '.' || (charAt = str.charAt(0)) < '0' || charAt > '2' || !ASN1RelativeOID.isValidIdentifier(str, 2)) {
            return false;
        }
        if (charAt == '2' || str.length() == 3 || str.charAt(3) == '.') {
            return true;
        }
        return (str.length() == 4 || str.charAt(4) == '.') && str.charAt(2) < '4';
    }

    private static String parseContents(byte[] bArr) {
        StringBuilder sb = new StringBuilder();
        boolean z = true;
        BigInteger bigInteger = null;
        long j = 0;
        for (int i = 0; i != bArr.length; i++) {
            byte b = bArr[i];
            if (j <= LONG_LIMIT) {
                long j2 = j + (b & ByteCompanionObject.MAX_VALUE);
                if ((b & ByteCompanionObject.MIN_VALUE) == 0) {
                    if (z) {
                        if (j2 < 40) {
                            sb.append('0');
                        } else if (j2 < 80) {
                            sb.append('1');
                            j2 -= 40;
                        } else {
                            sb.append('2');
                            j2 -= 80;
                        }
                        z = false;
                    }
                    sb.append('.');
                    sb.append(j2);
                    j = 0;
                } else {
                    j = j2 << 7;
                }
            } else {
                if (bigInteger == null) {
                    bigInteger = BigInteger.valueOf(j);
                }
                BigInteger or = bigInteger.or(BigInteger.valueOf(b & ByteCompanionObject.MAX_VALUE));
                if ((b & ByteCompanionObject.MIN_VALUE) == 0) {
                    if (z) {
                        sb.append('2');
                        or = or.subtract(BigInteger.valueOf(80L));
                        z = false;
                    }
                    sb.append('.');
                    sb.append(or);
                    bigInteger = null;
                    j = 0;
                } else {
                    bigInteger = or.shiftLeft(7);
                }
            }
        }
        return sb.toString();
    }

    private static byte[] parseIdentifier(String str) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        OIDTokenizer oIDTokenizer = new OIDTokenizer(str);
        int parseInt = Integer.parseInt(oIDTokenizer.nextToken()) * 40;
        String nextToken = oIDTokenizer.nextToken();
        if (nextToken.length() <= 18) {
            ASN1RelativeOID.writeField(byteArrayOutputStream, parseInt + Long.parseLong(nextToken));
        } else {
            ASN1RelativeOID.writeField(byteArrayOutputStream, new BigInteger(nextToken).add(BigInteger.valueOf(parseInt)));
        }
        while (oIDTokenizer.hasMoreTokens()) {
            String nextToken2 = oIDTokenizer.nextToken();
            if (nextToken2.length() <= 18) {
                ASN1RelativeOID.writeField(byteArrayOutputStream, Long.parseLong(nextToken2));
            } else {
                ASN1RelativeOID.writeField(byteArrayOutputStream, new BigInteger(nextToken2));
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static ASN1ObjectIdentifier tryFromID(String str) {
        if (str != null) {
            if (str.length() > MAX_IDENTIFIER_LENGTH || !isValidIdentifier(str)) {
                return null;
            }
            byte[] parseIdentifier = parseIdentifier(str);
            if (parseIdentifier.length <= 4096) {
                return new ASN1ObjectIdentifier(parseIdentifier, str);
            }
            return null;
        }
        throw new NullPointerException("'identifier' cannot be null");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        if (this == aSN1Primitive) {
            return true;
        }
        if (aSN1Primitive instanceof ASN1ObjectIdentifier) {
            return Arrays.areEqual(this.contents, ((ASN1ObjectIdentifier) aSN1Primitive).contents);
        }
        return false;
    }

    public ASN1ObjectIdentifier branch(String str) {
        byte[] concatenate;
        ASN1RelativeOID.checkIdentifier(str);
        if (str.length() <= 2) {
            checkContentsLength(this.contents.length + 1);
            int charAt = str.charAt(0) - '0';
            if (str.length() == 2) {
                charAt = (charAt * 10) + (str.charAt(1) - '0');
            }
            concatenate = Arrays.append(this.contents, (byte) charAt);
        } else {
            byte[] parseIdentifier = ASN1RelativeOID.parseIdentifier(str);
            checkContentsLength(this.contents.length + parseIdentifier.length);
            concatenate = Arrays.concatenate(this.contents, parseIdentifier);
        }
        return new ASN1ObjectIdentifier(concatenate, getId() + "." + str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public void encode(ASN1OutputStream aSN1OutputStream, boolean z) throws IOException {
        aSN1OutputStream.writeEncodingDL(z, 6, this.contents);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public boolean encodeConstructed() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.bouncycastle.asn1.ASN1Primitive
    public int encodedLength(boolean z) {
        return ASN1OutputStream.getLengthOfEncodingDL(z, this.contents.length);
    }

    public synchronized String getId() {
        if (this.identifier == null) {
            this.identifier = parseContents(this.contents);
        }
        return this.identifier;
    }

    @Override // org.bouncycastle.asn1.ASN1Primitive, org.bouncycastle.asn1.ASN1Object
    public int hashCode() {
        return Arrays.hashCode(this.contents);
    }

    public ASN1ObjectIdentifier intern() {
        OidHandle oidHandle = new OidHandle(this.contents);
        ConcurrentMap<OidHandle, ASN1ObjectIdentifier> concurrentMap = pool;
        ASN1ObjectIdentifier aSN1ObjectIdentifier = concurrentMap.get(oidHandle);
        if (aSN1ObjectIdentifier == null) {
            synchronized (concurrentMap) {
                if (concurrentMap.containsKey(oidHandle)) {
                    return concurrentMap.get(oidHandle);
                }
                concurrentMap.put(oidHandle, this);
                return this;
            }
        }
        return aSN1ObjectIdentifier;
    }

    /* renamed from: on */
    public boolean m147on(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        byte[] bArr = this.contents;
        byte[] bArr2 = aSN1ObjectIdentifier.contents;
        int length = bArr2.length;
        return bArr.length > length && Arrays.areEqual(bArr, 0, length, bArr2, 0, length);
    }

    public String toString() {
        return getId();
    }
}