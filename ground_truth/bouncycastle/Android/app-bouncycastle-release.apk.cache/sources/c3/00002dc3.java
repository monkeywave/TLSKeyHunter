package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class TrustedAuthority {
    protected Object identifier;
    protected short identifierType;

    public TrustedAuthority(short s, Object obj) {
        if (!isCorrectType(s, obj)) {
            throw new IllegalArgumentException("'identifier' is not an instance of the correct type");
        }
        this.identifierType = s;
        this.identifier = obj;
    }

    protected static boolean isCorrectType(short s, Object obj) {
        if (s == 0) {
            return obj == null;
        }
        if (s != 1) {
            if (s == 2) {
                return obj instanceof X500Name;
            }
            if (s != 3) {
                throw new IllegalArgumentException("'identifierType' is an unsupported IdentifierType");
            }
        }
        return isSHA1Hash(obj);
    }

    protected static boolean isSHA1Hash(Object obj) {
        return (obj instanceof byte[]) && ((byte[]) obj).length == 20;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v6, types: [org.bouncycastle.asn1.x500.X500Name, org.bouncycastle.asn1.ASN1Object] */
    public static TrustedAuthority parse(InputStream inputStream) throws IOException {
        byte[] bArr;
        short readUint8 = TlsUtils.readUint8(inputStream);
        if (readUint8 != 0) {
            if (readUint8 != 1) {
                if (readUint8 == 2) {
                    byte[] readOpaque16 = TlsUtils.readOpaque16(inputStream, 1);
                    ?? x500Name = X500Name.getInstance(TlsUtils.readASN1Object(readOpaque16));
                    TlsUtils.requireDEREncoding(x500Name, readOpaque16);
                    bArr = x500Name;
                } else if (readUint8 != 3) {
                    throw new TlsFatalAlert((short) 50);
                }
            }
            bArr = TlsUtils.readFully(20, inputStream);
        } else {
            bArr = null;
        }
        return new TrustedAuthority(readUint8, bArr);
    }

    protected void checkCorrectType(short s) {
        if (this.identifierType != s || !isCorrectType(s, this.identifier)) {
            throw new IllegalStateException("TrustedAuthority is not of type " + IdentifierType.getName(s));
        }
    }

    public void encode(OutputStream outputStream) throws IOException {
        TlsUtils.writeUint8(this.identifierType, outputStream);
        short s = this.identifierType;
        if (s != 0) {
            if (s != 1) {
                if (s == 2) {
                    TlsUtils.writeOpaque16(((X500Name) this.identifier).getEncoded(ASN1Encoding.DER), outputStream);
                    return;
                } else if (s != 3) {
                    throw new TlsFatalAlert((short) 80);
                }
            }
            outputStream.write((byte[]) this.identifier);
        }
    }

    public byte[] getCertSHA1Hash() {
        return Arrays.clone((byte[]) this.identifier);
    }

    public Object getIdentifier() {
        return this.identifier;
    }

    public short getIdentifierType() {
        return this.identifierType;
    }

    public byte[] getKeySHA1Hash() {
        return Arrays.clone((byte[]) this.identifier);
    }

    public X500Name getX509Name() {
        checkCorrectType((short) 2);
        return (X500Name) this.identifier;
    }
}