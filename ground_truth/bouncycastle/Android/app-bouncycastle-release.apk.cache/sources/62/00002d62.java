package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
public class OCSPStatusRequest {
    protected Extensions requestExtensions;
    protected Vector responderIDList;

    public OCSPStatusRequest(Vector vector, Extensions extensions) {
        this.responderIDList = vector;
        this.requestExtensions = extensions;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0031  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static org.bouncycastle.tls.OCSPStatusRequest parse(java.io.InputStream r4) throws java.io.IOException {
        /*
            java.util.Vector r0 = new java.util.Vector
            r0.<init>()
            byte[] r1 = org.bouncycastle.tls.TlsUtils.readOpaque16(r4)
            int r2 = r1.length
            if (r2 <= 0) goto L2a
            java.io.ByteArrayInputStream r2 = new java.io.ByteArrayInputStream
            r2.<init>(r1)
        L11:
            r1 = 1
            byte[] r1 = org.bouncycastle.tls.TlsUtils.readOpaque16(r2, r1)
            org.bouncycastle.asn1.ASN1Primitive r3 = org.bouncycastle.tls.TlsUtils.readASN1Object(r1)
            org.bouncycastle.asn1.ocsp.ResponderID r3 = org.bouncycastle.asn1.ocsp.ResponderID.getInstance(r3)
            org.bouncycastle.tls.TlsUtils.requireDEREncoding(r3, r1)
            r0.addElement(r3)
            int r1 = r2.available()
            if (r1 > 0) goto L11
        L2a:
            byte[] r4 = org.bouncycastle.tls.TlsUtils.readOpaque16(r4)
            int r1 = r4.length
            if (r1 <= 0) goto L3d
            org.bouncycastle.asn1.ASN1Primitive r1 = org.bouncycastle.tls.TlsUtils.readASN1Object(r4)
            org.bouncycastle.asn1.x509.Extensions r1 = org.bouncycastle.asn1.x509.Extensions.getInstance(r1)
            org.bouncycastle.tls.TlsUtils.requireDEREncoding(r1, r4)
            goto L3e
        L3d:
            r1 = 0
        L3e:
            org.bouncycastle.tls.OCSPStatusRequest r4 = new org.bouncycastle.tls.OCSPStatusRequest
            r4.<init>(r0, r1)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.OCSPStatusRequest.parse(java.io.InputStream):org.bouncycastle.tls.OCSPStatusRequest");
    }

    public void encode(OutputStream outputStream) throws IOException {
        Vector vector = this.responderIDList;
        if (vector == null || vector.isEmpty()) {
            TlsUtils.writeUint16(0, outputStream);
        } else {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            for (int i = 0; i < this.responderIDList.size(); i++) {
                TlsUtils.writeOpaque16(((ResponderID) this.responderIDList.elementAt(i)).getEncoded(ASN1Encoding.DER), byteArrayOutputStream);
            }
            TlsUtils.checkUint16(byteArrayOutputStream.size());
            TlsUtils.writeUint16(byteArrayOutputStream.size(), outputStream);
            Streams.writeBufTo(byteArrayOutputStream, outputStream);
        }
        Extensions extensions = this.requestExtensions;
        if (extensions == null) {
            TlsUtils.writeUint16(0, outputStream);
            return;
        }
        byte[] encoded = extensions.getEncoded(ASN1Encoding.DER);
        TlsUtils.checkUint16(encoded.length);
        TlsUtils.writeUint16(encoded.length, outputStream);
        outputStream.write(encoded);
    }

    public Extensions getRequestExtensions() {
        return this.requestExtensions;
    }

    public Vector getResponderIDList() {
        return this.responderIDList;
    }
}