package org.bouncycastle.oer.its;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class ItsUtils {
    @Deprecated
    public static <T> List<T> fillList(final Class<T> cls, final ASN1Sequence aSN1Sequence) {
        return (List) AccessController.doPrivileged(new PrivilegedAction<List<T>>() { // from class: org.bouncycastle.oer.its.ItsUtils.1
            @Override // java.security.PrivilegedAction
            public List<T> run() {
                try {
                    ArrayList arrayList = new ArrayList();
                    Iterator<ASN1Encodable> it = ASN1Sequence.this.iterator();
                    while (it.hasNext()) {
                        arrayList.add(cls.cast(cls.getMethod("getInstance", Object.class).invoke(null, it.next())));
                    }
                    return arrayList;
                } catch (Exception e) {
                    throw new IllegalStateException("could not invoke getInstance on type " + e.getMessage(), e);
                }
            }
        });
    }

    public static byte[] octetStringFixed(byte[] bArr) {
        if (bArr.length < 1 || bArr.length > 32) {
            throw new IllegalArgumentException("octet string out of range");
        }
        return Arrays.clone(bArr);
    }

    public static byte[] octetStringFixed(byte[] bArr, int i) {
        if (bArr.length == i) {
            return bArr;
        }
        throw new IllegalArgumentException("octet string out of range");
    }

    public static ASN1Sequence toSequence(List list) {
        return new DERSequence((ASN1Encodable[]) list.toArray(new ASN1Encodable[0]));
    }

    public static ASN1Sequence toSequence(ASN1Encodable... aSN1EncodableArr) {
        return new DERSequence(aSN1EncodableArr);
    }
}