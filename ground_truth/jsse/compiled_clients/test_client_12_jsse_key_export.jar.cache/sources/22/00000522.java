package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/gcm/Tables1kGCMExponentiator.class */
public class Tables1kGCMExponentiator implements GCMExponentiator {
    private Vector lookupPowX2;

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void init(byte[] bArr) {
        long[] asLongs = GCMUtil.asLongs(bArr);
        if (this.lookupPowX2 == null || 0 == GCMUtil.areEqual(asLongs, (long[]) this.lookupPowX2.elementAt(0))) {
            this.lookupPowX2 = new Vector(8);
            this.lookupPowX2.addElement(asLongs);
        }
    }

    @Override // org.bouncycastle.crypto.modes.gcm.GCMExponentiator
    public void exponentiateX(long j, byte[] bArr) {
        long[] oneAsLongs = GCMUtil.oneAsLongs();
        int i = 0;
        while (j > 0) {
            if ((j & 1) != 0) {
                ensureAvailable(i);
                GCMUtil.multiply(oneAsLongs, (long[]) this.lookupPowX2.elementAt(i));
            }
            i++;
            j >>>= 1;
        }
        GCMUtil.asBytes(oneAsLongs, bArr);
    }

    private void ensureAvailable(int i) {
        int size = this.lookupPowX2.size() - 1;
        if (size < i) {
            long[] jArr = (long[]) this.lookupPowX2.elementAt(size);
            do {
                long[] jArr2 = new long[2];
                GCMUtil.square(jArr, jArr2);
                this.lookupPowX2.addElement(jArr2);
                jArr = jArr2;
                size++;
            } while (size < i);
        }
    }
}