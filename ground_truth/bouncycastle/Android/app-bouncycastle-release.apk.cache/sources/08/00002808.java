package org.bouncycastle.oer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;

/* loaded from: classes2.dex */
public abstract class SwitchIndexer {

    /* loaded from: classes2.dex */
    public static class Asn1EncodableVectorIndexer extends SwitchIndexer {
        private final ASN1EncodableVector asn1EncodableVector;

        public Asn1EncodableVectorIndexer(ASN1EncodableVector aSN1EncodableVector) {
            this.asn1EncodableVector = aSN1EncodableVector;
        }

        @Override // org.bouncycastle.oer.SwitchIndexer
        public ASN1Encodable get(int i) {
            return this.asn1EncodableVector.get(i);
        }
    }

    /* loaded from: classes2.dex */
    public static class Asn1SequenceIndexer extends SwitchIndexer {
        private final ASN1Sequence sequence;

        public Asn1SequenceIndexer(ASN1Sequence aSN1Sequence) {
            this.sequence = aSN1Sequence;
        }

        @Override // org.bouncycastle.oer.SwitchIndexer
        public ASN1Encodable get(int i) {
            return this.sequence.getObjectAt(i);
        }
    }

    /* loaded from: classes2.dex */
    public static class FixedValueIndexer extends SwitchIndexer {
        private final ASN1Encodable returnValue;

        public FixedValueIndexer(ASN1Encodable aSN1Encodable) {
            this.returnValue = aSN1Encodable;
        }

        @Override // org.bouncycastle.oer.SwitchIndexer
        public ASN1Encodable get(int i) {
            return this.returnValue;
        }
    }

    public abstract ASN1Encodable get(int i);
}