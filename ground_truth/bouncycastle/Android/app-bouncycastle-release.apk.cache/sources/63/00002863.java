package org.bouncycastle.oer.its.etsi103097.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

/* loaded from: classes2.dex */
public class EtsiOriginatingHeaderInfoExtension extends Extension {

    /* loaded from: classes2.dex */
    public static class Builder {
        private ASN1Encodable encodable;

        /* renamed from: id */
        private ExtId f1155id;

        public EtsiOriginatingHeaderInfoExtension createEtsiOriginatingHeaderInfoExtension() {
            return new EtsiOriginatingHeaderInfoExtension(this.f1155id, this.encodable);
        }

        public Builder setEncodable(ASN1Encodable aSN1Encodable) {
            this.encodable = aSN1Encodable;
            return this;
        }

        public Builder setEtsiTs102941CrlRequest(EtsiTs102941CrlRequest etsiTs102941CrlRequest) {
            this.f1155id = Extension.etsiTs102941CrlRequestId;
            this.encodable = etsiTs102941CrlRequest;
            return this;
        }

        public Builder setEtsiTs102941DeltaCtlRequest(EtsiTs102941DeltaCtlRequest etsiTs102941DeltaCtlRequest) {
            this.f1155id = Extension.etsiTs102941DeltaCtlRequestId;
            this.encodable = etsiTs102941DeltaCtlRequest;
            return this;
        }

        public Builder setId(ExtId extId) {
            this.f1155id = extId;
            return this;
        }
    }

    private EtsiOriginatingHeaderInfoExtension(ASN1Sequence aSN1Sequence) {
        super(aSN1Sequence);
    }

    public EtsiOriginatingHeaderInfoExtension(ExtId extId, ASN1Encodable aSN1Encodable) {
        super(extId, aSN1Encodable);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static EtsiOriginatingHeaderInfoExtension getInstance(Object obj) {
        if (obj instanceof EtsiOriginatingHeaderInfoExtension) {
            return (EtsiOriginatingHeaderInfoExtension) obj;
        }
        if (obj != null) {
            return new EtsiOriginatingHeaderInfoExtension(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public EtsiTs102941CrlRequest getEtsiTs102941CrlRequest() {
        return EtsiTs102941CrlRequest.getInstance(getContent());
    }

    public EtsiTs102941DeltaCtlRequest getEtsiTs102941DeltaCtlRequest() {
        return EtsiTs102941DeltaCtlRequest.getInstance((Object) getContent());
    }
}