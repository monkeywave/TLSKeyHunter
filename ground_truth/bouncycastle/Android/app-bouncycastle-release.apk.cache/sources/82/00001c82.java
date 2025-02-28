package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class JPAKERound3Payload {
    private final BigInteger macTag;
    private final String participantId;

    public JPAKERound3Payload(String str, BigInteger bigInteger) {
        this.participantId = str;
        this.macTag = bigInteger;
    }

    public BigInteger getMacTag() {
        return this.macTag;
    }

    public String getParticipantId() {
        return this.participantId;
    }
}