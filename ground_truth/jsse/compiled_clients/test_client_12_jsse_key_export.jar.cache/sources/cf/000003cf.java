package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/jpake/JPAKEParticipant.class */
public class JPAKEParticipant {
    public static final int STATE_INITIALIZED = 0;
    public static final int STATE_ROUND_1_CREATED = 10;
    public static final int STATE_ROUND_1_VALIDATED = 20;
    public static final int STATE_ROUND_2_CREATED = 30;
    public static final int STATE_ROUND_2_VALIDATED = 40;
    public static final int STATE_KEY_CALCULATED = 50;
    public static final int STATE_ROUND_3_CREATED = 60;
    public static final int STATE_ROUND_3_VALIDATED = 70;
    private final String participantId;
    private char[] password;
    private final Digest digest;
    private final SecureRandom random;

    /* renamed from: p */
    private final BigInteger f93p;

    /* renamed from: q */
    private final BigInteger f94q;

    /* renamed from: g */
    private final BigInteger f95g;
    private String partnerParticipantId;

    /* renamed from: x1 */
    private BigInteger f96x1;

    /* renamed from: x2 */
    private BigInteger f97x2;
    private BigInteger gx1;
    private BigInteger gx2;
    private BigInteger gx3;
    private BigInteger gx4;

    /* renamed from: b */
    private BigInteger f98b;
    private int state;

    public JPAKEParticipant(String str, char[] cArr) {
        this(str, cArr, JPAKEPrimeOrderGroups.NIST_3072);
    }

    public JPAKEParticipant(String str, char[] cArr, JPAKEPrimeOrderGroup jPAKEPrimeOrderGroup) {
        this(str, cArr, jPAKEPrimeOrderGroup, new SHA256Digest(), CryptoServicesRegistrar.getSecureRandom());
    }

    public JPAKEParticipant(String str, char[] cArr, JPAKEPrimeOrderGroup jPAKEPrimeOrderGroup, Digest digest, SecureRandom secureRandom) {
        JPAKEUtil.validateNotNull(str, "participantId");
        JPAKEUtil.validateNotNull(cArr, "password");
        JPAKEUtil.validateNotNull(jPAKEPrimeOrderGroup, "p");
        JPAKEUtil.validateNotNull(digest, "digest");
        JPAKEUtil.validateNotNull(secureRandom, "random");
        if (cArr.length == 0) {
            throw new IllegalArgumentException("Password must not be empty.");
        }
        this.participantId = str;
        this.password = Arrays.copyOf(cArr, cArr.length);
        this.f93p = jPAKEPrimeOrderGroup.getP();
        this.f94q = jPAKEPrimeOrderGroup.getQ();
        this.f95g = jPAKEPrimeOrderGroup.getG();
        this.digest = digest;
        this.random = secureRandom;
        this.state = 0;
    }

    public int getState() {
        return this.state;
    }

    public JPAKERound1Payload createRound1PayloadToSend() {
        if (this.state >= 10) {
            throw new IllegalStateException("Round1 payload already created for " + this.participantId);
        }
        this.f96x1 = JPAKEUtil.generateX1(this.f94q, this.random);
        this.f97x2 = JPAKEUtil.generateX2(this.f94q, this.random);
        this.gx1 = JPAKEUtil.calculateGx(this.f93p, this.f95g, this.f96x1);
        this.gx2 = JPAKEUtil.calculateGx(this.f93p, this.f95g, this.f97x2);
        BigInteger[] calculateZeroKnowledgeProof = JPAKEUtil.calculateZeroKnowledgeProof(this.f93p, this.f94q, this.f95g, this.gx1, this.f96x1, this.participantId, this.digest, this.random);
        BigInteger[] calculateZeroKnowledgeProof2 = JPAKEUtil.calculateZeroKnowledgeProof(this.f93p, this.f94q, this.f95g, this.gx2, this.f97x2, this.participantId, this.digest, this.random);
        this.state = 10;
        return new JPAKERound1Payload(this.participantId, this.gx1, this.gx2, calculateZeroKnowledgeProof, calculateZeroKnowledgeProof2);
    }

    public void validateRound1PayloadReceived(JPAKERound1Payload jPAKERound1Payload) throws CryptoException {
        if (this.state >= 20) {
            throw new IllegalStateException("Validation already attempted for round1 payload for" + this.participantId);
        }
        this.partnerParticipantId = jPAKERound1Payload.getParticipantId();
        this.gx3 = jPAKERound1Payload.getGx1();
        this.gx4 = jPAKERound1Payload.getGx2();
        BigInteger[] knowledgeProofForX1 = jPAKERound1Payload.getKnowledgeProofForX1();
        BigInteger[] knowledgeProofForX2 = jPAKERound1Payload.getKnowledgeProofForX2();
        JPAKEUtil.validateParticipantIdsDiffer(this.participantId, jPAKERound1Payload.getParticipantId());
        JPAKEUtil.validateGx4(this.gx4);
        JPAKEUtil.validateZeroKnowledgeProof(this.f93p, this.f94q, this.f95g, this.gx3, knowledgeProofForX1, jPAKERound1Payload.getParticipantId(), this.digest);
        JPAKEUtil.validateZeroKnowledgeProof(this.f93p, this.f94q, this.f95g, this.gx4, knowledgeProofForX2, jPAKERound1Payload.getParticipantId(), this.digest);
        this.state = 20;
    }

    public JPAKERound2Payload createRound2PayloadToSend() {
        if (this.state >= 30) {
            throw new IllegalStateException("Round2 payload already created for " + this.participantId);
        }
        if (this.state < 20) {
            throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
        }
        BigInteger calculateGA = JPAKEUtil.calculateGA(this.f93p, this.gx1, this.gx3, this.gx4);
        BigInteger calculateX2s = JPAKEUtil.calculateX2s(this.f94q, this.f97x2, JPAKEUtil.calculateS(this.password));
        BigInteger calculateA = JPAKEUtil.calculateA(this.f93p, this.f94q, calculateGA, calculateX2s);
        BigInteger[] calculateZeroKnowledgeProof = JPAKEUtil.calculateZeroKnowledgeProof(this.f93p, this.f94q, calculateGA, calculateA, calculateX2s, this.participantId, this.digest, this.random);
        this.state = 30;
        return new JPAKERound2Payload(this.participantId, calculateA, calculateZeroKnowledgeProof);
    }

    public void validateRound2PayloadReceived(JPAKERound2Payload jPAKERound2Payload) throws CryptoException {
        if (this.state >= 40) {
            throw new IllegalStateException("Validation already attempted for round2 payload for" + this.participantId);
        }
        if (this.state < 20) {
            throw new IllegalStateException("Round1 payload must be validated prior to validating Round2 payload for " + this.participantId);
        }
        BigInteger calculateGA = JPAKEUtil.calculateGA(this.f93p, this.gx3, this.gx1, this.gx2);
        this.f98b = jPAKERound2Payload.getA();
        BigInteger[] knowledgeProofForX2s = jPAKERound2Payload.getKnowledgeProofForX2s();
        JPAKEUtil.validateParticipantIdsDiffer(this.participantId, jPAKERound2Payload.getParticipantId());
        JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, jPAKERound2Payload.getParticipantId());
        JPAKEUtil.validateGa(calculateGA);
        JPAKEUtil.validateZeroKnowledgeProof(this.f93p, this.f94q, calculateGA, this.f98b, knowledgeProofForX2s, jPAKERound2Payload.getParticipantId(), this.digest);
        this.state = 40;
    }

    public BigInteger calculateKeyingMaterial() {
        if (this.state >= 50) {
            throw new IllegalStateException("Key already calculated for " + this.participantId);
        }
        if (this.state < 40) {
            throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + this.participantId);
        }
        BigInteger calculateS = JPAKEUtil.calculateS(this.password);
        Arrays.fill(this.password, (char) 0);
        this.password = null;
        BigInteger calculateKeyingMaterial = JPAKEUtil.calculateKeyingMaterial(this.f93p, this.f94q, this.gx4, this.f97x2, calculateS, this.f98b);
        this.f96x1 = null;
        this.f97x2 = null;
        this.f98b = null;
        this.state = 50;
        return calculateKeyingMaterial;
    }

    public JPAKERound3Payload createRound3PayloadToSend(BigInteger bigInteger) {
        if (this.state >= 60) {
            throw new IllegalStateException("Round3 payload already created for " + this.participantId);
        }
        if (this.state < 50) {
            throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
        }
        BigInteger calculateMacTag = JPAKEUtil.calculateMacTag(this.participantId, this.partnerParticipantId, this.gx1, this.gx2, this.gx3, this.gx4, bigInteger, this.digest);
        this.state = 60;
        return new JPAKERound3Payload(this.participantId, calculateMacTag);
    }

    public void validateRound3PayloadReceived(JPAKERound3Payload jPAKERound3Payload, BigInteger bigInteger) throws CryptoException {
        if (this.state >= 70) {
            throw new IllegalStateException("Validation already attempted for round3 payload for" + this.participantId);
        }
        if (this.state < 50) {
            throw new IllegalStateException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
        }
        JPAKEUtil.validateParticipantIdsDiffer(this.participantId, jPAKERound3Payload.getParticipantId());
        JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, jPAKERound3Payload.getParticipantId());
        JPAKEUtil.validateMacTag(this.participantId, this.partnerParticipantId, this.gx1, this.gx2, this.gx3, this.gx4, bigInteger, this.digest, jPAKERound3Payload.getMacTag());
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;
        this.state = 70;
    }
}