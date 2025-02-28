package org.bouncycastle.pqc.crypto.util;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.bouncycastle.util.Integers;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Utils {
    static final AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_I);
    static final AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_III);
    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);
    static final AlgorithmIdentifier XMSS_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    static final AlgorithmIdentifier XMSS_SHA512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
    static final AlgorithmIdentifier XMSS_SHAKE128 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
    static final AlgorithmIdentifier XMSS_SHAKE256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);
    static final Map bikeOids;
    static final Map bikeParams;
    static final Map categories;
    static final Map dilithiumOids;
    static final Map dilithiumParams;
    static final Map falconOids;
    static final Map falconParams;
    static final Map frodoOids;
    static final Map frodoParams;
    static final Map hqcOids;
    static final Map hqcParams;
    static final Map mcElieceOids;
    static final Map mcElieceParams;
    static final Map mldsaOids;
    static final Map mldsaParams;
    static final Map mlkemOids;
    static final Map mlkemParams;
    static final Map ntruOids;
    static final Map ntruParams;
    static final Map ntruprimeOids;
    static final Map ntruprimeParams;
    static final Map picnicOids;
    static final Map picnicParams;
    static final Map rainbowOids;
    static final Map rainbowParams;
    static final Map saberOids;
    static final Map saberParams;
    static final Map shldsaOids;
    static final Map shldsaParams;
    static final Map sikeOids;
    static final Map sikeParams;
    static final Map sntruprimeOids;
    static final Map sntruprimeParams;
    static final Map sphincsPlusOids;
    static final Map sphincsPlusParams;

    static {
        HashMap hashMap = new HashMap();
        categories = hashMap;
        HashMap hashMap2 = new HashMap();
        picnicOids = hashMap2;
        HashMap hashMap3 = new HashMap();
        picnicParams = hashMap3;
        HashMap hashMap4 = new HashMap();
        frodoOids = hashMap4;
        HashMap hashMap5 = new HashMap();
        frodoParams = hashMap5;
        HashMap hashMap6 = new HashMap();
        saberOids = hashMap6;
        HashMap hashMap7 = new HashMap();
        saberParams = hashMap7;
        HashMap hashMap8 = new HashMap();
        mcElieceOids = hashMap8;
        HashMap hashMap9 = new HashMap();
        mcElieceParams = hashMap9;
        HashMap hashMap10 = new HashMap();
        sphincsPlusOids = hashMap10;
        HashMap hashMap11 = new HashMap();
        sphincsPlusParams = hashMap11;
        sikeOids = new HashMap();
        sikeParams = new HashMap();
        HashMap hashMap12 = new HashMap();
        ntruOids = hashMap12;
        HashMap hashMap13 = new HashMap();
        ntruParams = hashMap13;
        HashMap hashMap14 = new HashMap();
        falconOids = hashMap14;
        HashMap hashMap15 = new HashMap();
        falconParams = hashMap15;
        HashMap hashMap16 = new HashMap();
        ntruprimeOids = hashMap16;
        HashMap hashMap17 = new HashMap();
        ntruprimeParams = hashMap17;
        HashMap hashMap18 = new HashMap();
        sntruprimeOids = hashMap18;
        HashMap hashMap19 = new HashMap();
        sntruprimeParams = hashMap19;
        HashMap hashMap20 = new HashMap();
        dilithiumOids = hashMap20;
        HashMap hashMap21 = new HashMap();
        dilithiumParams = hashMap21;
        HashMap hashMap22 = new HashMap();
        bikeOids = hashMap22;
        HashMap hashMap23 = new HashMap();
        bikeParams = hashMap23;
        HashMap hashMap24 = new HashMap();
        hqcOids = hashMap24;
        HashMap hashMap25 = new HashMap();
        hqcParams = hashMap25;
        HashMap hashMap26 = new HashMap();
        rainbowOids = hashMap26;
        HashMap hashMap27 = new HashMap();
        rainbowParams = hashMap27;
        HashMap hashMap28 = new HashMap();
        mlkemOids = hashMap28;
        HashMap hashMap29 = new HashMap();
        mlkemParams = hashMap29;
        HashMap hashMap30 = new HashMap();
        mldsaOids = hashMap30;
        HashMap hashMap31 = new HashMap();
        mldsaParams = hashMap31;
        HashMap hashMap32 = new HashMap();
        shldsaOids = hashMap32;
        HashMap hashMap33 = new HashMap();
        shldsaParams = hashMap33;
        hashMap.put(PQCObjectIdentifiers.qTESLA_p_I, Integers.valueOf(5));
        hashMap.put(PQCObjectIdentifiers.qTESLA_p_III, Integers.valueOf(6));
        hashMap8.put(CMCEParameters.mceliece348864r3, BCObjectIdentifiers.mceliece348864_r3);
        hashMap8.put(CMCEParameters.mceliece348864fr3, BCObjectIdentifiers.mceliece348864f_r3);
        hashMap8.put(CMCEParameters.mceliece460896r3, BCObjectIdentifiers.mceliece460896_r3);
        hashMap8.put(CMCEParameters.mceliece460896fr3, BCObjectIdentifiers.mceliece460896f_r3);
        hashMap8.put(CMCEParameters.mceliece6688128r3, BCObjectIdentifiers.mceliece6688128_r3);
        hashMap8.put(CMCEParameters.mceliece6688128fr3, BCObjectIdentifiers.mceliece6688128f_r3);
        hashMap8.put(CMCEParameters.mceliece6960119r3, BCObjectIdentifiers.mceliece6960119_r3);
        hashMap8.put(CMCEParameters.mceliece6960119fr3, BCObjectIdentifiers.mceliece6960119f_r3);
        hashMap8.put(CMCEParameters.mceliece8192128r3, BCObjectIdentifiers.mceliece8192128_r3);
        hashMap8.put(CMCEParameters.mceliece8192128fr3, BCObjectIdentifiers.mceliece8192128f_r3);
        hashMap9.put(BCObjectIdentifiers.mceliece348864_r3, CMCEParameters.mceliece348864r3);
        hashMap9.put(BCObjectIdentifiers.mceliece348864f_r3, CMCEParameters.mceliece348864fr3);
        hashMap9.put(BCObjectIdentifiers.mceliece460896_r3, CMCEParameters.mceliece460896r3);
        hashMap9.put(BCObjectIdentifiers.mceliece460896f_r3, CMCEParameters.mceliece460896fr3);
        hashMap9.put(BCObjectIdentifiers.mceliece6688128_r3, CMCEParameters.mceliece6688128r3);
        hashMap9.put(BCObjectIdentifiers.mceliece6688128f_r3, CMCEParameters.mceliece6688128fr3);
        hashMap9.put(BCObjectIdentifiers.mceliece6960119_r3, CMCEParameters.mceliece6960119r3);
        hashMap9.put(BCObjectIdentifiers.mceliece6960119f_r3, CMCEParameters.mceliece6960119fr3);
        hashMap9.put(BCObjectIdentifiers.mceliece8192128_r3, CMCEParameters.mceliece8192128r3);
        hashMap9.put(BCObjectIdentifiers.mceliece8192128f_r3, CMCEParameters.mceliece8192128fr3);
        hashMap4.put(FrodoParameters.frodokem640aes, BCObjectIdentifiers.frodokem640aes);
        hashMap4.put(FrodoParameters.frodokem640shake, BCObjectIdentifiers.frodokem640shake);
        hashMap4.put(FrodoParameters.frodokem976aes, BCObjectIdentifiers.frodokem976aes);
        hashMap4.put(FrodoParameters.frodokem976shake, BCObjectIdentifiers.frodokem976shake);
        hashMap4.put(FrodoParameters.frodokem1344aes, BCObjectIdentifiers.frodokem1344aes);
        hashMap4.put(FrodoParameters.frodokem1344shake, BCObjectIdentifiers.frodokem1344shake);
        hashMap5.put(BCObjectIdentifiers.frodokem640aes, FrodoParameters.frodokem640aes);
        hashMap5.put(BCObjectIdentifiers.frodokem640shake, FrodoParameters.frodokem640shake);
        hashMap5.put(BCObjectIdentifiers.frodokem976aes, FrodoParameters.frodokem976aes);
        hashMap5.put(BCObjectIdentifiers.frodokem976shake, FrodoParameters.frodokem976shake);
        hashMap5.put(BCObjectIdentifiers.frodokem1344aes, FrodoParameters.frodokem1344aes);
        hashMap5.put(BCObjectIdentifiers.frodokem1344shake, FrodoParameters.frodokem1344shake);
        hashMap6.put(SABERParameters.lightsaberkem128r3, BCObjectIdentifiers.lightsaberkem128r3);
        hashMap6.put(SABERParameters.saberkem128r3, BCObjectIdentifiers.saberkem128r3);
        hashMap6.put(SABERParameters.firesaberkem128r3, BCObjectIdentifiers.firesaberkem128r3);
        hashMap6.put(SABERParameters.lightsaberkem192r3, BCObjectIdentifiers.lightsaberkem192r3);
        hashMap6.put(SABERParameters.saberkem192r3, BCObjectIdentifiers.saberkem192r3);
        hashMap6.put(SABERParameters.firesaberkem192r3, BCObjectIdentifiers.firesaberkem192r3);
        hashMap6.put(SABERParameters.lightsaberkem256r3, BCObjectIdentifiers.lightsaberkem256r3);
        hashMap6.put(SABERParameters.saberkem256r3, BCObjectIdentifiers.saberkem256r3);
        hashMap6.put(SABERParameters.firesaberkem256r3, BCObjectIdentifiers.firesaberkem256r3);
        hashMap6.put(SABERParameters.ulightsaberkemr3, BCObjectIdentifiers.ulightsaberkemr3);
        hashMap6.put(SABERParameters.usaberkemr3, BCObjectIdentifiers.usaberkemr3);
        hashMap6.put(SABERParameters.ufiresaberkemr3, BCObjectIdentifiers.ufiresaberkemr3);
        hashMap6.put(SABERParameters.lightsaberkem90sr3, BCObjectIdentifiers.lightsaberkem90sr3);
        hashMap6.put(SABERParameters.saberkem90sr3, BCObjectIdentifiers.saberkem90sr3);
        hashMap6.put(SABERParameters.firesaberkem90sr3, BCObjectIdentifiers.firesaberkem90sr3);
        hashMap6.put(SABERParameters.ulightsaberkem90sr3, BCObjectIdentifiers.ulightsaberkem90sr3);
        hashMap6.put(SABERParameters.usaberkem90sr3, BCObjectIdentifiers.usaberkem90sr3);
        hashMap6.put(SABERParameters.ufiresaberkem90sr3, BCObjectIdentifiers.ufiresaberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.lightsaberkem128r3, SABERParameters.lightsaberkem128r3);
        hashMap7.put(BCObjectIdentifiers.saberkem128r3, SABERParameters.saberkem128r3);
        hashMap7.put(BCObjectIdentifiers.firesaberkem128r3, SABERParameters.firesaberkem128r3);
        hashMap7.put(BCObjectIdentifiers.lightsaberkem192r3, SABERParameters.lightsaberkem192r3);
        hashMap7.put(BCObjectIdentifiers.saberkem192r3, SABERParameters.saberkem192r3);
        hashMap7.put(BCObjectIdentifiers.firesaberkem192r3, SABERParameters.firesaberkem192r3);
        hashMap7.put(BCObjectIdentifiers.lightsaberkem256r3, SABERParameters.lightsaberkem256r3);
        hashMap7.put(BCObjectIdentifiers.saberkem256r3, SABERParameters.saberkem256r3);
        hashMap7.put(BCObjectIdentifiers.firesaberkem256r3, SABERParameters.firesaberkem256r3);
        hashMap7.put(BCObjectIdentifiers.ulightsaberkemr3, SABERParameters.ulightsaberkemr3);
        hashMap7.put(BCObjectIdentifiers.usaberkemr3, SABERParameters.usaberkemr3);
        hashMap7.put(BCObjectIdentifiers.ufiresaberkemr3, SABERParameters.ufiresaberkemr3);
        hashMap7.put(BCObjectIdentifiers.lightsaberkem90sr3, SABERParameters.lightsaberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.saberkem90sr3, SABERParameters.saberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.firesaberkem90sr3, SABERParameters.firesaberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.ulightsaberkem90sr3, SABERParameters.ulightsaberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.usaberkem90sr3, SABERParameters.usaberkem90sr3);
        hashMap7.put(BCObjectIdentifiers.ufiresaberkem90sr3, SABERParameters.ufiresaberkem90sr3);
        hashMap2.put(PicnicParameters.picnicl1fs, BCObjectIdentifiers.picnicl1fs);
        hashMap2.put(PicnicParameters.picnicl1ur, BCObjectIdentifiers.picnicl1ur);
        hashMap2.put(PicnicParameters.picnicl3fs, BCObjectIdentifiers.picnicl3fs);
        hashMap2.put(PicnicParameters.picnicl3ur, BCObjectIdentifiers.picnicl3ur);
        hashMap2.put(PicnicParameters.picnicl5fs, BCObjectIdentifiers.picnicl5fs);
        hashMap2.put(PicnicParameters.picnicl5ur, BCObjectIdentifiers.picnicl5ur);
        hashMap2.put(PicnicParameters.picnic3l1, BCObjectIdentifiers.picnic3l1);
        hashMap2.put(PicnicParameters.picnic3l3, BCObjectIdentifiers.picnic3l3);
        hashMap2.put(PicnicParameters.picnic3l5, BCObjectIdentifiers.picnic3l5);
        hashMap2.put(PicnicParameters.picnicl1full, BCObjectIdentifiers.picnicl1full);
        hashMap2.put(PicnicParameters.picnicl3full, BCObjectIdentifiers.picnicl3full);
        hashMap2.put(PicnicParameters.picnicl5full, BCObjectIdentifiers.picnicl5full);
        hashMap3.put(BCObjectIdentifiers.picnicl1fs, PicnicParameters.picnicl1fs);
        hashMap3.put(BCObjectIdentifiers.picnicl1ur, PicnicParameters.picnicl1ur);
        hashMap3.put(BCObjectIdentifiers.picnicl3fs, PicnicParameters.picnicl3fs);
        hashMap3.put(BCObjectIdentifiers.picnicl3ur, PicnicParameters.picnicl3ur);
        hashMap3.put(BCObjectIdentifiers.picnicl5fs, PicnicParameters.picnicl5fs);
        hashMap3.put(BCObjectIdentifiers.picnicl5ur, PicnicParameters.picnicl5ur);
        hashMap3.put(BCObjectIdentifiers.picnic3l1, PicnicParameters.picnic3l1);
        hashMap3.put(BCObjectIdentifiers.picnic3l3, PicnicParameters.picnic3l3);
        hashMap3.put(BCObjectIdentifiers.picnic3l5, PicnicParameters.picnic3l5);
        hashMap3.put(BCObjectIdentifiers.picnicl1full, PicnicParameters.picnicl1full);
        hashMap3.put(BCObjectIdentifiers.picnicl3full, PicnicParameters.picnicl3full);
        hashMap3.put(BCObjectIdentifiers.picnicl5full, PicnicParameters.picnicl5full);
        hashMap12.put(NTRUParameters.ntruhps2048509, BCObjectIdentifiers.ntruhps2048509);
        hashMap12.put(NTRUParameters.ntruhps2048677, BCObjectIdentifiers.ntruhps2048677);
        hashMap12.put(NTRUParameters.ntruhps4096821, BCObjectIdentifiers.ntruhps4096821);
        hashMap12.put(NTRUParameters.ntruhps40961229, BCObjectIdentifiers.ntruhps40961229);
        hashMap12.put(NTRUParameters.ntruhrss701, BCObjectIdentifiers.ntruhrss701);
        hashMap12.put(NTRUParameters.ntruhrss1373, BCObjectIdentifiers.ntruhrss1373);
        hashMap13.put(BCObjectIdentifiers.ntruhps2048509, NTRUParameters.ntruhps2048509);
        hashMap13.put(BCObjectIdentifiers.ntruhps2048677, NTRUParameters.ntruhps2048677);
        hashMap13.put(BCObjectIdentifiers.ntruhps4096821, NTRUParameters.ntruhps4096821);
        hashMap13.put(BCObjectIdentifiers.ntruhps40961229, NTRUParameters.ntruhps40961229);
        hashMap13.put(BCObjectIdentifiers.ntruhrss701, NTRUParameters.ntruhrss701);
        hashMap13.put(BCObjectIdentifiers.ntruhrss1373, NTRUParameters.ntruhrss1373);
        hashMap14.put(FalconParameters.falcon_512, BCObjectIdentifiers.falcon_512);
        hashMap14.put(FalconParameters.falcon_1024, BCObjectIdentifiers.falcon_1024);
        hashMap15.put(BCObjectIdentifiers.falcon_512, FalconParameters.falcon_512);
        hashMap15.put(BCObjectIdentifiers.falcon_1024, FalconParameters.falcon_1024);
        hashMap28.put(MLKEMParameters.ml_kem_512, NISTObjectIdentifiers.id_alg_ml_kem_512);
        hashMap28.put(MLKEMParameters.ml_kem_768, NISTObjectIdentifiers.id_alg_ml_kem_768);
        hashMap28.put(MLKEMParameters.ml_kem_1024, NISTObjectIdentifiers.id_alg_ml_kem_1024);
        hashMap29.put(NISTObjectIdentifiers.id_alg_ml_kem_512, MLKEMParameters.ml_kem_512);
        hashMap29.put(NISTObjectIdentifiers.id_alg_ml_kem_768, MLKEMParameters.ml_kem_768);
        hashMap29.put(NISTObjectIdentifiers.id_alg_ml_kem_1024, MLKEMParameters.ml_kem_1024);
        hashMap16.put(NTRULPRimeParameters.ntrulpr653, BCObjectIdentifiers.ntrulpr653);
        hashMap16.put(NTRULPRimeParameters.ntrulpr761, BCObjectIdentifiers.ntrulpr761);
        hashMap16.put(NTRULPRimeParameters.ntrulpr857, BCObjectIdentifiers.ntrulpr857);
        hashMap16.put(NTRULPRimeParameters.ntrulpr953, BCObjectIdentifiers.ntrulpr953);
        hashMap16.put(NTRULPRimeParameters.ntrulpr1013, BCObjectIdentifiers.ntrulpr1013);
        hashMap16.put(NTRULPRimeParameters.ntrulpr1277, BCObjectIdentifiers.ntrulpr1277);
        hashMap17.put(BCObjectIdentifiers.ntrulpr653, NTRULPRimeParameters.ntrulpr653);
        hashMap17.put(BCObjectIdentifiers.ntrulpr761, NTRULPRimeParameters.ntrulpr761);
        hashMap17.put(BCObjectIdentifiers.ntrulpr857, NTRULPRimeParameters.ntrulpr857);
        hashMap17.put(BCObjectIdentifiers.ntrulpr953, NTRULPRimeParameters.ntrulpr953);
        hashMap17.put(BCObjectIdentifiers.ntrulpr1013, NTRULPRimeParameters.ntrulpr1013);
        hashMap17.put(BCObjectIdentifiers.ntrulpr1277, NTRULPRimeParameters.ntrulpr1277);
        hashMap18.put(SNTRUPrimeParameters.sntrup653, BCObjectIdentifiers.sntrup653);
        hashMap18.put(SNTRUPrimeParameters.sntrup761, BCObjectIdentifiers.sntrup761);
        hashMap18.put(SNTRUPrimeParameters.sntrup857, BCObjectIdentifiers.sntrup857);
        hashMap18.put(SNTRUPrimeParameters.sntrup953, BCObjectIdentifiers.sntrup953);
        hashMap18.put(SNTRUPrimeParameters.sntrup1013, BCObjectIdentifiers.sntrup1013);
        hashMap18.put(SNTRUPrimeParameters.sntrup1277, BCObjectIdentifiers.sntrup1277);
        hashMap19.put(BCObjectIdentifiers.sntrup653, SNTRUPrimeParameters.sntrup653);
        hashMap19.put(BCObjectIdentifiers.sntrup761, SNTRUPrimeParameters.sntrup761);
        hashMap19.put(BCObjectIdentifiers.sntrup857, SNTRUPrimeParameters.sntrup857);
        hashMap19.put(BCObjectIdentifiers.sntrup953, SNTRUPrimeParameters.sntrup953);
        hashMap19.put(BCObjectIdentifiers.sntrup1013, SNTRUPrimeParameters.sntrup1013);
        hashMap19.put(BCObjectIdentifiers.sntrup1277, SNTRUPrimeParameters.sntrup1277);
        hashMap30.put(MLDSAParameters.ml_dsa_44, NISTObjectIdentifiers.id_ml_dsa_44);
        hashMap30.put(MLDSAParameters.ml_dsa_65, NISTObjectIdentifiers.id_ml_dsa_65);
        hashMap30.put(MLDSAParameters.ml_dsa_87, NISTObjectIdentifiers.id_ml_dsa_87);
        hashMap30.put(MLDSAParameters.ml_dsa_44_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        hashMap30.put(MLDSAParameters.ml_dsa_65_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        hashMap30.put(MLDSAParameters.ml_dsa_87_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);
        hashMap31.put(NISTObjectIdentifiers.id_ml_dsa_44, MLDSAParameters.ml_dsa_44);
        hashMap31.put(NISTObjectIdentifiers.id_ml_dsa_65, MLDSAParameters.ml_dsa_65);
        hashMap31.put(NISTObjectIdentifiers.id_ml_dsa_87, MLDSAParameters.ml_dsa_87);
        hashMap31.put(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, MLDSAParameters.ml_dsa_44_with_sha512);
        hashMap31.put(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, MLDSAParameters.ml_dsa_65_with_sha512);
        hashMap31.put(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, MLDSAParameters.ml_dsa_87_with_sha512);
        hashMap20.put(DilithiumParameters.dilithium2, BCObjectIdentifiers.dilithium2);
        hashMap20.put(DilithiumParameters.dilithium3, BCObjectIdentifiers.dilithium3);
        hashMap20.put(DilithiumParameters.dilithium5, BCObjectIdentifiers.dilithium5);
        hashMap21.put(BCObjectIdentifiers.dilithium2, DilithiumParameters.dilithium2);
        hashMap21.put(BCObjectIdentifiers.dilithium3, DilithiumParameters.dilithium3);
        hashMap21.put(BCObjectIdentifiers.dilithium5, DilithiumParameters.dilithium5);
        hashMap23.put(BCObjectIdentifiers.bike128, BIKEParameters.bike128);
        hashMap23.put(BCObjectIdentifiers.bike192, BIKEParameters.bike192);
        hashMap23.put(BCObjectIdentifiers.bike256, BIKEParameters.bike256);
        hashMap22.put(BIKEParameters.bike128, BCObjectIdentifiers.bike128);
        hashMap22.put(BIKEParameters.bike192, BCObjectIdentifiers.bike192);
        hashMap22.put(BIKEParameters.bike256, BCObjectIdentifiers.bike256);
        hashMap25.put(BCObjectIdentifiers.hqc128, HQCParameters.hqc128);
        hashMap25.put(BCObjectIdentifiers.hqc192, HQCParameters.hqc192);
        hashMap25.put(BCObjectIdentifiers.hqc256, HQCParameters.hqc256);
        hashMap24.put(HQCParameters.hqc128, BCObjectIdentifiers.hqc128);
        hashMap24.put(HQCParameters.hqc192, BCObjectIdentifiers.hqc192);
        hashMap24.put(HQCParameters.hqc256, BCObjectIdentifiers.hqc256);
        hashMap27.put(BCObjectIdentifiers.rainbow_III_classic, RainbowParameters.rainbowIIIclassic);
        hashMap27.put(BCObjectIdentifiers.rainbow_III_circumzenithal, RainbowParameters.rainbowIIIcircumzenithal);
        hashMap27.put(BCObjectIdentifiers.rainbow_III_compressed, RainbowParameters.rainbowIIIcompressed);
        hashMap27.put(BCObjectIdentifiers.rainbow_V_classic, RainbowParameters.rainbowVclassic);
        hashMap27.put(BCObjectIdentifiers.rainbow_V_circumzenithal, RainbowParameters.rainbowVcircumzenithal);
        hashMap27.put(BCObjectIdentifiers.rainbow_V_compressed, RainbowParameters.rainbowVcompressed);
        hashMap26.put(RainbowParameters.rainbowIIIclassic, BCObjectIdentifiers.rainbow_III_classic);
        hashMap26.put(RainbowParameters.rainbowIIIcircumzenithal, BCObjectIdentifiers.rainbow_III_circumzenithal);
        hashMap26.put(RainbowParameters.rainbowIIIcompressed, BCObjectIdentifiers.rainbow_III_compressed);
        hashMap26.put(RainbowParameters.rainbowVclassic, BCObjectIdentifiers.rainbow_V_classic);
        hashMap26.put(RainbowParameters.rainbowVcircumzenithal, BCObjectIdentifiers.rainbow_V_circumzenithal);
        hashMap26.put(RainbowParameters.rainbowVcompressed, BCObjectIdentifiers.rainbow_V_compressed);
        hashMap32.put(SLHDSAParameters.sha2_128s, NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        hashMap32.put(SLHDSAParameters.sha2_128f, NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        hashMap32.put(SLHDSAParameters.sha2_192s, NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        hashMap32.put(SLHDSAParameters.sha2_192f, NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        hashMap32.put(SLHDSAParameters.sha2_256s, NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        hashMap32.put(SLHDSAParameters.sha2_256f, NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        hashMap32.put(SLHDSAParameters.shake_128s, NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        hashMap32.put(SLHDSAParameters.shake_128f, NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        hashMap32.put(SLHDSAParameters.shake_192s, NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        hashMap32.put(SLHDSAParameters.shake_192f, NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        hashMap32.put(SLHDSAParameters.shake_256s, NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        hashMap32.put(SLHDSAParameters.shake_256f, NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        hashMap32.put(SLHDSAParameters.sha2_128s_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        hashMap32.put(SLHDSAParameters.sha2_128f_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        hashMap32.put(SLHDSAParameters.sha2_192s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        hashMap32.put(SLHDSAParameters.sha2_192f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        hashMap32.put(SLHDSAParameters.sha2_256s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        hashMap32.put(SLHDSAParameters.sha2_256f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        hashMap32.put(SLHDSAParameters.shake_128s_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        hashMap32.put(SLHDSAParameters.shake_128f_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        hashMap32.put(SLHDSAParameters.shake_192s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        hashMap32.put(SLHDSAParameters.shake_192f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        hashMap32.put(SLHDSAParameters.shake_256s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        hashMap32.put(SLHDSAParameters.shake_256f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, SLHDSAParameters.sha2_128s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, SLHDSAParameters.sha2_128f);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, SLHDSAParameters.sha2_192s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, SLHDSAParameters.sha2_192f);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, SLHDSAParameters.sha2_256s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, SLHDSAParameters.sha2_256f);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s, SLHDSAParameters.shake_128s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f, SLHDSAParameters.shake_128f);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s, SLHDSAParameters.shake_192s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f, SLHDSAParameters.shake_192f);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s, SLHDSAParameters.shake_256s);
        hashMap33.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f, SLHDSAParameters.shake_256f);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, SLHDSAParameters.sha2_128s_with_sha256);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, SLHDSAParameters.sha2_128f_with_sha256);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, SLHDSAParameters.sha2_192s_with_sha512);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, SLHDSAParameters.sha2_192f_with_sha512);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, SLHDSAParameters.sha2_256s_with_sha512);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, SLHDSAParameters.sha2_256f_with_sha512);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, SLHDSAParameters.shake_128s_with_shake128);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, SLHDSAParameters.shake_128f_with_shake128);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, SLHDSAParameters.shake_192s_with_shake256);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, SLHDSAParameters.shake_192f_with_shake256);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, SLHDSAParameters.shake_256s_with_shake256);
        hashMap33.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, SLHDSAParameters.shake_256f_with_shake256);
        hashMap10.put(SLHDSAParameters.sha2_128s, BCObjectIdentifiers.sphincsPlus_sha2_128s);
        hashMap10.put(SLHDSAParameters.sha2_128f, BCObjectIdentifiers.sphincsPlus_sha2_128f);
        hashMap10.put(SLHDSAParameters.sha2_192s, BCObjectIdentifiers.sphincsPlus_sha2_192s);
        hashMap10.put(SLHDSAParameters.sha2_192f, BCObjectIdentifiers.sphincsPlus_sha2_192f);
        hashMap10.put(SLHDSAParameters.sha2_256s, BCObjectIdentifiers.sphincsPlus_sha2_256s);
        hashMap10.put(SLHDSAParameters.sha2_256f, BCObjectIdentifiers.sphincsPlus_sha2_256f);
        hashMap10.put(SLHDSAParameters.shake_128s, BCObjectIdentifiers.sphincsPlus_shake_128s);
        hashMap10.put(SLHDSAParameters.shake_128f, BCObjectIdentifiers.sphincsPlus_shake_128f);
        hashMap10.put(SLHDSAParameters.shake_192s, BCObjectIdentifiers.sphincsPlus_shake_192s);
        hashMap10.put(SLHDSAParameters.shake_192f, BCObjectIdentifiers.sphincsPlus_shake_192f);
        hashMap10.put(SLHDSAParameters.shake_256s, BCObjectIdentifiers.sphincsPlus_shake_256s);
        hashMap10.put(SLHDSAParameters.shake_256f, BCObjectIdentifiers.sphincsPlus_shake_256f);
        hashMap10.put(SPHINCSPlusParameters.sha2_128s_robust, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
        hashMap10.put(SPHINCSPlusParameters.sha2_128f_robust, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_128s_robust, BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_128f_robust, BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_128s, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_128f, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
        hashMap10.put(SPHINCSPlusParameters.sha2_192s_robust, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
        hashMap10.put(SPHINCSPlusParameters.sha2_192f_robust, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_192s_robust, BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_192f_robust, BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_192s, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_192f, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
        hashMap10.put(SPHINCSPlusParameters.sha2_256s_robust, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
        hashMap10.put(SPHINCSPlusParameters.sha2_256f_robust, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_256s_robust, BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
        hashMap10.put(SPHINCSPlusParameters.shake_256f_robust, BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_256s, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_256f, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
        hashMap10.put(SPHINCSPlusParameters.haraka_128s_simple, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.haraka_128f_simple, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.haraka_192s_simple, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.haraka_192f_simple, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.haraka_256s_simple, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.haraka_256f_simple, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple);
        hashMap10.put(SPHINCSPlusParameters.sha2_128s, BCObjectIdentifiers.sphincsPlus_sha2_128s);
        hashMap10.put(SPHINCSPlusParameters.sha2_128f, BCObjectIdentifiers.sphincsPlus_sha2_128f);
        hashMap10.put(SPHINCSPlusParameters.sha2_192s, BCObjectIdentifiers.sphincsPlus_sha2_192s);
        hashMap10.put(SPHINCSPlusParameters.sha2_192f, BCObjectIdentifiers.sphincsPlus_sha2_192f);
        hashMap10.put(SPHINCSPlusParameters.sha2_256s, BCObjectIdentifiers.sphincsPlus_sha2_256s);
        hashMap10.put(SPHINCSPlusParameters.sha2_256f, BCObjectIdentifiers.sphincsPlus_sha2_256f);
        hashMap10.put(SPHINCSPlusParameters.shake_128s, BCObjectIdentifiers.sphincsPlus_shake_128s);
        hashMap10.put(SPHINCSPlusParameters.shake_128f, BCObjectIdentifiers.sphincsPlus_shake_128f);
        hashMap10.put(SPHINCSPlusParameters.shake_192s, BCObjectIdentifiers.sphincsPlus_shake_192s);
        hashMap10.put(SPHINCSPlusParameters.shake_192f, BCObjectIdentifiers.sphincsPlus_shake_192f);
        hashMap10.put(SPHINCSPlusParameters.shake_256s, BCObjectIdentifiers.sphincsPlus_shake_256s);
        hashMap10.put(SPHINCSPlusParameters.shake_256f, BCObjectIdentifiers.sphincsPlus_shake_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128s, SPHINCSPlusParameters.sha2_128s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128f, SPHINCSPlusParameters.sha2_128f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128s, SPHINCSPlusParameters.shake_128s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128f, SPHINCSPlusParameters.shake_128f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192s, SPHINCSPlusParameters.sha2_192s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192f, SPHINCSPlusParameters.sha2_192f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192s, SPHINCSPlusParameters.shake_192s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192f, SPHINCSPlusParameters.shake_192f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256s, SPHINCSPlusParameters.sha2_256s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256f, SPHINCSPlusParameters.sha2_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256s, SPHINCSPlusParameters.shake_256s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256f, SPHINCSPlusParameters.shake_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, SPHINCSPlusParameters.sha2_128s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, SPHINCSPlusParameters.sha2_128f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, SPHINCSPlusParameters.shake_128s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, SPHINCSPlusParameters.shake_128f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, SPHINCSPlusParameters.haraka_128s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, SPHINCSPlusParameters.haraka_128f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, SPHINCSPlusParameters.sha2_192s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, SPHINCSPlusParameters.sha2_192f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, SPHINCSPlusParameters.shake_192s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, SPHINCSPlusParameters.shake_192f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, SPHINCSPlusParameters.haraka_192s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, SPHINCSPlusParameters.haraka_192f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, SPHINCSPlusParameters.sha2_256s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, SPHINCSPlusParameters.sha2_256f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, SPHINCSPlusParameters.shake_256s_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, SPHINCSPlusParameters.shake_256f_robust);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, SPHINCSPlusParameters.haraka_256s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, SPHINCSPlusParameters.haraka_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, SPHINCSPlusParameters.sha2_128s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, SPHINCSPlusParameters.sha2_128f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, SPHINCSPlusParameters.shake_128s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, SPHINCSPlusParameters.shake_128f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, SPHINCSPlusParameters.haraka_128s_simple);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, SPHINCSPlusParameters.haraka_128f_simple);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, SPHINCSPlusParameters.sha2_192s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, SPHINCSPlusParameters.sha2_192f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, SPHINCSPlusParameters.shake_192s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, SPHINCSPlusParameters.shake_192f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, SPHINCSPlusParameters.haraka_192s_simple);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, SPHINCSPlusParameters.haraka_192f_simple);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, SPHINCSPlusParameters.sha2_256s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, SPHINCSPlusParameters.sha2_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, SPHINCSPlusParameters.shake_256s);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, SPHINCSPlusParameters.shake_256f);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, SPHINCSPlusParameters.haraka_256s_simple);
        hashMap11.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, SPHINCSPlusParameters.haraka_256f_simple);
    }

    Utils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier bikeOidLookup(BIKEParameters bIKEParameters) {
        return (ASN1ObjectIdentifier) bikeOids.get(bIKEParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BIKEParameters bikeParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (BIKEParameters) bikeParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier dilithiumOidLookup(DilithiumParameters dilithiumParameters) {
        return (ASN1ObjectIdentifier) dilithiumOids.get(dilithiumParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DilithiumParameters dilithiumParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (DilithiumParameters) dilithiumParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier falconOidLookup(FalconParameters falconParameters) {
        return (ASN1ObjectIdentifier) falconOids.get(falconParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FalconParameters falconParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (FalconParameters) falconParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier frodoOidLookup(FrodoParameters frodoParameters) {
        return (ASN1ObjectIdentifier) frodoOids.get(frodoParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FrodoParameters frodoParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (FrodoParameters) frodoParams.get(aSN1ObjectIdentifier);
    }

    public static AlgorithmIdentifier getAlgorithmIdentifier(String str) {
        if (str.equals(McElieceCCA2KeyGenParameterSpec.SHA1)) {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        }
        if (str.equals(McElieceCCA2KeyGenParameterSpec.SHA224)) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224);
        }
        if (str.equals("SHA-256")) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (str.equals(McElieceCCA2KeyGenParameterSpec.SHA384)) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        if (str.equals("SHA-512")) {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }
        throw new IllegalArgumentException("unrecognised digest algorithm: " + str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Digest getDigest(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return new SHA256Digest();
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return new SHA512Digest();
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake128)) {
            return new SHAKEDigest(128);
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake256)) {
            return new SHAKEDigest(256);
        }
        throw new IllegalArgumentException("unrecognized digest OID: " + aSN1ObjectIdentifier);
    }

    public static String getDigestName(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) OIWObjectIdentifiers.idSHA1)) {
            return McElieceCCA2KeyGenParameterSpec.SHA1;
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha224)) {
            return McElieceCCA2KeyGenParameterSpec.SHA224;
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return "SHA-256";
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha384)) {
            return McElieceCCA2KeyGenParameterSpec.SHA384;
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return "SHA-512";
        }
        throw new IllegalArgumentException("unrecognised digest algorithm: " + aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier hqcOidLookup(HQCParameters hQCParameters) {
        return (ASN1ObjectIdentifier) hqcOids.get(hQCParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static HQCParameters hqcParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (HQCParameters) hqcParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier mcElieceOidLookup(CMCEParameters cMCEParameters) {
        return (ASN1ObjectIdentifier) mcElieceOids.get(cMCEParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CMCEParameters mcElieceParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (CMCEParameters) mcElieceParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier mldsaOidLookup(MLDSAParameters mLDSAParameters) {
        return (ASN1ObjectIdentifier) mldsaOids.get(mLDSAParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MLDSAParameters mldsaParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (MLDSAParameters) mldsaParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier mlkemOidLookup(MLKEMParameters mLKEMParameters) {
        return (ASN1ObjectIdentifier) mlkemOids.get(mLKEMParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static MLKEMParameters mlkemParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (MLKEMParameters) mlkemParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier ntruOidLookup(NTRUParameters nTRUParameters) {
        return (ASN1ObjectIdentifier) ntruOids.get(nTRUParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static NTRUParameters ntruParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (NTRUParameters) ntruParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier ntrulprimeOidLookup(NTRULPRimeParameters nTRULPRimeParameters) {
        return (ASN1ObjectIdentifier) ntruprimeOids.get(nTRULPRimeParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static NTRULPRimeParameters ntrulprimeParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (NTRULPRimeParameters) ntruprimeParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier picnicOidLookup(PicnicParameters picnicParameters) {
        return (ASN1ObjectIdentifier) picnicOids.get(picnicParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static PicnicParameters picnicParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (PicnicParameters) picnicParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmIdentifier qTeslaLookupAlgID(int i) {
        if (i != 5) {
            if (i == 6) {
                return AlgID_qTESLA_p_III;
            }
            throw new IllegalArgumentException("unknown security category: " + i);
        }
        return AlgID_qTESLA_p_I;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int qTeslaLookupSecurityCategory(AlgorithmIdentifier algorithmIdentifier) {
        return ((Integer) categories.get(algorithmIdentifier.getAlgorithm())).intValue();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier rainbowOidLookup(RainbowParameters rainbowParameters) {
        return (ASN1ObjectIdentifier) rainbowOids.get(rainbowParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RainbowParameters rainbowParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (RainbowParameters) rainbowParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier saberOidLookup(SABERParameters sABERParameters) {
        return (ASN1ObjectIdentifier) saberOids.get(sABERParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SABERParameters saberParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (SABERParameters) saberParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier slhdsaOidLookup(SLHDSAParameters sLHDSAParameters) {
        return (ASN1ObjectIdentifier) shldsaOids.get(sLHDSAParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SLHDSAParameters slhdsaParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (SLHDSAParameters) shldsaParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier sntruprimeOidLookup(SNTRUPrimeParameters sNTRUPrimeParameters) {
        return (ASN1ObjectIdentifier) sntruprimeOids.get(sNTRUPrimeParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SNTRUPrimeParameters sntruprimeParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (SNTRUPrimeParameters) sntruprimeParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmIdentifier sphincs256LookupTreeAlgID(String str) {
        if (str.equals("SHA3-256")) {
            return SPHINCS_SHA3_256;
        }
        if (str.equals(SPHINCSKeyParameters.SHA512_256)) {
            return SPHINCS_SHA512_256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static String sphincs256LookupTreeAlgName(SPHINCS256KeyParams sPHINCS256KeyParams) {
        AlgorithmIdentifier treeDigest = sPHINCS256KeyParams.getTreeDigest();
        if (treeDigest.getAlgorithm().equals((ASN1Primitive) SPHINCS_SHA3_256.getAlgorithm())) {
            return "SHA3-256";
        }
        if (treeDigest.getAlgorithm().equals((ASN1Primitive) SPHINCS_SHA512_256.getAlgorithm())) {
            return SPHINCSKeyParameters.SHA512_256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + treeDigest.getAlgorithm());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ASN1ObjectIdentifier sphincsPlusOidLookup(SPHINCSPlusParameters sPHINCSPlusParameters) {
        return (ASN1ObjectIdentifier) sphincsPlusOids.get(sPHINCSPlusParameters);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static SPHINCSPlusParameters sphincsPlusParamsLookup(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        return (SPHINCSPlusParameters) sphincsPlusParams.get(aSN1ObjectIdentifier);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmIdentifier xmssLookupTreeAlgID(String str) {
        if (str.equals("SHA-256")) {
            return XMSS_SHA256;
        }
        if (str.equals("SHA-512")) {
            return XMSS_SHA512;
        }
        if (str.equals("SHAKE128")) {
            return XMSS_SHAKE128;
        }
        if (str.equals("SHAKE256")) {
            return XMSS_SHAKE256;
        }
        throw new IllegalArgumentException("unknown tree digest: " + str);
    }
}