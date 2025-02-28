package org.bouncycastle.asn1.cms;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.LocaleUtil;

/* loaded from: classes.dex */
public class Time extends ASN1Object implements ASN1Choice {
    ASN1Primitive time;

    public Time(Date date) {
        SimpleDateFormat simpleDateFormat;
        SimpleTimeZone simpleTimeZone = new SimpleTimeZone(0, "Z");
        new SimpleDateFormat("yyyyMMddHHmmss", LocaleUtil.EN_Locale).setTimeZone(simpleTimeZone);
        String str = simpleDateFormat.format(date) + "Z";
        int parseInt = Integer.parseInt(str.substring(0, 4));
        this.time = (parseInt < 1950 || parseInt > 2049) ? new DERGeneralizedTime(str) : new DERUTCTime(str.substring(2));
    }

    public Time(Date date, Locale locale) {
        SimpleDateFormat simpleDateFormat;
        SimpleTimeZone simpleTimeZone = new SimpleTimeZone(0, "Z");
        new SimpleDateFormat("yyyyMMddHHmmss", locale).setTimeZone(simpleTimeZone);
        String str = simpleDateFormat.format(date) + "Z";
        int parseInt = Integer.parseInt(str.substring(0, 4));
        this.time = (parseInt < 1950 || parseInt > 2049) ? new DERGeneralizedTime(str) : new DERUTCTime(str.substring(2));
    }

    private Time(ASN1Primitive aSN1Primitive) {
        if (!(aSN1Primitive instanceof ASN1UTCTime) && !(aSN1Primitive instanceof ASN1GeneralizedTime)) {
            throw new IllegalArgumentException("unknown object passed to Time");
        }
        this.time = aSN1Primitive;
    }

    public static Time getInstance(Object obj) {
        if (obj == null || (obj instanceof Time)) {
            return (Time) obj;
        }
        if (obj instanceof ASN1UTCTime) {
            return new Time((ASN1UTCTime) obj);
        }
        if (obj instanceof ASN1GeneralizedTime) {
            return new Time((ASN1GeneralizedTime) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static Time getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        if (z) {
            return getInstance(aSN1TaggedObject.getExplicitBaseObject());
        }
        throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    public Date getDate() {
        try {
            ASN1Primitive aSN1Primitive = this.time;
            return aSN1Primitive instanceof ASN1UTCTime ? ((ASN1UTCTime) aSN1Primitive).getAdjustedDate() : ((ASN1GeneralizedTime) aSN1Primitive).getDate();
        } catch (ParseException e) {
            throw new IllegalStateException("invalid date string: " + e.getMessage());
        }
    }

    public String getTime() {
        ASN1Primitive aSN1Primitive = this.time;
        return aSN1Primitive instanceof ASN1UTCTime ? ((ASN1UTCTime) aSN1Primitive).getAdjustedTime() : ((ASN1GeneralizedTime) aSN1Primitive).getTime();
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.time;
    }
}