package org.bouncycastle.math.p016ec.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.TreeSet;
import org.bouncycastle.asn1.p009x9.ECNamedCurveTable;
import org.bouncycastle.asn1.p009x9.X9ECParametersHolder;
import org.bouncycastle.crypto.p010ec.CustomNamedCurves;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.util.Strings;

/* renamed from: org.bouncycastle.math.ec.tools.F2mSqrtOptimizer */
/* loaded from: classes2.dex */
public class F2mSqrtOptimizer {
    private static List enumToList(Enumeration enumeration) {
        ArrayList arrayList = new ArrayList();
        while (enumeration.hasMoreElements()) {
            arrayList.add(enumeration.nextElement());
        }
        return arrayList;
    }

    private static void implPrintRootZ(ECCurve eCCurve) {
        ECFieldElement fromBigInteger = eCCurve.fromBigInteger(BigInteger.valueOf(2L));
        ECFieldElement sqrt = fromBigInteger.sqrt();
        System.out.println(Strings.toUpperCase(sqrt.toBigInteger().toString(16)));
        if (!sqrt.square().equals(fromBigInteger)) {
            throw new IllegalStateException("Optimized-sqrt sanity check failed");
        }
    }

    public static void main(String[] strArr) {
        TreeSet<String> treeSet = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        treeSet.addAll(enumToList(CustomNamedCurves.getNames()));
        for (String str : treeSet) {
            X9ECParametersHolder byNameLazy = CustomNamedCurves.getByNameLazy(str);
            if (byNameLazy == null) {
                byNameLazy = ECNamedCurveTable.getByNameLazy(str);
            }
            if (byNameLazy != null) {
                ECCurve curve = byNameLazy.getCurve();
                if (ECAlgorithms.isF2mCurve(curve)) {
                    System.out.print(str + ":");
                    implPrintRootZ(curve);
                }
            }
        }
    }

    public static void printRootZ(ECCurve eCCurve) {
        if (!ECAlgorithms.isF2mCurve(eCCurve)) {
            throw new IllegalArgumentException("Sqrt optimization only defined over characteristic-2 fields");
        }
        implPrintRootZ(eCCurve);
    }
}