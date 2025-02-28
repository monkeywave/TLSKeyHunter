package com.google.android.material.color.utilities;

import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public final class QuantizerCelebi {
    private QuantizerCelebi() {
    }

    public static Map<Integer, Integer> quantize(int[] iArr, int i) {
        Set<Integer> keySet = new QuantizerWu().quantize(iArr, i).colorToCount.keySet();
        int[] iArr2 = new int[keySet.size()];
        int i2 = 0;
        for (Integer num : keySet) {
            iArr2[i2] = num.intValue();
            i2++;
        }
        return QuantizerWsmeans.quantize(iArr, iArr2, i);
    }
}