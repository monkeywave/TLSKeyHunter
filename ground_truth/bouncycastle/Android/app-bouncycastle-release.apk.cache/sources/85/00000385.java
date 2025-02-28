package androidx.constraintlayout.core.widgets;

import androidx.constraintlayout.core.LinearSystem;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class Chain {
    private static final boolean DEBUG = false;
    public static final boolean USE_CHAIN_OPTIMIZATION = false;

    public static void applyChainConstraints(ConstraintWidgetContainer constraintWidgetContainer, LinearSystem linearSystem, ArrayList<ConstraintWidget> arrayList, int i) {
        int i2;
        ChainHead[] chainHeadArr;
        int i3;
        if (i == 0) {
            i2 = constraintWidgetContainer.mHorizontalChainsSize;
            chainHeadArr = constraintWidgetContainer.mHorizontalChainsArray;
            i3 = 0;
        } else {
            i2 = constraintWidgetContainer.mVerticalChainsSize;
            chainHeadArr = constraintWidgetContainer.mVerticalChainsArray;
            i3 = 2;
        }
        for (int i4 = 0; i4 < i2; i4++) {
            ChainHead chainHead = chainHeadArr[i4];
            chainHead.define();
            if (arrayList == null || (arrayList != null && arrayList.contains(chainHead.mFirst))) {
                applyChainConstraints(constraintWidgetContainer, linearSystem, i, i3, chainHead);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0037, code lost:
        if (r2.mHorizontalChainStyle == 2) goto L320;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x004a, code lost:
        if (r2.mVerticalChainStyle == 2) goto L320;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x004c, code lost:
        r5 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x004e, code lost:
        r5 = false;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:110:0x01b7  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01f3  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x0383  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x03dc  */
    /* JADX WARN: Removed duplicated region for block: B:236:0x03fc  */
    /* JADX WARN: Removed duplicated region for block: B:283:0x04d9  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x0523  */
    /* JADX WARN: Removed duplicated region for block: B:299:0x052e  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x0533  */
    /* JADX WARN: Removed duplicated region for block: B:303:0x0539  */
    /* JADX WARN: Removed duplicated region for block: B:304:0x053e  */
    /* JADX WARN: Removed duplicated region for block: B:306:0x0542  */
    /* JADX WARN: Removed duplicated region for block: B:310:0x0553  */
    /* JADX WARN: Removed duplicated region for block: B:312:0x0556  */
    /* JADX WARN: Removed duplicated region for block: B:325:0x03de A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    static void applyChainConstraints(androidx.constraintlayout.core.widgets.ConstraintWidgetContainer r38, androidx.constraintlayout.core.LinearSystem r39, int r40, int r41, androidx.constraintlayout.core.widgets.ChainHead r42) {
        /*
            Method dump skipped, instructions count: 1407
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.core.widgets.Chain.applyChainConstraints(androidx.constraintlayout.core.widgets.ConstraintWidgetContainer, androidx.constraintlayout.core.LinearSystem, int, int, androidx.constraintlayout.core.widgets.ChainHead):void");
    }
}