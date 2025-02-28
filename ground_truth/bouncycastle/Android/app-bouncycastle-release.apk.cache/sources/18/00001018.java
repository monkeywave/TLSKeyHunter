package com.google.android.material.navigationrail;

import android.content.Context;
import android.view.View;
import com.google.android.material.C0602R;
import com.google.android.material.navigation.NavigationBarItemView;

/* loaded from: classes.dex */
final class NavigationRailItemView extends NavigationBarItemView {
    public NavigationRailItemView(Context context) {
        super(context);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (View.MeasureSpec.getMode(i2) == 0) {
            setMeasuredDimension(getMeasuredWidthAndState(), Math.max(getMeasuredHeight(), View.MeasureSpec.getSize(i2)));
        }
    }

    @Override // com.google.android.material.navigation.NavigationBarItemView
    protected int getItemLayoutResId() {
        return C0602R.layout.mtrl_navigation_rail_item;
    }

    @Override // com.google.android.material.navigation.NavigationBarItemView
    protected int getItemDefaultMarginResId() {
        return C0602R.dimen.mtrl_navigation_rail_icon_margin;
    }
}