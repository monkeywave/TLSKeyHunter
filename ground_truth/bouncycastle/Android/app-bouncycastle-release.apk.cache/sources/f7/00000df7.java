package com.google.android.material.color;

/* loaded from: classes.dex */
public class ColorContrastOptions {
    private final int highContrastThemeOverlayResourceId;
    private final int mediumContrastThemeOverlayResourceId;

    private ColorContrastOptions(Builder builder) {
        this.mediumContrastThemeOverlayResourceId = builder.mediumContrastThemeOverlayResourceId;
        this.highContrastThemeOverlayResourceId = builder.highContrastThemeOverlayResourceId;
    }

    public int getMediumContrastThemeOverlay() {
        return this.mediumContrastThemeOverlayResourceId;
    }

    public int getHighContrastThemeOverlay() {
        return this.highContrastThemeOverlayResourceId;
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private int highContrastThemeOverlayResourceId;
        private int mediumContrastThemeOverlayResourceId;

        public Builder setMediumContrastThemeOverlay(int i) {
            this.mediumContrastThemeOverlayResourceId = i;
            return this;
        }

        public Builder setHighContrastThemeOverlay(int i) {
            this.highContrastThemeOverlayResourceId = i;
            return this;
        }

        public ColorContrastOptions build() {
            return new ColorContrastOptions(this);
        }
    }
}