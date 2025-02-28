package com.google.android.material.color.utilities;

import java.util.function.Function;

/* loaded from: classes.dex */
public final class MaterialDynamicColors {
    private static final double CONTAINER_ACCENT_TONE_DELTA = 15.0d;

    public DynamicColor highestSurface(DynamicScheme dynamicScheme) {
        return dynamicScheme.isDark ? surfaceBright() : surfaceDim();
    }

    public DynamicColor primaryPaletteKeyColor() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda63
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryPaletteKeyColor$0((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda65
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryPaletteKeyColor$1((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$primaryPaletteKeyColor$0(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$primaryPaletteKeyColor$1(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.primaryPalette.getKeyColor().getTone());
    }

    public DynamicColor secondaryPaletteKeyColor() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda70
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryPaletteKeyColor$2((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda71
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryPaletteKeyColor$3((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$secondaryPaletteKeyColor$2(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$secondaryPaletteKeyColor$3(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.secondaryPalette.getKeyColor().getTone());
    }

    public DynamicColor tertiaryPaletteKeyColor() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda80
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryPaletteKeyColor$4((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda81
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryPaletteKeyColor$5((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$tertiaryPaletteKeyColor$4(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$tertiaryPaletteKeyColor$5(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.tertiaryPalette.getKeyColor().getTone());
    }

    public DynamicColor neutralPaletteKeyColor() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda11
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$neutralPaletteKeyColor$6((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda22
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$neutralPaletteKeyColor$7((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$neutralPaletteKeyColor$6(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$neutralPaletteKeyColor$7(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.neutralPalette.getKeyColor().getTone());
    }

    public DynamicColor neutralVariantPaletteKeyColor() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda131
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$neutralVariantPaletteKeyColor$8((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda132
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$neutralVariantPaletteKeyColor$9((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$neutralVariantPaletteKeyColor$8(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$neutralVariantPaletteKeyColor$9(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.neutralVariantPalette.getKeyColor().getTone());
    }

    public static /* synthetic */ TonalPalette lambda$background$10(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$background$11(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 6.0d : 98.0d);
    }

    public DynamicColor background() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda91
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$background$10((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda92
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$background$11((DynamicScheme) obj);
            }
        });
    }

    public DynamicColor onBackground() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda95
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onBackground$12((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda96
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onBackground$13((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda98
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m239x24678954((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onBackground$12(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$onBackground$13(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
    }

    /* renamed from: lambda$onBackground$14$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m239x24678954(DynamicScheme dynamicScheme) {
        return background();
    }

    public static /* synthetic */ TonalPalette lambda$surface$15(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surface$16(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 6.0d : 98.0d);
    }

    public DynamicColor surface() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda0
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surface$15((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda64
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surface$16((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$inverseSurface$17(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$inverseSurface$18(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 20.0d);
    }

    public DynamicColor inverseSurface() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda35
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inverseSurface$17((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda36
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inverseSurface$18((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceBright$19(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceBright$20(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 24.0d : 98.0d);
    }

    public DynamicColor surfaceBright() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda101
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceBright$19((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda102
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceBright$20((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceDim$21(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceDim$22(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 6.0d : 87.0d);
    }

    public DynamicColor surfaceDim() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda33
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceDim$21((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda44
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceDim$22((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceContainerLowest$23(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceContainerLowest$24(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 4.0d : 100.0d);
    }

    public DynamicColor surfaceContainerLowest() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda1
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerLowest$23((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda2
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerLowest$24((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceContainerLow$25(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceContainerLow$26(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 10.0d : 96.0d);
    }

    public DynamicColor surfaceContainerLow() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda72
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerLow$25((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda73
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerLow$26((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceContainer$27(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceContainer$28(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 12.0d : 94.0d);
    }

    public DynamicColor surfaceContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda29
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainer$27((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda30
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainer$28((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceContainerHigh$29(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceContainerHigh$30(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 17.0d : 92.0d);
    }

    public DynamicColor surfaceContainerHigh() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda93
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerHigh$29((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda94
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerHigh$30((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceContainerHighest$31(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$surfaceContainerHighest$32(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 22.0d : 90.0d);
    }

    public DynamicColor surfaceContainerHighest() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda137
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerHighest$31((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda138
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceContainerHighest$32((DynamicScheme) obj);
            }
        });
    }

    public DynamicColor onSurface() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda130
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSurface$33((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda141
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSurface$34((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$onSurface$33(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$onSurface$34(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
    }

    public DynamicColor inverseOnSurface() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda10
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inverseOnSurface$35((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda12
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inverseOnSurface$36((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda13
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m241x55e5e264((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$inverseOnSurface$35(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$inverseOnSurface$36(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 20.0d : 95.0d);
    }

    /* renamed from: lambda$inverseOnSurface$37$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m241x55e5e264(DynamicScheme dynamicScheme) {
        return inverseSurface();
    }

    public static /* synthetic */ TonalPalette lambda$surfaceVariant$38(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$surfaceVariant$39(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 90.0d);
    }

    public DynamicColor surfaceVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda128
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceVariant$38((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda129
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceVariant$39((DynamicScheme) obj);
            }
        });
    }

    public DynamicColor onSurfaceVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda31
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSurfaceVariant$40((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda32
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSurfaceVariant$41((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda34
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m226xb0eb5d45((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onSurfaceVariant$40(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$onSurfaceVariant$41(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 30.0d);
    }

    /* renamed from: lambda$onSurfaceVariant$42$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m226xb0eb5d45(DynamicScheme dynamicScheme) {
        return surfaceVariant();
    }

    public DynamicColor outline() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda3
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$outline$43((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda4
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$outline$44((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$outline$43(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$outline$44(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 60.0d : 50.0d);
    }

    public DynamicColor outlineVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda99
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$outlineVariant$45((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda100
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$outlineVariant$46((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$outlineVariant$45(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$outlineVariant$46(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 80.0d);
    }

    public static /* synthetic */ TonalPalette lambda$shadow$47(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$shadow$48(DynamicScheme dynamicScheme) {
        return Double.valueOf(0.0d);
    }

    public DynamicColor shadow() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda135
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$shadow$47((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda136
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$shadow$48((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$scrim$49(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$scrim$50(DynamicScheme dynamicScheme) {
        return Double.valueOf(0.0d);
    }

    public DynamicColor scrim() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda50
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$scrim$49((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda51
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$scrim$50((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$surfaceTint$51(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$surfaceTint$52(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 40.0d);
    }

    public DynamicColor surfaceTint() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda5
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceTint$51((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda6
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$surfaceTint$52((DynamicScheme) obj);
            }
        });
    }

    public DynamicColor primaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda89
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryContainer$53((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda90
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryContainer$54((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$primaryContainer$53(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$primaryContainer$54(DynamicScheme dynamicScheme) {
        if (isFidelity(dynamicScheme)) {
            return Double.valueOf(performAlbers(dynamicScheme.sourceColorHct, dynamicScheme));
        }
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 85.0d : 25.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 90.0d);
    }

    public DynamicColor onPrimaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda123
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimaryContainer$55((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda124
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m235x3414da81((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda125
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m234xfd65642((DynamicScheme) obj);
            }
        }, null);
    }

    public static /* synthetic */ TonalPalette lambda$onPrimaryContainer$55(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    /* renamed from: lambda$onPrimaryContainer$56$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ Double m235x3414da81(DynamicScheme dynamicScheme) {
        if (isFidelity(dynamicScheme)) {
            return Double.valueOf(DynamicColor.contrastingTone(primaryContainer().tone.apply(dynamicScheme).doubleValue(), 4.5d));
        }
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 0.0d : 100.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
    }

    /* renamed from: lambda$onPrimaryContainer$57$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m234xfd65642(DynamicScheme dynamicScheme) {
        return primaryContainer();
    }

    public DynamicColor primary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda47
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primary$58((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda48
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primary$59((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this), new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda49
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m220x30fa1110((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$primary$58(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$primary$59(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 100.0d : 0.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 40.0d);
    }

    /* renamed from: lambda$primary$60$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ ToneDeltaConstraint m220x30fa1110(DynamicScheme dynamicScheme) {
        return new ToneDeltaConstraint(CONTAINER_ACCENT_TONE_DELTA, primaryContainer(), dynamicScheme.isDark ? TonePolarity.DARKER : TonePolarity.LIGHTER);
    }

    public DynamicColor inversePrimary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda106
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inversePrimary$61((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda107
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$inversePrimary$62((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda109
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m240xdc505989((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$inversePrimary$61(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$inversePrimary$62(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 40.0d : 80.0d);
    }

    /* renamed from: lambda$inversePrimary$63$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m240xdc505989(DynamicScheme dynamicScheme) {
        return inverseSurface();
    }

    public DynamicColor onPrimary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda103
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimary$64((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda104
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimary$65((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda105
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m236xd79e8fd5((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onPrimary$64(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$onPrimary$65(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 20.0d : 100.0d);
    }

    /* renamed from: lambda$onPrimary$66$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m236xd79e8fd5(DynamicScheme dynamicScheme) {
        return primary();
    }

    public DynamicColor secondaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda74
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryContainer$67((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda76
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryContainer$68((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$secondaryContainer$67(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$secondaryContainer$68(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 30.0d : 85.0d);
        }
        double d = dynamicScheme.isDark ? 30.0d : 90.0d;
        if (!isFidelity(dynamicScheme)) {
            return Double.valueOf(d);
        }
        return Double.valueOf(performAlbers(dynamicScheme.secondaryPalette.getHct(findDesiredChromaByTone(dynamicScheme.secondaryPalette.getHue(), dynamicScheme.secondaryPalette.getChroma(), d, !dynamicScheme.isDark)), dynamicScheme));
    }

    public DynamicColor onSecondaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda17
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondaryContainer$69((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda18
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m230x4d827fab((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda19
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m229x2943fb6c((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onSecondaryContainer$69(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    /* renamed from: lambda$onSecondaryContainer$70$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ Double m230x4d827fab(DynamicScheme dynamicScheme) {
        if (isFidelity(dynamicScheme)) {
            return Double.valueOf(DynamicColor.contrastingTone(secondaryContainer().tone.apply(dynamicScheme).doubleValue(), 4.5d));
        }
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
    }

    /* renamed from: lambda$onSecondaryContainer$71$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m229x2943fb6c(DynamicScheme dynamicScheme) {
        return secondaryContainer();
    }

    public DynamicColor secondary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda149
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondary$72((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda150
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondary$73((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this), new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda151
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m219xeac40501((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$secondary$72(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$secondary$73(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 40.0d);
    }

    /* renamed from: lambda$secondary$74$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ ToneDeltaConstraint m219xeac40501(DynamicScheme dynamicScheme) {
        return new ToneDeltaConstraint(CONTAINER_ACCENT_TONE_DELTA, secondaryContainer(), dynamicScheme.isDark ? TonePolarity.DARKER : TonePolarity.LIGHTER);
    }

    public DynamicColor onSecondary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda146
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondary$75((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda147
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondary$76((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda148
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m231x659efcc3((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onSecondary$75(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$onSecondary$76(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 10.0d : 100.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 20.0d : 100.0d);
    }

    /* renamed from: lambda$onSecondary$77$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m231x659efcc3(DynamicScheme dynamicScheme) {
        return secondary();
    }

    public DynamicColor tertiaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda144
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryContainer$78((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda145
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryContainer$79((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$tertiaryContainer$78(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$tertiaryContainer$79(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 60.0d : 49.0d);
        } else if (isFidelity(dynamicScheme)) {
            return Double.valueOf(DislikeAnalyzer.fixIfDisliked(dynamicScheme.tertiaryPalette.getHct(performAlbers(dynamicScheme.tertiaryPalette.getHct(dynamicScheme.sourceColorHct.getTone()), dynamicScheme))).getTone());
        } else {
            return Double.valueOf(dynamicScheme.isDark ? 30.0d : 90.0d);
        }
    }

    public DynamicColor onTertiaryContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda14
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiaryContainer$80((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda15
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m224xd7ba90a1((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda16
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m223xb37c0c62((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onTertiaryContainer$80(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    /* renamed from: lambda$onTertiaryContainer$81$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ Double m224xd7ba90a1(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 0.0d : 100.0d);
        } else if (isFidelity(dynamicScheme)) {
            return Double.valueOf(DynamicColor.contrastingTone(tertiaryContainer().tone.apply(dynamicScheme).doubleValue(), 4.5d));
        } else {
            return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
        }
    }

    /* renamed from: lambda$onTertiaryContainer$82$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m223xb37c0c62(DynamicScheme dynamicScheme) {
        return tertiaryContainer();
    }

    public DynamicColor tertiary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda56
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiary$83((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda57
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiary$84((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this), new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda58
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m218x8e709069((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$tertiary$83(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$tertiary$84(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 90.0d : 25.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 40.0d);
    }

    /* renamed from: lambda$tertiary$85$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ ToneDeltaConstraint m218x8e709069(DynamicScheme dynamicScheme) {
        return new ToneDeltaConstraint(CONTAINER_ACCENT_TONE_DELTA, tertiaryContainer(), dynamicScheme.isDark ? TonePolarity.DARKER : TonePolarity.LIGHTER);
    }

    public DynamicColor onTertiary() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda97
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiary$86((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda108
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiary$87((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda119
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m225xa50c734d((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onTertiary$86(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$onTertiary$87(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
        }
        return Double.valueOf(dynamicScheme.isDark ? 20.0d : 100.0d);
    }

    /* renamed from: lambda$onTertiary$88$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m225xa50c734d(DynamicScheme dynamicScheme) {
        return tertiary();
    }

    public DynamicColor errorContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda42
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$errorContainer$89((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda43
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$errorContainer$90((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$errorContainer$89(DynamicScheme dynamicScheme) {
        return dynamicScheme.errorPalette;
    }

    public static /* synthetic */ Double lambda$errorContainer$90(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 90.0d);
    }

    public DynamicColor onErrorContainer() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda37
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onErrorContainer$91((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda38
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onErrorContainer$92((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda39
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m237x8b3efb40((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onErrorContainer$91(DynamicScheme dynamicScheme) {
        return dynamicScheme.errorPalette;
    }

    public static /* synthetic */ Double lambda$onErrorContainer$92(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 90.0d : 10.0d);
    }

    /* renamed from: lambda$onErrorContainer$93$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m237x8b3efb40(DynamicScheme dynamicScheme) {
        return errorContainer();
    }

    public DynamicColor error() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda24
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$error$94((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda25
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$error$95((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this), new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda26
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m242xec5337ad((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$error$94(DynamicScheme dynamicScheme) {
        return dynamicScheme.errorPalette;
    }

    public static /* synthetic */ Double lambda$error$95(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 40.0d);
    }

    /* renamed from: lambda$error$96$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ ToneDeltaConstraint m242xec5337ad(DynamicScheme dynamicScheme) {
        return new ToneDeltaConstraint(CONTAINER_ACCENT_TONE_DELTA, errorContainer(), dynamicScheme.isDark ? TonePolarity.DARKER : TonePolarity.LIGHTER);
    }

    public DynamicColor onError() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda117
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onError$97((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda118
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onError$98((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda120
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m238x49ea46ef((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onError$97(DynamicScheme dynamicScheme) {
        return dynamicScheme.errorPalette;
    }

    public static /* synthetic */ Double lambda$onError$98(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 20.0d : 100.0d);
    }

    /* renamed from: lambda$onError$99$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m238x49ea46ef(DynamicScheme dynamicScheme) {
        return error();
    }

    public DynamicColor primaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda139
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryFixed$100((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda140
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryFixed$101((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$primaryFixed$100(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$primaryFixed$101(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 100.0d : 10.0d);
        }
        return Double.valueOf(90.0d);
    }

    public DynamicColor primaryFixedDim() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda142
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryFixedDim$102((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda143
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$primaryFixedDim$103((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$primaryFixedDim$102(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$primaryFixedDim$103(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 90.0d : 20.0d);
        }
        return Double.valueOf(80.0d);
    }

    public DynamicColor onPrimaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda20
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimaryFixed$104((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda21
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimaryFixed$105((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda23
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m233x1e87ba58((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onPrimaryFixed$104(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$onPrimaryFixed$105(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
        }
        return Double.valueOf(10.0d);
    }

    /* renamed from: lambda$onPrimaryFixed$106$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m233x1e87ba58(DynamicScheme dynamicScheme) {
        return primaryFixedDim();
    }

    public DynamicColor onPrimaryFixedVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda112
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimaryFixedVariant$107((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda113
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onPrimaryFixedVariant$108((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda114
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m232xec68ae64((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onPrimaryFixedVariant$107(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$onPrimaryFixedVariant$108(DynamicScheme dynamicScheme) {
        if (isMonochrome(dynamicScheme)) {
            return Double.valueOf(dynamicScheme.isDark ? 30.0d : 70.0d);
        }
        return Double.valueOf(30.0d);
    }

    /* renamed from: lambda$onPrimaryFixedVariant$109$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m232xec68ae64(DynamicScheme dynamicScheme) {
        return primaryFixedDim();
    }

    public DynamicColor secondaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda110
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryFixed$110((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda111
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryFixed$111((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$secondaryFixed$110(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$secondaryFixed$111(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 80.0d : 90.0d);
    }

    public DynamicColor secondaryFixedDim() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda126
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryFixedDim$112((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda127
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$secondaryFixedDim$113((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$secondaryFixedDim$112(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$secondaryFixedDim$113(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 70.0d : 80.0d);
    }

    public DynamicColor onSecondaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda7
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondaryFixed$114((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda8
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondaryFixed$115((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda9
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m228x36835905((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onSecondaryFixed$114(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$onSecondaryFixed$115(DynamicScheme dynamicScheme) {
        return Double.valueOf(10.0d);
    }

    /* renamed from: lambda$onSecondaryFixed$116$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m228x36835905(DynamicScheme dynamicScheme) {
        return secondaryFixedDim();
    }

    public DynamicColor onSecondaryFixedVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda52
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondaryFixedVariant$117((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda53
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onSecondaryFixedVariant$118((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda54
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m227x89aa74b5((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onSecondaryFixedVariant$117(DynamicScheme dynamicScheme) {
        return dynamicScheme.secondaryPalette;
    }

    public static /* synthetic */ Double lambda$onSecondaryFixedVariant$118(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 25.0d : 30.0d);
    }

    /* renamed from: lambda$onSecondaryFixedVariant$119$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m227x89aa74b5(DynamicScheme dynamicScheme) {
        return secondaryFixedDim();
    }

    public DynamicColor tertiaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda45
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryFixed$120((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda46
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryFixed$121((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$tertiaryFixed$120(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$tertiaryFixed$121(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 40.0d : 90.0d);
    }

    public DynamicColor tertiaryFixedDim() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda115
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryFixedDim$122((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda116
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$tertiaryFixedDim$123((DynamicScheme) obj);
            }
        }, new MaterialDynamicColors$$ExternalSyntheticLambda152(this));
    }

    public static /* synthetic */ TonalPalette lambda$tertiaryFixedDim$122(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$tertiaryFixedDim$123(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 30.0d : 80.0d);
    }

    public DynamicColor onTertiaryFixed() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda77
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiaryFixed$124((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda78
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiaryFixed$125((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda79
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m222xce8d5c4e((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onTertiaryFixed$124(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$onTertiaryFixed$125(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 90.0d : 10.0d);
    }

    /* renamed from: lambda$onTertiaryFixed$126$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m222xce8d5c4e(DynamicScheme dynamicScheme) {
        return tertiaryFixedDim();
    }

    public DynamicColor onTertiaryFixedVariant() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda67
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiaryFixedVariant$127((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda68
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$onTertiaryFixedVariant$128((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda69
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.this.m221x5ddcaeea((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$onTertiaryFixedVariant$127(DynamicScheme dynamicScheme) {
        return dynamicScheme.tertiaryPalette;
    }

    public static /* synthetic */ Double lambda$onTertiaryFixedVariant$128(DynamicScheme dynamicScheme) {
        return Double.valueOf(isMonochrome(dynamicScheme) ? 70.0d : 30.0d);
    }

    /* renamed from: lambda$onTertiaryFixedVariant$129$com-google-android-material-color-utilities-MaterialDynamicColors */
    public /* synthetic */ DynamicColor m221x5ddcaeea(DynamicScheme dynamicScheme) {
        return tertiaryFixedDim();
    }

    public static /* synthetic */ TonalPalette lambda$controlActivated$130(DynamicScheme dynamicScheme) {
        return dynamicScheme.primaryPalette;
    }

    public static /* synthetic */ Double lambda$controlActivated$131(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 90.0d);
    }

    public DynamicColor controlActivated() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda61
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlActivated$130((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda62
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlActivated$131((DynamicScheme) obj);
            }
        }, null);
    }

    public static /* synthetic */ TonalPalette lambda$controlNormal$132(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$controlNormal$133(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 80.0d : 30.0d);
    }

    public DynamicColor controlNormal() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda59
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlNormal$132((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda60
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlNormal$133((DynamicScheme) obj);
            }
        });
    }

    public DynamicColor controlHighlight() {
        return new DynamicColor(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda82
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$134((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda83
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$135((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda84
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$136((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda85
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$137((DynamicScheme) obj);
            }
        }, null, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda87
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$139((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda88
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$141((DynamicScheme) obj);
            }
        }, null);
    }

    public static /* synthetic */ Double lambda$controlHighlight$134(DynamicScheme dynamicScheme) {
        return Double.valueOf(0.0d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$135(DynamicScheme dynamicScheme) {
        return Double.valueOf(0.0d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$136(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 100.0d : 0.0d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$137(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 0.2d : 0.12d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$138(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 100.0d : 0.0d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$139(DynamicScheme dynamicScheme) {
        return Double.valueOf(DynamicColor.toneMinContrastDefault(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda66
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$138((DynamicScheme) obj);
            }
        }, null, dynamicScheme, null));
    }

    public static /* synthetic */ Double lambda$controlHighlight$140(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 100.0d : 0.0d);
    }

    public static /* synthetic */ Double lambda$controlHighlight$141(DynamicScheme dynamicScheme) {
        return Double.valueOf(DynamicColor.toneMaxContrastDefault(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda55
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$controlHighlight$140((DynamicScheme) obj);
            }
        }, null, dynamicScheme, null));
    }

    public static /* synthetic */ TonalPalette lambda$textPrimaryInverse$142(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$textPrimaryInverse$143(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
    }

    public DynamicColor textPrimaryInverse() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda27
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textPrimaryInverse$142((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda28
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textPrimaryInverse$143((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$textSecondaryAndTertiaryInverse$144(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralVariantPalette;
    }

    public static /* synthetic */ Double lambda$textSecondaryAndTertiaryInverse$145(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 30.0d : 80.0d);
    }

    public DynamicColor textSecondaryAndTertiaryInverse() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda40
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textSecondaryAndTertiaryInverse$144((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda41
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textSecondaryAndTertiaryInverse$145((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$textPrimaryInverseDisableOnly$146(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$textPrimaryInverseDisableOnly$147(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
    }

    public DynamicColor textPrimaryInverseDisableOnly() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda121
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textPrimaryInverseDisableOnly$146((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda122
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textPrimaryInverseDisableOnly$147((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$textSecondaryAndTertiaryInverseDisabled$148(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$textSecondaryAndTertiaryInverseDisabled$149(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
    }

    public DynamicColor textSecondaryAndTertiaryInverseDisabled() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda75
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textSecondaryAndTertiaryInverseDisabled$148((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda86
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textSecondaryAndTertiaryInverseDisabled$149((DynamicScheme) obj);
            }
        });
    }

    public static /* synthetic */ TonalPalette lambda$textHintInverse$150(DynamicScheme dynamicScheme) {
        return dynamicScheme.neutralPalette;
    }

    public static /* synthetic */ Double lambda$textHintInverse$151(DynamicScheme dynamicScheme) {
        return Double.valueOf(dynamicScheme.isDark ? 10.0d : 90.0d);
    }

    public DynamicColor textHintInverse() {
        return DynamicColor.fromPalette(new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda133
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textHintInverse$150((DynamicScheme) obj);
            }
        }, new Function() { // from class: com.google.android.material.color.utilities.MaterialDynamicColors$$ExternalSyntheticLambda134
            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                return MaterialDynamicColors.lambda$textHintInverse$151((DynamicScheme) obj);
            }
        });
    }

    private static ViewingConditions viewingConditionsForAlbers(DynamicScheme dynamicScheme) {
        return ViewingConditions.defaultWithBackgroundLstar(dynamicScheme.isDark ? 30.0d : 80.0d);
    }

    private static boolean isFidelity(DynamicScheme dynamicScheme) {
        return dynamicScheme.variant == Variant.FIDELITY || dynamicScheme.variant == Variant.CONTENT;
    }

    private static boolean isMonochrome(DynamicScheme dynamicScheme) {
        return dynamicScheme.variant == Variant.MONOCHROME;
    }

    static double findDesiredChromaByTone(double d, double d2, double d3, boolean z) {
        Hct from = Hct.from(d, d2, d3);
        if (from.getChroma() < d2) {
            Hct hct = from;
            double chroma = from.getChroma();
            double d4 = d3;
            while (hct.getChroma() < d2) {
                double d5 = d4 + (z ? -1.0d : 1.0d);
                Hct from2 = Hct.from(d, d2, d5);
                if (chroma > from2.getChroma() || Math.abs(from2.getChroma() - d2) < 0.4d) {
                    return d5;
                }
                if (Math.abs(from2.getChroma() - d2) < Math.abs(hct.getChroma() - d2)) {
                    hct = from2;
                }
                chroma = Math.max(chroma, from2.getChroma());
                d4 = d5;
            }
            return d4;
        }
        return d3;
    }

    static double performAlbers(Hct hct, DynamicScheme dynamicScheme) {
        Hct inViewingConditions = hct.inViewingConditions(viewingConditionsForAlbers(dynamicScheme));
        if (DynamicColor.tonePrefersLightForeground(hct.getTone()) && !DynamicColor.toneAllowsLightForeground(inViewingConditions.getTone())) {
            return DynamicColor.enableLightForeground(hct.getTone());
        }
        return DynamicColor.enableLightForeground(inViewingConditions.getTone());
    }
}