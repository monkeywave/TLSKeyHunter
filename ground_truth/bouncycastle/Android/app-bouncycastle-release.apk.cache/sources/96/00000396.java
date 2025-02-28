package androidx.constraintlayout.core.widgets;

/* loaded from: classes.dex */
public class Rectangle {
    public int height;
    public int width;

    /* renamed from: x */
    public int f43x;

    /* renamed from: y */
    public int f44y;

    public void setBounds(int i, int i2, int i3, int i4) {
        this.f43x = i;
        this.f44y = i2;
        this.width = i3;
        this.height = i4;
    }

    void grow(int i, int i2) {
        this.f43x -= i;
        this.f44y -= i2;
        this.width += i * 2;
        this.height += i2 * 2;
    }

    boolean intersects(Rectangle rectangle) {
        int i;
        int i2;
        int i3 = this.f43x;
        int i4 = rectangle.f43x;
        return i3 >= i4 && i3 < i4 + rectangle.width && (i = this.f44y) >= (i2 = rectangle.f44y) && i < i2 + rectangle.height;
    }

    public boolean contains(int i, int i2) {
        int i3;
        int i4 = this.f43x;
        return i >= i4 && i < i4 + this.width && i2 >= (i3 = this.f44y) && i2 < i3 + this.height;
    }

    public int getCenterX() {
        return (this.f43x + this.width) / 2;
    }

    public int getCenterY() {
        return (this.f44y + this.height) / 2;
    }
}