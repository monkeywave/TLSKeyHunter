package com.example.tls_library_ground_truth.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import androidx.viewbinding.ViewBinding;
import androidx.viewbinding.ViewBindings;
import com.example.tls_library_ground_truth.C0596R;

/* loaded from: classes.dex */
public final class ActivityMainBinding implements ViewBinding {
    public final EditText ipField;
    public final TextView keyView;
    public final Spinner librarySpinner;
    public final EditText portField;
    private final ScrollView rootView;
    public final Button startButton;
    public final Button stopButton;
    public final TextView textView;
    public final Spinner versionSpinner;

    private ActivityMainBinding(ScrollView scrollView, EditText editText, TextView textView, Spinner spinner, EditText editText2, Button button, Button button2, TextView textView2, Spinner spinner2) {
        this.rootView = scrollView;
        this.ipField = editText;
        this.keyView = textView;
        this.librarySpinner = spinner;
        this.portField = editText2;
        this.startButton = button;
        this.stopButton = button2;
        this.textView = textView2;
        this.versionSpinner = spinner2;
    }

    @Override // androidx.viewbinding.ViewBinding
    public ScrollView getRoot() {
        return this.rootView;
    }

    public static ActivityMainBinding inflate(LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    public static ActivityMainBinding inflate(LayoutInflater layoutInflater, ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(C0596R.layout.activity_main, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    public static ActivityMainBinding bind(View view) {
        int i = C0596R.C0599id.ip_field;
        EditText editText = (EditText) ViewBindings.findChildViewById(view, i);
        if (editText != null) {
            i = C0596R.C0599id.keyView;
            TextView textView = (TextView) ViewBindings.findChildViewById(view, i);
            if (textView != null) {
                i = C0596R.C0599id.library_spinner;
                Spinner spinner = (Spinner) ViewBindings.findChildViewById(view, i);
                if (spinner != null) {
                    i = C0596R.C0599id.port_field;
                    EditText editText2 = (EditText) ViewBindings.findChildViewById(view, i);
                    if (editText2 != null) {
                        i = C0596R.C0599id.start_button;
                        Button button = (Button) ViewBindings.findChildViewById(view, i);
                        if (button != null) {
                            i = C0596R.C0599id.stop_button;
                            Button button2 = (Button) ViewBindings.findChildViewById(view, i);
                            if (button2 != null) {
                                i = C0596R.C0599id.textView;
                                TextView textView2 = (TextView) ViewBindings.findChildViewById(view, i);
                                if (textView2 != null) {
                                    i = C0596R.C0599id.version_spinner;
                                    Spinner spinner2 = (Spinner) ViewBindings.findChildViewById(view, i);
                                    if (spinner2 != null) {
                                        return new ActivityMainBinding((ScrollView) view, editText, textView, spinner, editText2, button, button2, textView2, spinner2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }
}