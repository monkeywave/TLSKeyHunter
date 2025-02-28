package org.bouncycastle.asn1.x509;

import java.util.Vector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x509/GeneralNamesBuilder.class */
public class GeneralNamesBuilder {
    private Vector names = new Vector();

    public GeneralNamesBuilder addNames(GeneralNames generalNames) {
        GeneralName[] names = generalNames.getNames();
        for (int i = 0; i != names.length; i++) {
            this.names.addElement(names[i]);
        }
        return this;
    }

    public GeneralNamesBuilder addName(GeneralName generalName) {
        this.names.addElement(generalName);
        return this;
    }

    public GeneralNames build() {
        GeneralName[] generalNameArr = new GeneralName[this.names.size()];
        for (int i = 0; i != generalNameArr.length; i++) {
            generalNameArr[i] = (GeneralName) this.names.elementAt(i);
        }
        return new GeneralNames(generalNameArr);
    }
}