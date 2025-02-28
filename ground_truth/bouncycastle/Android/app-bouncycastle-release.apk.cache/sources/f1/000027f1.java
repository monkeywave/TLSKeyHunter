package org.bouncycastle.oer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.oer.OERDefinition;

/* loaded from: classes2.dex */
public class Element {
    private final Switch aSwitch;
    private final OERDefinition.BaseType baseType;
    private final int block;
    private final List<Element> children;
    private final ASN1Encodable defaultValue;
    private final boolean defaultValuesInChildren;
    private final ElementSupplier elementSupplier;
    private final BigInteger enumValue;
    private final boolean explicit;
    private final boolean extensionsInDefinition;
    private final String label;
    private final BigInteger lowerBound;
    private final boolean mayRecurse;
    private List<Element> optionalChildrenInOrder;
    private final int optionals;
    private Element parent;
    private final Map<String, ElementSupplier> supplierMap;
    private final String typeName;
    private final BigInteger upperBound;
    private List<ASN1Encodable> validSwitchValues;

    public Element(Element element, Element element2) {
        this.baseType = element.baseType;
        ArrayList<Element> arrayList = new ArrayList(element.children);
        this.children = arrayList;
        this.explicit = element.explicit;
        this.label = element.label;
        this.lowerBound = element.lowerBound;
        this.upperBound = element.upperBound;
        this.extensionsInDefinition = element.extensionsInDefinition;
        this.enumValue = element.enumValue;
        this.defaultValue = element.defaultValue;
        this.aSwitch = element.aSwitch;
        this.validSwitchValues = element.validSwitchValues;
        this.elementSupplier = element.elementSupplier;
        this.mayRecurse = element.mayRecurse;
        this.typeName = element.typeName;
        this.supplierMap = element.supplierMap;
        this.parent = element2;
        this.block = element.block;
        this.optionals = element.optionals;
        this.defaultValuesInChildren = element.defaultValuesInChildren;
        for (Element element3 : arrayList) {
            element3.parent = this;
        }
    }

    public Element(OERDefinition.BaseType baseType, List<Element> list, boolean z, String str, BigInteger bigInteger, BigInteger bigInteger2, boolean z2, BigInteger bigInteger3, ASN1Encodable aSN1Encodable, Switch r14, List<ASN1Encodable> list2, ElementSupplier elementSupplier, boolean z3, String str2, Map<String, ElementSupplier> map, int i, int i2, boolean z4) {
        Map<String, ElementSupplier> map2 = map;
        this.baseType = baseType;
        this.children = list;
        this.explicit = z;
        this.label = str;
        this.lowerBound = bigInteger;
        this.upperBound = bigInteger2;
        this.extensionsInDefinition = z2;
        this.enumValue = bigInteger3;
        this.defaultValue = aSN1Encodable;
        this.aSwitch = r14;
        this.validSwitchValues = list2 != null ? Collections.unmodifiableList(list2) : null;
        this.elementSupplier = elementSupplier;
        this.mayRecurse = z3;
        this.typeName = str2;
        this.block = i;
        this.optionals = i2;
        this.defaultValuesInChildren = z4;
        this.supplierMap = map2 == null ? Collections.emptyMap() : map2;
        for (Element element : list) {
            element.parent = this;
        }
    }

    public static Element expandDeferredDefinition(Element element, Element element2) {
        ElementSupplier elementSupplier = element.elementSupplier;
        if (elementSupplier != null) {
            Element build = elementSupplier.build();
            return build.getParent() != element2 ? new Element(build, element2) : build;
        }
        return element;
    }

    public String appendLabel(String str) {
        return "[" + (getLabel() == null ? "" : getLabel()) + (isExplicit() ? " (E)" : "") + "] " + str;
    }

    public boolean canBeNegative() {
        return getLowerBound() != null && BigInteger.ZERO.compareTo(getLowerBound()) > 0;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Element element = (Element) obj;
        if (this.explicit == element.explicit && this.extensionsInDefinition == element.extensionsInDefinition && this.defaultValuesInChildren == element.defaultValuesInChildren && this.mayRecurse == element.mayRecurse && this.optionals == element.optionals && this.block == element.block && this.baseType == element.baseType) {
            List<Element> list = this.children;
            if (list == null ? element.children == null : list.equals(element.children)) {
                String str = this.label;
                if (str == null ? element.label == null : str.equals(element.label)) {
                    BigInteger bigInteger = this.lowerBound;
                    if (bigInteger == null ? element.lowerBound == null : bigInteger.equals(element.lowerBound)) {
                        BigInteger bigInteger2 = this.upperBound;
                        if (bigInteger2 == null ? element.upperBound == null : bigInteger2.equals(element.upperBound)) {
                            BigInteger bigInteger3 = this.enumValue;
                            if (bigInteger3 == null ? element.enumValue == null : bigInteger3.equals(element.enumValue)) {
                                ASN1Encodable aSN1Encodable = this.defaultValue;
                                if (aSN1Encodable == null ? element.defaultValue == null : aSN1Encodable.equals(element.defaultValue)) {
                                    Switch r2 = this.aSwitch;
                                    if (r2 == null ? element.aSwitch == null : r2.equals(element.aSwitch)) {
                                        List<Element> list2 = this.optionalChildrenInOrder;
                                        if (list2 == null ? element.optionalChildrenInOrder == null : list2.equals(element.optionalChildrenInOrder)) {
                                            List<ASN1Encodable> list3 = this.validSwitchValues;
                                            if (list3 == null ? element.validSwitchValues == null : list3.equals(element.validSwitchValues)) {
                                                ElementSupplier elementSupplier = this.elementSupplier;
                                                if (elementSupplier == null ? element.elementSupplier == null : elementSupplier.equals(element.elementSupplier)) {
                                                    String str2 = this.typeName;
                                                    if (str2 == null ? element.typeName == null : str2.equals(element.typeName)) {
                                                        Map<String, ElementSupplier> map = this.supplierMap;
                                                        Map<String, ElementSupplier> map2 = element.supplierMap;
                                                        if (map != null) {
                                                            if (!map.equals(map2)) {
                                                                return true;
                                                            }
                                                        } else if (map2 != null) {
                                                            return true;
                                                        }
                                                        return false;
                                                    }
                                                    return false;
                                                }
                                                return false;
                                            }
                                            return false;
                                        }
                                        return false;
                                    }
                                    return false;
                                }
                                return false;
                            }
                            return false;
                        }
                        return false;
                    }
                    return false;
                }
                return false;
            }
            return false;
        }
        return false;
    }

    public OERDefinition.BaseType getBaseType() {
        return this.baseType;
    }

    public int getBlock() {
        return this.block;
    }

    public List<Element> getChildren() {
        return this.children;
    }

    public ASN1Encodable getDefaultValue() {
        return this.defaultValue;
    }

    public String getDerivedTypeName() {
        String str = this.typeName;
        return str != null ? str : this.baseType.name();
    }

    public ElementSupplier getElementSupplier() {
        return this.elementSupplier;
    }

    public BigInteger getEnumValue() {
        return this.enumValue;
    }

    public Element getFirstChid() {
        return getChildren().get(0);
    }

    public String getLabel() {
        return this.label;
    }

    public BigInteger getLowerBound() {
        return this.lowerBound;
    }

    public List<Element> getOptionalChildrenInOrder() {
        return this.optionalChildrenInOrder;
    }

    public int getOptionals() {
        return this.optionals;
    }

    public Element getParent() {
        return this.parent;
    }

    public String getTypeName() {
        return this.typeName;
    }

    public BigInteger getUpperBound() {
        return this.upperBound;
    }

    public List<ASN1Encodable> getValidSwitchValues() {
        return this.validSwitchValues;
    }

    public Switch getaSwitch() {
        return this.aSwitch;
    }

    public boolean hasDefaultChildren() {
        return this.defaultValuesInChildren;
    }

    public boolean hasPopulatedExtension() {
        return this.extensionsInDefinition;
    }

    public int hashCode() {
        OERDefinition.BaseType baseType = this.baseType;
        int hashCode = (baseType != null ? baseType.hashCode() : 0) * 31;
        List<Element> list = this.children;
        int hashCode2 = (((hashCode + (list != null ? list.hashCode() : 0)) * 31) + (this.explicit ? 1 : 0)) * 31;
        String str = this.label;
        int hashCode3 = (hashCode2 + (str != null ? str.hashCode() : 0)) * 31;
        BigInteger bigInteger = this.lowerBound;
        int hashCode4 = (hashCode3 + (bigInteger != null ? bigInteger.hashCode() : 0)) * 31;
        BigInteger bigInteger2 = this.upperBound;
        int hashCode5 = (((hashCode4 + (bigInteger2 != null ? bigInteger2.hashCode() : 0)) * 31) + (this.extensionsInDefinition ? 1 : 0)) * 31;
        BigInteger bigInteger3 = this.enumValue;
        int hashCode6 = (hashCode5 + (bigInteger3 != null ? bigInteger3.hashCode() : 0)) * 31;
        ASN1Encodable aSN1Encodable = this.defaultValue;
        int hashCode7 = (hashCode6 + (aSN1Encodable != null ? aSN1Encodable.hashCode() : 0)) * 31;
        Switch r2 = this.aSwitch;
        int hashCode8 = (((hashCode7 + (r2 != null ? r2.hashCode() : 0)) * 31) + (this.defaultValuesInChildren ? 1 : 0)) * 31;
        List<Element> list2 = this.optionalChildrenInOrder;
        int hashCode9 = (hashCode8 + (list2 != null ? list2.hashCode() : 0)) * 31;
        List<ASN1Encodable> list3 = this.validSwitchValues;
        int hashCode10 = (hashCode9 + (list3 != null ? list3.hashCode() : 0)) * 31;
        ElementSupplier elementSupplier = this.elementSupplier;
        int hashCode11 = (((hashCode10 + (elementSupplier != null ? elementSupplier.hashCode() : 0)) * 31) + (this.mayRecurse ? 1 : 0)) * 31;
        String str2 = this.typeName;
        int hashCode12 = (hashCode11 + (str2 != null ? str2.hashCode() : 0)) * 31;
        Map<String, ElementSupplier> map = this.supplierMap;
        return ((((hashCode12 + (map != null ? map.hashCode() : 0)) * 31) + this.optionals) * 31) + this.block;
    }

    public int intBytesForRange() {
        if (getLowerBound() != null && getUpperBound() != null) {
            int i = 1;
            if (BigInteger.ZERO.equals(getLowerBound())) {
                int i2 = 0;
                while (i2 < OERDefinition.uIntMax.length) {
                    if (getUpperBound().compareTo(OERDefinition.uIntMax[i2]) < 0) {
                        return i;
                    }
                    i2++;
                    i *= 2;
                }
            } else {
                int i3 = 0;
                int i4 = 1;
                while (i3 < OERDefinition.sIntRange.length) {
                    if (getLowerBound().compareTo(OERDefinition.sIntRange[i3][0]) >= 0 && getUpperBound().compareTo(OERDefinition.sIntRange[i3][1]) < 0) {
                        return -i4;
                    }
                    i3++;
                    i4 *= 2;
                }
            }
        }
        return 0;
    }

    public boolean isExplicit() {
        return this.explicit;
    }

    public boolean isExtensionsInDefinition() {
        return this.extensionsInDefinition;
    }

    public boolean isFixedLength() {
        return getLowerBound() != null && getLowerBound().equals(getUpperBound());
    }

    public boolean isLowerRangeZero() {
        return BigInteger.ZERO.equals(getLowerBound());
    }

    public boolean isMayRecurse() {
        return this.mayRecurse;
    }

    public boolean isUnbounded() {
        return getUpperBound() == null && getLowerBound() == null;
    }

    public boolean isUnsignedWithRange() {
        return isLowerRangeZero() && getUpperBound() != null && BigInteger.ZERO.compareTo(getUpperBound()) < 0;
    }

    public List<Element> optionalOrDefaultChildrenInOrder() {
        List<Element> optionalChildrenInOrder;
        synchronized (this) {
            if (getOptionalChildrenInOrder() == null) {
                ArrayList arrayList = new ArrayList();
                for (Element element : getChildren()) {
                    if (!element.isExplicit() || element.getDefaultValue() != null) {
                        arrayList.add(element);
                    }
                }
                this.optionalChildrenInOrder = Collections.unmodifiableList(arrayList);
            }
            optionalChildrenInOrder = getOptionalChildrenInOrder();
        }
        return optionalChildrenInOrder;
    }

    public String rangeExpression() {
        return "(" + (getLowerBound() != null ? getLowerBound().toString() : "MIN") + " ... " + (getUpperBound() != null ? getUpperBound().toString() : "MAX") + ")";
    }

    public ElementSupplier resolveSupplier() {
        if (this.supplierMap.containsKey(this.label)) {
            return this.supplierMap.get(this.label);
        }
        Element element = this.parent;
        if (element != null) {
            return element.resolveSupplier(this.label);
        }
        throw new IllegalStateException("unable to resolve: " + this.label);
    }

    protected ElementSupplier resolveSupplier(String str) {
        String str2 = this.label + "." + str;
        if (this.supplierMap.containsKey(str2)) {
            return this.supplierMap.get(str2);
        }
        Element element = this.parent;
        if (element != null) {
            return element.resolveSupplier(str2);
        }
        throw new IllegalStateException("unable to resolve: " + str2);
    }

    public String toString() {
        return "[" + this.typeName + " " + this.baseType.name() + " '" + getLabel() + "']";
    }
}