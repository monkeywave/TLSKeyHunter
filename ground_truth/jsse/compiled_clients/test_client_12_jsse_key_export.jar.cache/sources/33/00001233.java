package org.openjsse.sun.security.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.openjsse.sun.security.ssl.SSLLogger;
import org.openjsse.sun.security.util.RegisteredDomain;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName.class */
public class DomainName {
    private static final Map<String, Rules> cache = new ConcurrentHashMap();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$Match.class */
    public interface Match {
        RegisteredDomain registeredDomain();

        Rule.Type type();
    }

    private DomainName() {
    }

    public static RegisteredDomain registeredDomain(String domain) {
        Match match = getMatch(domain);
        if (match != null) {
            return match.registeredDomain();
        }
        return null;
    }

    private static Match getMatch(String domain) {
        if (domain == null) {
            throw new NullPointerException();
        }
        Rules rules = Rules.getRules(domain);
        if (rules == null) {
            return null;
        }
        return rules.match(domain);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$Rules.class */
    public static class Rules {
        private final LinkedList<RuleSet> ruleSets = new LinkedList<>();
        private final boolean hasExceptions;

        private Rules(InputStream is) throws IOException {
            String line;
            InputStreamReader isr = new InputStreamReader(is, "UTF-8");
            BufferedReader reader = new BufferedReader(isr);
            boolean hasExceptions = false;
            int read = reader.read();
            while (true) {
                int type = read;
                if (type == -1 || (line = reader.readLine()) == null) {
                    break;
                }
                int numLabels = RuleSet.numLabels(line);
                if (numLabels != 0) {
                    RuleSet ruleset = getRuleSet(numLabels - 1);
                    ruleset.addRule(type, line);
                    hasExceptions |= ruleset.hasExceptions;
                }
                read = reader.read();
            }
            this.hasExceptions = hasExceptions;
        }

        static Rules getRules(String domain) {
            String tld = getTopLevelDomain(domain);
            if (!tld.isEmpty()) {
                return (Rules) DomainName.cache.computeIfAbsent(tld, k -> {
                    return createRules(tld);
                });
            }
            return null;
        }

        private static String getTopLevelDomain(String domain) {
            int n = domain.lastIndexOf(46);
            if (n == -1) {
                return domain;
            }
            return domain.substring(n + 1);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Rules createRules(String tld) {
            try {
                InputStream pubSuffixStream = getPubSuffixStream();
                if (pubSuffixStream != null) {
                    Rules rules = getRules(tld, new ZipInputStream(pubSuffixStream));
                    if (pubSuffixStream != null) {
                        if (0 != 0) {
                            pubSuffixStream.close();
                        } else {
                            pubSuffixStream.close();
                        }
                    }
                    return rules;
                }
                if (pubSuffixStream != null) {
                    if (0 != 0) {
                        pubSuffixStream.close();
                    } else {
                        pubSuffixStream.close();
                    }
                }
                return null;
            } catch (IOException e) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("cannot parse public suffix data for " + tld + ": " + e.getMessage(), new Object[0]);
                    return null;
                }
                return null;
            }
        }

        private static InputStream getPubSuffixStream() {
            InputStream is = (InputStream) AccessController.doPrivileged(new PrivilegedAction<InputStream>() { // from class: org.openjsse.sun.security.util.DomainName.Rules.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // java.security.PrivilegedAction
                public InputStream run() {
                    File f = new File(System.getProperty("java.home"), "lib/security/public_suffix_list.dat");
                    try {
                        return new FileInputStream(f);
                    } catch (FileNotFoundException e) {
                        return null;
                    }
                }
            });
            if (is == null && SSLLogger.isOn && SSLLogger.isOn("ssl") && SSLLogger.isOn("trustmanager")) {
                SSLLogger.fine("lib/security/public_suffix_list.dat not found", new Object[0]);
            }
            return is;
        }

        private static Rules getRules(String tld, ZipInputStream zis) throws IOException {
            boolean found = false;
            ZipEntry ze = zis.getNextEntry();
            while (ze != null && !found) {
                if (ze.getName().equals(tld)) {
                    found = true;
                } else {
                    ze = zis.getNextEntry();
                }
            }
            if (!found) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.fine("Domain " + tld + " not found", new Object[0]);
                    return null;
                }
                return null;
            }
            return new Rules(zis);
        }

        private RuleSet getRuleSet(int index) {
            if (index < this.ruleSets.size()) {
                return this.ruleSets.get(index);
            }
            RuleSet r = null;
            for (int i = this.ruleSets.size(); i <= index; i++) {
                r = new RuleSet(i + 1);
                this.ruleSets.add(r);
            }
            return r;
        }

        Match match(String domain) {
            Match possibleMatch = null;
            Iterator<RuleSet> it = this.ruleSets.descendingIterator();
            while (it.hasNext()) {
                RuleSet ruleSet = it.next();
                Match match = ruleSet.match(domain);
                if (match != null) {
                    if (match.type() == Rule.Type.EXCEPTION || !this.hasExceptions) {
                        return match;
                    }
                    if (possibleMatch == null) {
                        possibleMatch = match;
                    }
                }
            }
            return possibleMatch;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$Rules$RuleSet.class */
        public static class RuleSet {
            private final int numLabels;
            private final Set<Rule> rules = new HashSet();
            boolean hasExceptions = false;
            private static final RegisteredDomain.Type[] AUTHS = RegisteredDomain.Type.values();

            RuleSet(int n) {
                this.numLabels = n;
            }

            void addRule(int auth, String rule) {
                if (rule.startsWith("!")) {
                    this.rules.add(new Rule(rule.substring(1), Rule.Type.EXCEPTION, AUTHS[auth]));
                    this.hasExceptions = true;
                } else if (rule.startsWith("*.") && rule.lastIndexOf(42) == 0) {
                    this.rules.add(new Rule(rule.substring(2), Rule.Type.WILDCARD, AUTHS[auth]));
                } else if (rule.indexOf(42) == -1) {
                    this.rules.add(new Rule(rule, Rule.Type.NORMAL, AUTHS[auth]));
                } else {
                    this.rules.add(new OtherRule(rule, AUTHS[auth], split(rule)));
                }
            }

            Match match(String domain) {
                Match match = null;
                for (Rule rule : this.rules) {
                    switch (rule.type) {
                        case NORMAL:
                            if (match == null) {
                                match = matchNormal(domain, rule);
                                break;
                            } else {
                                break;
                            }
                        case WILDCARD:
                            if (match == null) {
                                match = matchWildcard(domain, rule);
                                break;
                            } else {
                                break;
                            }
                        case OTHER:
                            if (match == null) {
                                match = matchOther(domain, rule);
                                break;
                            } else {
                                break;
                            }
                        case EXCEPTION:
                            Match excMatch = matchException(domain, rule);
                            if (excMatch == null) {
                                break;
                            } else {
                                return excMatch;
                            }
                    }
                }
                return match;
            }

            private static LinkedList<String> split(String rule) {
                String[] labels = rule.split("\\.");
                return new LinkedList<>(Arrays.asList(labels));
            }

            /* JADX INFO: Access modifiers changed from: private */
            public static int numLabels(String rule) {
                if (rule.equals("")) {
                    return 0;
                }
                int len = rule.length();
                int count = 0;
                int index = 0;
                while (index < len) {
                    int pos = rule.indexOf(46, index);
                    if (pos == -1) {
                        return count + 1;
                    }
                    index = pos + 1;
                    count++;
                }
                return count;
            }

            private Match matchNormal(String domain, Rule rule) {
                int index = labels(domain, this.numLabels);
                if (index == -1) {
                    return null;
                }
                String substring = domain.substring(index);
                if (rule.domain.equals(substring)) {
                    return new CommonMatch(domain, rule, index);
                }
                return null;
            }

            private Match matchWildcard(String domain, Rule rule) {
                int index = labels(domain, this.numLabels - 1);
                if (index > 0) {
                    String substring = domain.substring(index);
                    if (rule.domain.equals(substring)) {
                        return new CommonMatch(domain, rule, labels(domain, this.numLabels));
                    }
                    return null;
                }
                return null;
            }

            private Match matchException(String domain, Rule rule) {
                int index = labels(domain, this.numLabels);
                if (index == -1) {
                    return null;
                }
                String substring = domain.substring(index);
                if (rule.domain.equals(substring)) {
                    return new CommonMatch(domain, rule, labels(domain, this.numLabels - 1));
                }
                return null;
            }

            private Match matchOther(String domain, Rule rule) {
                OtherRule otherRule = (OtherRule) rule;
                LinkedList<String> target = split(domain);
                int diff = target.size() - this.numLabels;
                if (diff < 0) {
                    return null;
                }
                boolean found = true;
                int i = 0;
                while (true) {
                    if (i >= this.numLabels) {
                        break;
                    }
                    String ruleLabel = otherRule.labels.get(i);
                    String targetLabel = target.get(i + diff);
                    if (ruleLabel.charAt(0) == '*' || ruleLabel.equalsIgnoreCase(targetLabel)) {
                        i++;
                    } else {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return new OtherMatch(rule, this.numLabels, target);
                }
                return null;
            }

            private static int labels(String s, int n) {
                if (n < 1) {
                    return -1;
                }
                int index = s.length();
                for (int i = 0; i < n; i++) {
                    int next = s.lastIndexOf(46, index);
                    if (next == -1) {
                        if (i == n - 1) {
                            return 0;
                        }
                        return -1;
                    }
                    index = next - 1;
                }
                return index + 2;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$Rule.class */
    public static class Rule {
        String domain;
        Type type;
        RegisteredDomain.Type auth;

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$Rule$Type.class */
        public enum Type {
            EXCEPTION,
            NORMAL,
            OTHER,
            WILDCARD
        }

        Rule(String domain, Type type, RegisteredDomain.Type auth) {
            this.domain = domain;
            this.type = type;
            this.auth = auth;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$OtherRule.class */
    public static class OtherRule extends Rule {
        List<String> labels;

        OtherRule(String domain, RegisteredDomain.Type auth, List<String> labels) {
            super(domain, Rule.Type.OTHER, auth);
            this.labels = labels;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$RegisteredDomainImpl.class */
    private static class RegisteredDomainImpl implements RegisteredDomain {
        private final String name;
        private final RegisteredDomain.Type type;
        private final String publicSuffix;

        RegisteredDomainImpl(String name, RegisteredDomain.Type type, String publicSuffix) {
            this.name = name;
            this.type = type;
            this.publicSuffix = publicSuffix;
        }

        @Override // org.openjsse.sun.security.util.RegisteredDomain
        public String name() {
            return this.name;
        }

        @Override // org.openjsse.sun.security.util.RegisteredDomain
        public RegisteredDomain.Type type() {
            return this.type;
        }

        @Override // org.openjsse.sun.security.util.RegisteredDomain
        public String publicSuffix() {
            return this.publicSuffix;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$CommonMatch.class */
    public static class CommonMatch implements Match {
        private String domain;
        private int publicSuffix;
        private int registeredDomain;
        private final Rule rule;

        CommonMatch(String domain, Rule rule, int publicSuffix) {
            this.domain = domain;
            this.publicSuffix = publicSuffix;
            this.rule = rule;
            this.registeredDomain = domain.lastIndexOf(46, publicSuffix - 2);
            if (this.registeredDomain == -1) {
                this.registeredDomain = 0;
            } else {
                this.registeredDomain++;
            }
        }

        @Override // org.openjsse.sun.security.util.DomainName.Match
        public RegisteredDomain registeredDomain() {
            if (this.publicSuffix == 0) {
                return null;
            }
            return new RegisteredDomainImpl(this.domain.substring(this.registeredDomain), this.rule.auth, this.domain.substring(this.publicSuffix));
        }

        @Override // org.openjsse.sun.security.util.DomainName.Match
        public Rule.Type type() {
            return this.rule.type;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/DomainName$OtherMatch.class */
    public static class OtherMatch implements Match {
        private final Rule rule;
        private final int numLabels;
        private final LinkedList<String> target;

        OtherMatch(Rule rule, int numLabels, LinkedList<String> target) {
            this.rule = rule;
            this.numLabels = numLabels;
            this.target = target;
        }

        @Override // org.openjsse.sun.security.util.DomainName.Match
        public RegisteredDomain registeredDomain() {
            int nlabels = this.numLabels + 1;
            if (nlabels > this.target.size()) {
                return null;
            }
            return new RegisteredDomainImpl(getSuffixes(nlabels), this.rule.auth, getSuffixes(this.numLabels));
        }

        @Override // org.openjsse.sun.security.util.DomainName.Match
        public Rule.Type type() {
            return this.rule.type;
        }

        private String getSuffixes(int n) {
            Iterator<String> targetIter = this.target.descendingIterator();
            StringBuilder sb = new StringBuilder();
            while (n > 0 && targetIter.hasNext()) {
                String s = targetIter.next();
                sb.insert(0, s);
                if (n > 1) {
                    sb.insert(0, '.');
                }
                n--;
            }
            return sb.toString();
        }
    }
}