package com.secufusion.spike.tenant;

import java.util.Locale;

/** Domain normalisation shared by the registry and the resolver. Exact match only, never suffix match. */
public final class Domains {

    private Domains() {
    }

    /** Lower-case, trim, drop one trailing dot. Returns null for blank input. */
    public static String normalize(String domain) {
        if (domain == null) {
            return null;
        }
        String d = domain.trim().toLowerCase(Locale.ROOT);
        if (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        return d.isEmpty() ? null : d;
    }

    /** Domain part of an email address, normalised; null if the value is not an email. */
    public static String domainOfEmail(String email) {
        if (email == null) {
            return null;
        }
        int at = email.lastIndexOf('@');
        if (at <= 0 || at == email.length() - 1) {
            return null;
        }
        return normalize(email.substring(at + 1));
    }
}
