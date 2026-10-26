package com.secufusion.oidcpoc.tenant;

/** Per-request holder, set by {@link TenantContextFilter} and always cleared in a finally block. */
public final class TenantContextHolder {

    private static final ThreadLocal<TenantContext> CURRENT = new ThreadLocal<>();

    private TenantContextHolder() {
    }

    static void set(TenantContext context) {
        CURRENT.set(context);
    }

    static void clear() {
        CURRENT.remove();
    }

    /** Fails closed: data access without a tenant is an error, never "all tenants". */
    public static TenantContext require() {
        TenantContext ctx = CURRENT.get();
        if (ctx == null) {
            throw new MissingTenantContextException();
        }
        return ctx;
    }

    public static class MissingTenantContextException extends RuntimeException {
        public MissingTenantContextException() {
            super("No tenant context for this request");
        }
    }
}
