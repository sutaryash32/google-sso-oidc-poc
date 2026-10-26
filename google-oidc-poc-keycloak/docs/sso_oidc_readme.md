# Google Workspace SSO via Keycloak (OIDC) — POC Guide & Production Playbook

> **Update:** this guide describes the original single-domain POC. The system is now multi-tenant and **hub-and-spoke**: a realm
> per tenant (`yserious` is the first), a shared Google IdP in the `master` realm, a tenant gate in each realm and on master, and a backend
> that trusts each realm's issuer only for its own tenant. The Google Cloud steps below (OAuth client, consent screen) are still accurate,
> except that the redirect URI to register is now master's: `http://localhost:8280/realms/master/broker/google/endpoint`. For how login,
> the gates and tenants work now, see [the project README](../README.md) and [hub_and_spoke_poc_plan.md](hub_and_spoke_poc_plan.md);
> the Keycloak steps and the single-domain Hosted Domain restriction described here belong to the earlier design.
