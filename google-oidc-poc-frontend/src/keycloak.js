import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
  url: 'http://localhost:8280',
  realm: 'google-oidc-poc',
  clientId: 'google-oidc-poc-frontend',
});

export default keycloak;
