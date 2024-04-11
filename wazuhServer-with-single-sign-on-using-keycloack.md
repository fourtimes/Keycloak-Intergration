## Setup wazuh server via SSO (single sign-on) method using Keycloack

### Keycloak
Keycloak is an open source identity and access management tool. It provides user federation, strong authentication, user management, and fine-grained authorization for modern applications and services. In this guide, we integrate the KeyCloak IdP to authenticate users into the Wazuh platform.

There are three stages in the single sign-on integration:

> 1. KeyCloak configuration
> 2. Wazuh indexer configuration
> 3. Wazuh dashboard configuration

### `KeyCloak configuration`
1. Create a new `realm`. Log in to the Keycloak admin console, expand the master drop-down menu and click `Add Realm`. Input a name in the Realm name field; in our case, this is named `Wazuh`. Click on Create to `apply` this configuration.
  <img width="1446" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/61ed2f6c-387a-433a-99ef-50b1ec105fcc">
  

2. Create a new `client`. In the newly created realm, navigate to `Clients` > `Create Client` and modify the following parameters:

**Client type:** select `SAML` from the drop-down menu.

**Client ID:** input `wazuh-saml`. This is the `SP Entity ID` value which will be used later in the `config.yml` on the Wazuh indexer instance.

You can leave the rest of the values as default. Click **`Save`** to apply the configuration.

  <img width="1459" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/8f815c40-0c21-498f-a603-6e4c6470fc8a">


3. Configure client settings.

    Navigate to `Clients` > `Settings` and ensure the Enabled button is turned on. Complete the section with these parameters:

- Client ID: `wazuh-saml`
- Name: `Wazuh SSO`
- Valid redirect URIs: `https://<WAZUH_DASHBOARD_URL>/*`
- IDP-Initiated SSO URL name: `wazuh-dashboard`
- Name ID format: `username`
- Force POST binding: `ON`
- Include AuthnStatement: `ON`
- Sign documents: `ON`
- Sign assertions: `ON`
- Signature algorithm: `RSA_SHA256`
- SAML signature key name: `KEY_ID`
- Canonicalization method: `EXCLUSIVE`
- Front channel logout: `ON`

Replace the `WAZUH_DASHBOARD_URL` field with the corresponding URL of your Wazuh dashboard instance.

<img width="1465" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/3a838f9a-17dd-497c-a303-0fc8b9b954d1">
<img width="1451" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/c188d5c8-2104-4bdf-b845-51bae460e0da">

