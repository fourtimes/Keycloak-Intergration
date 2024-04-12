## Setup wazuh server via SSO (single sign-on) method using Keycloack

### Keycloak
Keycloak is an open source identity and access management tool. It provides user federation, strong authentication, user management, and fine-grained authorization for modern applications and services. In this guide, we integrate the KeyCloak IdP to authenticate users into the Wazuh platform.

There are three stages in the single sign-on integration:

> 1. KeyCloak configuration
> 2. Wazuh indexer configuration
> 3. Wazuh dashboard configuration

## `KeyCloak Configuration`
1. Create a new `realm`. Log in to the Keycloak admin console, expand the master drop-down menu and click `Add Realm`. Input a name in the Realm name field; in our case, this is named `Wazuh`. Click on Create to `apply` this configuration.
  <img width="1446" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/61ed2f6c-387a-433a-99ef-50b1ec105fcc">
  

2. Create a new `client`. In the newly created realm, navigate to `Clients` > `Create Client` and modify the following parameters:

    - Client type:  select `SAML` from the drop-down menu.
    - Client ID:  input `wazuh-saml`. This is the `SP Entity ID` value which will be used later in the `config.yml` on the Wazuh indexer instance.

You can leave the rest of the values as default. Click **`Save`** to apply the configuration.

  <img width="1459" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/8f815c40-0c21-498f-a603-6e4c6470fc8a">


3. Configure client settings.

    A. Navigate to `Clients` > `Settings` and ensure the `Enabled` button is turned on. Complete the section with these parameters:

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
  <img width="1462" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/8cc1c42d-3740-4942-b7c4-4a36b9149731">
  <img width="1457" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/af186c7e-a01c-4806-80a0-4663f9b59bb1">
  <img width="1450" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/c9b67679-fc45-4c3a-a0a9-f6250623a5de">

  You can leave the rest of the values as default. Click `Save` to apply the configuration.
  
  B. Navigate to `Clients` > `Keys` and complete the section with these parameters:
      
   - Client signature required: `Off`
    
  <img width="1456" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/36e3a75a-5f55-4f4d-9f45-dad264023402">
  

  C. Navigate to `Clients` > `Advanced` > `Fine Grain SAML Endpoint Configuration` and complete the section with these parameters:
  
   - Assertion Consumer Service POST Binding URL: `https://<WAZUH_DASHBOARD_URL>/_opendistro/_security/saml/acs/idpinitiated`
   - Logout Service Redirect Binding URL: `https://<WAZUH_DASHBOARD_URL>/app/wazuh`

   <img width="1458" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/d48f629f-07f4-4d25-87ab-84eca5928876">
  
You can leave the rest of the values as default. Click `Save` to apply the configuration.

4. Create a new role. Navigate to `Realm roles` > `Create role` and complete the section with these parameters:

   - Role name: Input `admin`. This will be our backend role in the Wazuh Indexer configuration.

  <img width="1141" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/ff01ccb0-53f1-4bdf-8629-1482e65b9767">

Click on `Save` to apply the configuration.

5. Create a new user.

  A. Navigate to `Users` > `Add user` and fill in the required information.

<img width="1148" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/2b5dd8c1-4040-43bf-9b11-c18a3bd415e8">

  Click on Create to apply the configuration.

  B. Navigate to `Users` > `Credentials` > `Set password` and input a password for the newly created user. You will use these credentials to log in to the Wazuh dashboard.

<img width="1142" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/9431c983-deaf-4a51-b3e9-77f2144b1db1">

Click on `Save` to apply the configuration.

6. Create a new group and assign the user.

   A. Go to `Groups` > `Create group` and assign a name to the group. In our case, this is `Wazuh-admins`.

  <img width="1145" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/15f65f65-ccd4-4829-a494-49037d8be2b9">

   B. Click on the `Wazuh-admins created group`, navigate to `Members` > `Add member` and select the user created in the previous step. Click on `Add` to add it to the group.

   <img width="1142" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/91cde1fd-50d0-471d-afab-a2bff710d896">

   C. In the `Wazuh-admins created group` details, go to `Role Mapping` > `Assign role` and select the `admin` role created in step 3. Click on `Assign` to apply the configuration.
   <img width="1140" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/7f7bc9c6-73d7-45a1-8be7-a2a45c9e4c7c">


7. Configure protocol mapper.

  a. Navigate to `Client scopes > role_list > Mappers > Configure a new mapper`.

<img width="1150" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/4aedb7f4-a517-4cb4-9e14-0db9bde64e83">

 b. Select `Role list` from the list as seen below:
 
 <img width="912" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/ee37f0ff-ec36-42c0-8b30-421cd4a8caab">

 c. Complete the Add mapper section with these parameters:

   - Mapper type: `Role list`
   - Name: `wazuhRoleKey`. You can use any name here.
   - Role attribute name: `Roles`. This will be the roles_key on the Wazuh Indexer configuration.
   - SAML Attribute NameFormat: `Basic`
   - Single Role Attribute: `On`

   <img width="1148" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/d9511668-ae80-4ba1-b2af-5bf9099cab73">

  Click on `Save` to apply the configuration. 

  d. After that We will see the Created Role list. We will see below ouput only(`wazuhRoleKey`). In case is there any other role list we must delete that role list.

  <img width="1460" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/3ddf55a1-0ca5-43c0-8fc7-5635995f949f">

8. Note the necessary parameters from the SAML settings of Keycloak.

   a. The parameters already obtained during the integration are:

      - sp.entity_id: `wazuh-saml`
      - roles_key: `Roles`
      - kibana_url: `https://<WAZUH_DASHBOARD_URL>`

   b. To obtain the remaining parameters.

      - Navigate to `Clients` and select the name of your client. In our case, this is `wazuh-saml`.
      - Navigate to `Action` > `Download adapter` config, and ensure the Format option is `Mod Auth Mellon` files.
      - Click on Download to download the remaining files.
        
   <img width="1141" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/0229ab0e-1e66-4734-a83a-001faa4bc038">

   c. The downloaded files contain the `idp.metadata.xml` file and the `sp.metadata.xml` file.

      - The `idp.entityID` parameter is in the `idp.metadata.xml` file.
      - The exchange_key parameter is found in the `ds:X509Certificate` field in the `idp.metadata.xml` file.

    <img width="1283" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/2871c584-0bf6-4c4e-bcef-62e5272aad0f">


 ## `Wazuh Indexer Configuration`
Go to the Wazuh server and edit the Wazuh indexer security configuration files. We recommend that you back up these files before you carry out the configuration.

1. Place the `idp.metadata.xml` and `sp.metadata.xml` files within the `/etc/wazuh-indexer/opensearch-security/` directory. Set the file ownership to wazuh-indexer using the following command:
```sh
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/idp.metadata.xml
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/sp.metadata.xml
```
2. Edit the `/etc/wazuh-indexer/opensearch-security/config.yml` file and change the following values:

    - Set the order in `basic_internal_auth_domain` to `0`, and set the `challenge` flag to `false`.
    - The `idp.entityID` parameter is in the `idp.metadata.xml` file.
    -  The exchange_key parameter is found in the `ds:X509Certificate` field in the `idp.metadata.xml` file.
    - Include a `saml_auth_domain` configuration under the `authc` section similar to the following:

```yml
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 1
        authentication_backend:
          type: noop
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_file: '/etc/wazuh-indexer/opensearch-security/idp.metadata.xml'
              entity_id: 'https://keycloak.fourcodes.net/realms/Wazuh'
            sp:
              entity_id: wazuh-saml
              metadata_file: '/etc/wazuh-indexer/opensearch-security/sp.metadata.xml'
            kibana_url: 'https://<WAZUH_DASHBOARD_ADDRESS>'
            roles_key: Roles
            exchange_key: 'MIICmTCCAYECBgGOy+NIWTANBgkqhkiG9w0BAQsFA.........................'
      proxy_auth_domain:
        description: "Authenticate via proxy"
        http_enabled: false
        transport_enabled: false
        order: 3
        http_authenticator:
         type: proxy
         challenge: false
         config:
            user_header: "x-proxy-user"
            roles_header: "x-proxy-roles"
        authentication_backend:
          type: noop
```

Ensure to change the following parameters to their corresponding value:
  - idp.metadata_file
  - idp.entity_id
  - sp.entity_id
  - sp.metadata_file
  - kibana_url
  - roles_key
  - exchange_key

3. Run the `securityadmin` script to load the configuration changes made in the `config.yml` file.
```sh
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/config.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv
```
The command output must be similar to the following:
```
Security Admin v7
Will connect to localhost:9200 ... done
Connected as "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
OpenSearch Version: 2.8.0
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ...
Clustername: wazuh-cluster
Clusterstate: GREEN
Number of nodes: 1
Number of data nodes: 1
.opendistro_security index already exists, so we do not need to create one.
Populate config from /etc/wazuh-indexer/opensearch-security
Will update '/config' with /etc/wazuh-indexer/opensearch-security/config.yml
   SUCC: Configuration for 'config' created or updated
SUCC: Expected 1 config types for node {"updated_config_types":["config"],"updated_config_size":1,"message":null} is 1 (["config"]) due to: null
Done with success
```

4. Edit the `/etc/wazuh-indexer/opensearch-security/roles_mapping.yml` file and change the following values:
```yml
all_access:
  reserved: false
  hidden: false
  backend_roles:
  - "admin"
```
5. Run the `securityadmin` script to load the configuration changes made in the `roles_mapping.yml` file.
```sh
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv
```
The command output must be similar to the following:
```
Security Admin v7
Will connect to localhost:9200 ... done
Connected as "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
OpenSearch Version: 2.8.0
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ...
Clustername: wazuh-cluster
Clusterstate: GREEN
Number of nodes: 1
Number of data nodes: 1
.opendistro_security index already exists, so we do not need to create one.
Populate config from /etc/wazuh-indexer/opensearch-security
Will update '/rolesmapping' with /etc/wazuh-indexer/opensearch-security/roles_mapping.yml
   SUCC: Configuration for 'rolesmapping' created or updated
SUCC: Expected 1 config types for node {"updated_config_types":["rolesmapping"],"updated_config_size":1,"message":null} is 1 (["rolesmapping"]) due to: null
Done with success
```
## `Wazuh dashboard configuration`
1. Check the value of `run_as` in the `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` configuration file. If `run_as` is set to `false`, proceed to the next step. 
```yml
hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: "<wazuh-wui-password>"
      run_as: false
```
2. Edit the Wazuh dashboard configuration file. Add these configurations to `/etc/wazuh-dashboard/opensearch_dashboards.yml`. We recommend that you back up these files before you carry out the configuration.
```sh
opensearch_security.auth.type: "saml"
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"]
opensearch_security.session.keepalive: false
```
3. Restart the Wazuh dashboard service using this command:
```sh
systemctl restart wazuh-dashboard
```
4. Test the configuration. Go to your `Wazuh dashboard URL` and log in with your Keycloak account with the keycloak `user` with `password`.

<img width="1469" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/bca706e5-f98e-4647-bb42-dc56cca45695">

<img width="1469" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/cc7b42e6-a01f-4320-ace5-b1807f915438">




**REFERENCE**

> https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/administrator/keycloak.html#keycloak










 
