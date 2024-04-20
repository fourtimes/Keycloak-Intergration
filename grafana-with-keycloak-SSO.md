# 1. Grafana with KeyCloak SingleSignOn Implemention using Docker
```yml
---
version: '3'
services:
  grafana:
    image: grafana/grafana
    container_name: grafana
    ports:
      - 3000:3000
    restart: unless-stopped
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_SERVER_DOMAIN: "grafana-dashboard-client"
      GF_SERVER_ROOT_URL: "http://(public-ip):3000"
      GF_AUTH_GENERIC_OAUTH_ENABLED: "true"
      GF_AUTH_GENERIC_OAUTH_NAME: "SingleSignOn"
      GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP: "true"
      GF_AUTH_GENERIC_OAUTH_CLIENT_ID: "grafana-dashboard-client"
      GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET: "h1UEkI7694zjC2dPRTpGhz75XwgL24u8"
      GF_AUTH_GENERIC_OAUTH_SCOPES: openid profile email 
      GF_AUTH_GENERIC_OAUTH_AUTH_URL: "https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/auth"
      GF_AUTH_GENERIC_OAUTH_TOKEN_URL: "https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/token"
      GF_AUTH_GENERIC_OAUTH_API_URL: "https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/userinfo"
      GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: contains(realm_access.roles[*], 'admin') && 'Admin' || contains(realm_access.roles[*], 'editor') && 'Editor' || 'Viewer'
      GF_AUTH_GENERIC_OAUTH_REDIRECT_URL: "http://(public-ip):3000/oauth/callback"
      GF_AUTH_GENERIC_OAUTH_LOGOUT_URL: "https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/logout"
      # Additional session handling settings
      GF_SESSION_COOKIE_SECURE: "true"
      GF_SESSION_COOKIE_SAMESITE: "None" # or "Lax"
      GF_SESSION_LIFETIME: "3600" # Session lifetime in seconds, e.g., 1 hour
      GF_STRICT_FLUSH_INTERVAL: "true"
```
## We should enter the redirect url in the keycloak console.
<img width="1470" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/47d211a7-ddac-4b14-9374-2396c9145001">


_Note:_
> [!TIP]
> In this grafana SSO, we must create clients under the client type `OpenID Connect`
> 
> Based on your keycloak Realm we must change the variable below in the yaml file
> 
    - GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET
    - GF_AUTH_GENERIC_OAUTH_AUTH_URL
    - GF_AUTH_GENERIC_OAUTH_TOKEN_URL
    - GF_AUTH_GENERIC_OAUTH_API_URL
    - GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH
    - GF_AUTH_GENERIC_OAUTH_LOGOUT_URL



> [!IMPORTANT]
> https://stackoverflow.com/questions/68741412/grafana-generic-oauth-role-assignment



# 2. Grafana as a service with KeyCloak SingleSignOn Implemention
1. Install grafana in ubuntu
2. Create a file - grafana.sh. Add the below line inside the file.
 ```sh
#!/bin/bash

sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
sudo systemctl status grafana-server
```

3. change the permission
```sh
sudo chmod +x grafana.sh
```
4. execute the file
```sh
./grafana.sh
```
5. Create the `Client` in the keycloak console and configure the client.

_Note:_
> [!TIP]
> In this grafana SSO, we must create clients under the client type `OpenID Connect`

6. Add the keycloak configuration in grafana service

    - Create the ini file `sudo vim /etc/grafana/grafana.ini`
```ini
[server]
root_url = http://3.85.125.143:3000

[auth.generic_oauth]
enabled = true
name = Keycloak-OAuth
allow_sign_up = true
client_id = grafana-dashboard-client
client_secret = h1UEkI7694zjC2dPRTpGhz75XwgL24u8
scopes = openid profile email
auth_url = https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/auth
token_url = https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/token
api_url = https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/userinfo
role_attribute_path = contains(realm_access.roles[*], 'admin') && 'Admin' || contains(realm_access.roles[*], 'editor') && 'Editor' || 'Viewer'  
groups_attribute_path = groups
logout_redirect_url = https://keycloak.fourcodes.net/realms/fourcodes/protocol/openid-connect/logout
```
7.  Go to the browser. Enter this url -  `http://3.85.125.143:3000`

<img width="1464" alt="image" src="https://github.com/fourtimes/Keycloak-Intergration/assets/91359308/66dc0f21-dd40-46f7-b34c-91be162e9512">

Reference

https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/keycloak/#teamsync
