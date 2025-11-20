# sftpgo-qnap-authgateway

Tiny HTTP gateway that lets SFTPGo authenticate users transparently against a QNAP NAS and auto‑map all shares
with granted permission as virtual folders in sftpgo. Running entirely with Container Station on QNAP NAS.

This provides the long-overdue missing feature of a SFTP server in today's QNAP NAS'es in the most-transparent
way possible with central user and permission management remaining in QNAP UI.

Designed to be used with [sftpgo](https://github.com/drakkan/sftpgo) and ran on 
[QNAP's Container Station](https://www.qnap.com/en-us/products/container_station.html).

# Features

- Authenticates via QNAP API to verify user-provided credentials.
- Builds SFTPGo virtual folders from QNAP shares the user has access to.
- Certificate validation for both QNAP and SFTPGo can be disabled, if needed.
- If `SFTPGO_FOLDER_SYNC` is enabled and sftpgo credentials are provided, it syncs virtual folders from
  QNAP to sftpgo during each successful login.
- If file `/etc/passwd` from QNAP NAS is mounted to `/qnap_passwd` within the container, it will be used to map user
  and group IDs to usernames to handle permissions properly. Unfortunately, QNAP API does not provide this
  information. Even when the name suggests otherwise, this file does not contain any passwords nor hashes.

# Requirements

- QNAP NAS (tested QuTS hero 5.2.7.3297) with:
  - Container Station installed
  - Respective users do need `Application Privilege` named `Application - File Station` 
    which is required that the user can query its accessible shares via QNAP API
- SFTPGo (tested 2.7.0)

# How it works

The procedure is as follows:

1) Users can log in to QNAP using SFTP (or any other protocol sftpgo provides) to sftpgo service, run in a container.
2) sftpgo makes an HTTP call to the auth gateway to validate authentication. 
3) The auth gateway uses the same user credentials provided to perform a login to QNAP API to check for credentials.
4) If authentication is successful, it retrieves all shared folders the user has permissions to.
5) If `/qnap_passwd` is mounted in container, it will be used to map user/group IDs to usernames for proper permissions.
6) Then, the auth gateway provides sftpgo a response to allow login or deny access. 
7) sftpgo then gets the response and, if successful, provides access to the QNAP shared folders the user has access to.

## SFTP Client Example

```text
# sftp -P 9022 test@192.168.0.10
test@192.168.0.10's password:
Connected to 192.168.0.10.
sftp> ls -l
drwxr-xr-x    1 0        0               0 Jan 1  1970 Public
drwxr-xr-x    1 0        0               0 Jan 1  1970 Test
sftp>
sftp> cd Test/
sftp> ls -l
sftp> put test.txt
Uploading test.txt to /Test/test.txt
test.txt                       100%    0     0.0KB/s   00:00
sftp> ls -l
-rwxrwxrwx    1 1004     100         0 Nov 16 01:32 test.txt
```

## Diagram

```text
 ┌───────────────────────────┐
 │        SFTP Client        │
 │ (User connects to SFTPGO) │
 └──────────────┬────────────┘
                │                       
                │ 1) User login attempt 
                │
   ┌────────────▼────────────┐                      ┌──────────────────────────┐
   │          SFTPGO         │──────────────────────│       Auth Gateway       │
   │  Containerized service  │ 2) HTTP auth request | (HTTP endpoint for auth) │
   └────────────┬────────────┘                      └───────────┬──────────────┘
                │                                               │
                │                                               │ 3) Gateway logs in to QNAP API
                │                                               │     with same credentials
                │                                               │
                │                                  ┌────────────▼─────────────┐
                │                                  │         QNAP API         │
                │                                  │ Validates credentials    │
                │                                  │ Returns permitted shares │
                │                                  └────────────┬─────────────┘
                │                                               │
                │                                               │ 4) Return folders
                │                                               │
                │<──────────────────────────────────────────────┘
                │       5) If /qnap_passwd mounted:
                │          → Map username → UID/GID
                │
                │<───────────────────────────
                │ 6) Auth result (allow/deny)
                │
  ┌─────────────▼────────────┐
  │          SFTPGO          │
  │  Grants / denies access  │
  └─────────────┬────────────┘
                │
                │ 7) If allowed, expose QNAP shares
                │
      ┌─────────▼─────────┐
      │ User gets access  │
      │ to shared folders │
      └───────────────────┘
```

# Quick Start

- Create a container on QNAP with this application.
    - Mount `/share` from QNAP to `/share` (or whatever is set in `QNAP_SHARE_PATH`) within the container.
- Configure the environment variables and start the service.
- Point SFTPGo external auth to the service endpoint:
    - `external_auth_hook=https://sftpgo-qnap-authgw/auth`
    - `external_auth_scope=5` (only password and keyboard-interactive; any other is unsupported)
- Disable the auto-ban on invalid logins on QNAP for this service and configure sftpgo to take care of it.
  (To prevent the auth gateway from being blocked, instead of the user)
- If you want to take advantage of automated virtual folders sync during successful user login, make sure to enable 
  REST API on SFTPGo and provide the below environment variable.

# Roadmap/Ideas

- Implement HTTPS webserver support
- Implement queue for sftpgo virtual sync based on virtual folders. Also add proper locking.
- Implement some basic caching for sftpgo virtual sync folders for performance (e.g., update only every 5s)
- Implement some basic caching for passwd-file reading 
  (e.g., read once at startup, update cache if user not found? modification date?)

# Configuration

## Setup sftpgo service account (optional)

If you want to enable automated virtual folder managed, this service needs a user account with proper permissions 
during the login. The user can either be created manually, or via API. As can be seen for the API calls below.

**Note**: Please replace URLs, username, and password accordingly.

```shell
# 1. Set all variables to your needs
GW_URL=http://127.0.0.1:8080
GW_ADMIN_USER=admin
GW_ADMIN_PASS=admin
GW_SERVICE_USER=sa-qnap-authgw
GW_SERVICE_PASS=password

# 2. Get an access token
GW_TOKEN=$(
  curl -s -u "${GW_ADMIN_USER}:${GW_ADMIN_PASS}" \
    -X GET "${GW_URL}/api/v2/token" \
    -H "Accept: application/json" |
  jq -r '.access_token'
)

# 3. Create a new admin account for the Auth Gateway
# (only "manage_folders" permission is required)
curl -X POST "${GW_URL}/api/v2/admins" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $GW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": 1,
    "username": "'"${GW_SERVICE_USER}"'",
    "description": "sftpgo-qnap-authgateway service account",
    "password": "'"${GW_SERVICE_PASS}"'",
    "permissions": ["manage_folders"]
  }'

# 4. Get newly created admin account details
curl -X GET "${GW_URL}/api/v2/admins/${GW_SERVICE_USER}" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $GW_TOKEN"

# 5. Logout (invalidate the token)
curl -X GET "${GW_URL}/api/v2/logout" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $GW_TOKEN"
```

## Environment variables

| Variable                    | Default                                                    | Description                                                                 |
|-----------------------------|------------------------------------------------------------|-----------------------------------------------------------------------------|
| `QNAP_URL`                  | `https://host.docker.internal`                             | Full URL, e.g. `https://10.0.0.100`                                         |
| `QNAP_CHECK_CERT`           | `true`                                                     | Verify QNAP TLS cert; set to `false` to disable verification.               |
| `QNAP_SHARE_PATH`           | `/share/{name}/`                                           | Absolute folder on QNAP where share is located at                           |
| `SFTPGO_FOLDER_SYNC`        | `false`                                                    | Enable virtual folder sync upon successful login                            |
| `SFTPGO_FOLDER_DESCRIPTION` | `QNAP Share: {name} / Managed by sftpgo-qnap-auth-gateway` | Use specific folder description in sftpgo during sync                       |
| `SFTPGO_ACCOUNT_EXPIRATION` | `5m`                                                       | Set expiration time after of sftpgo user after successful login             |
| `SFTPGO_AUTH_CACHE_TIME`    | by default same as `SFTPGO_ACCOUNT_EXPIRATION`             | Define time a login is cached by sftpgo. Default same as expiration. 0=off. |                                                     
| `SFTPGO_API_URL`            | `http://host.docker.internal:8080`                         | API URL for sftpgo instance for virtual folder sync                         |
| `SFTPGO_API_USER`           | `sa-qnap-authgw`                                           | sftpgo service account username; required for virtual folder sync           |
| `SFTPGO_API_PASS`           | none                                                       | sftpgo service account password; required for virtual folder sync           |
| `SFTPGO_CHECK_CERT`         | `true`                                                     | Verify sftpgo TLS cert; set to `false` to disable verification              |
| `SFTPGO_HOMEDIR`            | `/var/tmp`                                                 | sftpgo requires this, empty folder is OK; "{user}" is replaced to username  |
| `AUTHGW_TLS`                | `false`                                                    | Enable TLS and HTTPS \(not implemented yet\)                                |
| `LOG_LEVEL`                 | `info`                                                     | Log level \(allowed: trace\|debug\|info\|warn\|error\)                      |

## `compose.yml` example

**Note**: This contains very basic passwords and should not be used in production. Change them.

Use `Container Station - Applications - Create` and use below example compose configuration as a quick start.

```yaml
services:
  sftpgo:
    image: drakkan/sftpgo:v2.7-distroless-slim
    container_name: sftpgo
    restart: unless-stopped
    user: "0:100" # UID=0/root needed to change permissions to any logged-in user (GID100=everyone)
    depends_on:
      - authgw
    networks:
      sftp_net:
        ipv4_address: 172.22.99.10
    volumes:
      - sftpgo_config:/var/lib/sftpgo:rw # where sftpgo config is persisted
      - /share:/share:rw # where all QNAP shares are located
    ports:
      - "9080:8080" # Web UI on host
      - "9022:2022" # SFTP/SSH on host
    environment:
      SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN: "true"
      SFTPGO_DATA_PROVIDER__EXTERNAL_AUTH_HOOK: "http://authgw:9999/auth"
      SFTPGO_DEFAULT_ADMIN_USERNAME: "admin" # only used on the first startup of sftpgo
      SFTPGO_DEFAULT_ADMIN_PASSWORD: "admin" # Change them afterward via sftpgo Web UI!

  authgw:
    image: ghcr.io/patschi/sftpgo-qnap-authgateway:latest
    container_name: authgw
    restart: unless-stopped
    networks:
      sftp_net:
        ipv4_address: 172.22.99.20
    volumes:
      - /etc/passwd:/qnap_passwd:ro # read-only needed to get UID/GID from a logged-in user
    expose:
      - "9999" # only accessible inside sftp_net, so only from QNAP NAS and sftpgo container
    environment:
      LOG_LEVEL: "debug" # 'trace' not recommended due to high verbosity
      QNAP_CHECK_CERT: "false"
      QNAP_URL: "https://172.22.99.1" # .1 points to the gateway, which should be QNAP NAS itself
      SFTPGO_API_URL: "http://sftpgo:8080/"
      SFTPGO_API_USER: "admin" # needed if SFTPGO_FOLDER_SYNC enabled, use a dedicated account
      SFTPGO_API_PASS: "admin" # use highly secure password here

networks:
  sftp_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.99.0/24 # make sure this subnet is not in use on QNAP NAS

volumes:
  sftpgo_config:
```

# Notes

- QNAP and sftpgo API calls time out after 10 seconds.
- Sessions to QNAP and sftpgo are explicitly logged out after use.
- If `/qnap_passwd` is not mounted, permissions will be set to user/group the sftpgo container is running under.
- Virtual folder sync requires sftpgo REST API to be enabled and a service account with `manage_folders` permission.
- User entries for sftpgo expire 5 minutes after issuance.

# FAQ

## sftpgo logs show "Operation not permitted" (when changing permissions) for any files.

**Answer**: This occurs when sftpgo is not running as root, and hence is not able to change permissions properly.
Also, this can be observed when running `chown 1000:100 test.txt` as any non-root user.

**Solution**: Set `user` to `0:100` in `docker-compose.yml` to run sftpgo as `root` with group `everybody`.
