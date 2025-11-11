# sftpgo-qnap-authgateway

Tiny HTTP gateway that lets SFTPGo authenticate users against a QNAP NAS and auto‑map their accessible shares as virtual
folders. Fast, stateless, and logs every request with a request ID.

## Features

- Authenticates via QNAP API
- Builds SFTPGo virtual folders from QNAP shares
- Per‑request cookies, strict timeouts, structured logging
- Simple JSON API for SFTPGo external auth
- Optional TLS cert verification for QNAP API

## Roadmap

- Implement HTTPS webserver support
- Implement queue for sftpgo virtual sync based on virtual folders. Also add proper locking.
- Implement some basic caching for sftpgo virtual sync folders for performance (e.g. update only every 5s)

## Requirements

- QNAP NAS (tested QuTS hero 5.2.7.3297) with installed Container Station
- SFTPGo (tested 2.7.0)

## Quick start

- Create a container on QNAP with this application.
    - Mount `/share` from QNAP to `/share` (or whatever is set in `QNAP_SHARE_PATH`) within the container.
- Configure the environment variables and start the service.
- Point SFTPGo external auth to the service endpoint:
    - `external_auth_hook=https://sftpgo-qnap-authgw/auth`
    - `external_auth_scope=5` (only password and keyboard-interactive; any other is unsupported)
- Disable auto-ban on invalid logins on QNAP for this service and configure sftpgo to take care of it. (To prevent this
  auth gateway from being blocked, instead of the user)
- If you want to take advantage of automated virtual folders sync during successful user login, make sure to enable REST
  API on SFTPGo and provide the below environment variable.

## Configuration

### Setup sftpgo service account (optional)

If you want to enable automated virtual folder managed, this service needs a user account with proper permissions during
the login.
The user can either be created manually, or via API. As can be seen for API calls below.

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

### Environment variables

| Variable                    | Default                                                    | Description                                                                |
|-----------------------------|------------------------------------------------------------|----------------------------------------------------------------------------|
| `QNAP_URL`                  | `https://host.docker.internal`                             | Full URL, e.g. `https://10.0.0.100`                                        |
| `QNAP_CHECK_CERT`           | `true`                                                     | Verify QNAP TLS cert; set to `false` to disable verification.              |
| `QNAP_SHARE_PATH`           | `/share/{name}/`                                           | Absolute folder on QNAP where share is located at                          |
| `SFTPGO_FOLDER_SYNC`        | `false`                                                    | Enable virtual folder sync upon successful login                           |
| `SFTPGO_FOLDER_DESCRIPTION` | `QNAP Share: {name} / Managed by sftpgo-qnap-auth-gateway` | Use specific folder description in sftpgo during sync                      |
| `SFTPGO_ACCOUNT_EXPIRATION` | `5m`                                                       | Set expiration date timeframe after of sftpgo user after successful login  |
| `SFTPGO_API_URL`            | `http://host.docker.internal:8080`                         | API URL for sftpgo instance for virtual folder sync                        |
| `SFTPGO_API_USER`           | `sa-qnap-authgw`                                           | sftpgo service account username; required for virtual folder sync          |
| `SFTPGO_API_PASS`           | none                                                       | sftpgo service account password; required for virtual folder sync          |
| `SFTPGO_CHECK_CERT`         | `true`                                                     | Verify sftpgo TLS cert; set to `false` to disable verification             |
| `SFTPGO_HOMEDIR`            | `/var/tmp`                                                 | sftpgo requires this, empty folder is OK; "{user}" is replaced to username |
| `AUTHGW_TLS`                | `false`                                                    | Enable TLS and HTTPS \(not implemented yet\)                               |
| `LOG_LEVEL`                 | `info`                                                     | Log level \(allowed: trace\|debug\|info\|warn\|error\)                     |

## Notes

- QNAP API calls time out after 10s.
- Sessions are logged out after shares are fetched.
- User entries for sftpgo expire 5 minutes after issuance.
