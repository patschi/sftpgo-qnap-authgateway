# sftpgo-qnap-authgateway

Tiny HTTP gateway that lets SFTPGo authenticate users against a QNAP NAS and auto‑map their accessible shares as virtual folders. Fast, stateless, and logs every request with a request ID.

## Features
- Authenticates via QNAP API
- Builds SFTPGo virtual folders from QNAP shares
- Per‑request cookies, strict timeouts, structured logging
- Simple JSON API for SFTPGo external auth
- Optional TLS cert verification for QNAP API

## Quick start
- Create a container on QNAP with this application.
- Configure the environment variables and start the service.
- Point SFTPGo external auth to the service endpoint:
    - `external_auth_hook=https://sftpgo-qnap-authgw/auth`
    - `external_auth_scope=5` (only password and keyboard-interactive; any other are unsupported)
- If you want to take advantage of automated virtual folders sync during successful user login, make sure to enable REST API on SFTPGo and provide below environment variable.

## Configuration

| Variable             | Default                            | Description                                                     |
|----------------------|------------------------------------|-----------------------------------------------------------------|
| `QNAP_URL`           | `https://host.docker.internal`     | Full URL, e.g. `https://10.0.0.100`                             |
| `QNAP_CHECK_CERT`    | `true`                             | Verify QNAP TLS cert; set to `false` to disable verification.   |
| `QNAP_SHARE_PATH`    | `/share/{name}/`                   | Absolute folder on QNAP where share is located at               |
| `SFTPGO_FOLDER_SYNC` | `false`                            | Enable virtual folder sync upon successful login                |
| `SFTPGO_API_URL`     | `http://host.docker.internal:8080` | API URL for sftpgo instance for virtual folder sync             |
| `SFTPGO_API_TOKEN`   | none                               | sftpgo REST API key; required for virtual folder sync           |
| `SFTPGO_CHECK_CERT`  | `true`                             | Verify sftpgo TLS cert; set to `false` to disable verification. |
| `AUTHGW_HTTPS`       | `false`                            | HTTPS mode \(not implemented\).                                 |
| `AUTHGW_ADDR`        | `0.0.0.0`                          | Bind address.                                                   |
| `AUTHGW_PORT`        | `9999`                             | Listen port.                                                    |
| `LOG_LEVEL`          | `info`                             | Log level \(allowed: trace\|debug\|info\|warn\|error\).         |

## Notes
- QNAP API calls time out after 10s.
- Sessions are logged out after shares are fetched.
- User entries for sftpgo expire 5 minutes after issuance.
