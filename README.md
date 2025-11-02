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

## Configuration

| Variable          | Default          | Description                                                |
|-------------------|------------------|------------------------------------------------------------|
| `QNAP_HTTP`       | `https`          | Protocol to reach QNAP \(http\|https\).                    |
| `QNAP_HOST`       | `127.0.0.1`      | QNAP Web hostname or IP.                                   |
| `QNAP_PORT`       | `443`            | QNAP Web port.                                             |
| `QNAP_CHECKCERT`  | `true`           | Verify QNAP TLS cert; set to `false` to skip verification. |
| `QNAP_SHARE_PATH` | `/share/{name}/` | Absolute folder on QNAP where share is located at          |
| `AUTHGW_HTTPS`    | `false`          | HTTPS mode \(not implemented\).                            |
| `AUTHGW_ADDR`     | `0.0.0.0`        | Bind address.                                              |
| `AUTHGW_PORT`     | `9999`           | Listen port.                                               |
| `LOG_LEVEL`       | `info`           | Log level \(allowed: trace\|debug\|info\|warn\|error\).    |

## Notes
- QNAP API calls time out after 10s.
- Sessions are logged out after shares are fetched.
- User entries for sftpgo expire 5 minutes after issuance.
