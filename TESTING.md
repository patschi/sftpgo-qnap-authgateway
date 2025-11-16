# Notes for testing

Just rough notes used during and for testing.

## sftpgo

### Spin up sftpgo:

```shell
docker run --rm --name sftpgo -p 8080:8080 -p 2022:2022 -e SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=true -e SFTPGO_DEFAULT_ADMIN_USERNAME=admin -e SFTPGO_DEFAULT_ADMIN_PASSWORD=admin -e SFTPGO_DATA_PROVIDER__EXTERNAL_AUTH_HOOK=http://host.docker.internal:9999/auth drakkan/sftpgo:latest
```

### Create user

```shell
TOKEN=$(curl -s -u admin:admin -X GET --url http://127.0.0.1:8080/api/v2/token -H 'Accept: application/json'); echo $TOKEN; TOKEN=$(echo "$TOKEN" | jq -r '.access_token')

curl -X GET --url http://127.0.0.1:8080/api/v2/admins -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"

curl -X POST --url http://127.0.0.1:8080/api/v2/admins -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"status": 1, "username": "sa-qnap-authgw", "description": "sftpgo-qnap-authgateway service account", "password": "password", "permissions": [ "manage_folders" ]}'

curl -X GET --url http://127.0.0.1:8080/api/v2/admins -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"

curl -X GET --url http://127.0.0.1:8080/api/v2/logout -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"
```

### Test folder workflow

```shell
TOKEN=$(curl -s -u sa-qnap-authgw:password -X GET --url http://127.0.0.1:8080/api/v2/token -H 'Accept: application/json'); echo $TOKEN; TOKEN=$(echo "$TOKEN" | jq -r '.access_token')

curl -X GET --url http://127.0.0.1:8080/api/v2/folders -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"

curl -X POST --url http://127.0.0.1:8080/api/v2/folders -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name": "testFolder", "mapped_path": "/tmp", "description": "Text", "filesystem": { "provider": 0 }}'

curl -X GET --url http://127.0.0.1:8080/api/v2/folders/testFolder -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"

curl -X DELETE --url http://127.0.0.1:8080/api/v2/folders/testFolder -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"

curl -X GET --url http://127.0.0.1:8080/api/v2/logout -H 'Accept: application/json' -H "Authorization: Bearer $TOKEN"
```

## auth-gw

1. Set up user in QNAP and auth-gw as described in README.md.

2. Trigger test authentication: (user needs to exist in QNAP)

```shell
curl -X POST http://localhost:9999/auth -H "Content-Type: application/json" -d '{"username": "test", "password": "Password_123", "ip": "10.0.0.1", "protocol": "ssh" }' | jq .
```

## sftp client

1. Transfer test file

```shell
echo -e "cd Test/\nls -l\nput test.txt\nls -l" | sshpass -p "Password_123" sftp -o StrictHostKeyChecking=no -P 9022 test@192.168.0.10
Connected to 192.168.0.10.
sftp> cd Test/
sftp> ls -l
sftp> put test.txt
Uploading test.txt to /Test/test.txt
sftp> ls -l
-rwxrwxrwx    1 1004     100             0 Nov 16 01:14 test.txt
```
