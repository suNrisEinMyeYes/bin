#!/usr/bin/env python3
import asyncio
import sys
import ssl
from async_lensocket import open_connection

ServerPublicKey = """-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIJAOnsDSB2FBg4MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjAwMzI1MDg1NTQ2WhcNMjEwMzI1MDg1NTQ2WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwg75VfAn0tefYUklSebY+uJrNQUsNZYplgmMSq+fMu/6tL5pDbHnji0X
dK9E8r2AE1h5j9cN8ISNoVeVwNP+kZwke6ORV2jn5nHlXb4v3yBdwyR811LE5geV
AzY4uZtclbGn4+XAXxFdIHVmp8cXqt0J3FdNvcByqNT/OPHEDuyi2B5MsFHQffIG
yTufVXsPxpMN6tWc5wMTeOAru6OuJHtjBEosYzt9Ncr0XHco/lQhiDoGVZEhGCmC
ntO40Dh+ejycqSq58vv0+XFqm+9MVazhSIvOxKjZ5kiQHLQNIyOmBc5Ses1XIStO
W8nEO3I+JGgSSQBgNBXRAD7SEXiNYQIDAQABo1MwUTAdBgNVHQ4EFgQUKetrKFoF
lw+5VYIHBBPi0Abj8FcwHwYDVR0jBBgwFoAUKetrKFoFlw+5VYIHBBPi0Abj8Fcw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAPQ2k8kA0Jb1JAPmg
hd2I41R+qEP+oukn1HdSi20Dk0wKXrJ7TtVKgYs35JeF7Mf+cbh/Cf4nN1FeuxI+
ERQ0rRCS5WJIsLpKMxP3UVgSsGA4KOLOL2GmIHpNskRD4tFPhJH651OmX1H7VeZL
p7d+y5aJvZnMjd7o7tOXsEwwwYm7h1Djc8ySbzGCgiT8HjOSuXwQ2GtYGz2D+U57
2Q6TNmxScP2Nz4TV+J9KCZlwtgD3MW9yzbjkwZ0qx00XsITKsHB13O6eiEOJnHXI
ztIb6+WklizDFnG7AF5hCwQrDrwoD2cPA2qJF2qW8wU07PzXmLQx8ueKOZdoWpHI
FncpWQ==
-----END CERTIFICATE-----
"""
ClientCertFile = "./cert.pem"
ClientPkeyFile = "./private_key.pem"
PORT = 5002

async def change_remote_password(host: str, password: bytes) -> bool:
    context = ssl.create_default_context(cadata=ServerPublicKey)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=ClientCertFile, keyfile=ClientPkeyFile)
    reader, writer = await open_connection(host, PORT, ssl=context)
    writer.write(password)
    resp = await reader.read()
    return resp == b"ok"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} host")
    host = sys.argv[1]
    loop = asyncio.get_event_loop()
    loop.run_until_complete(change_remote_password(host, b"korol i gorshok"))

