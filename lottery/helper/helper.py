#!/usr/bin/env python3
import asyncio
import async_lensocket
import ssl
import sys
import mysql.connector # type: ignore
from asyncio import create_subprocess_exec
from typing import Optional

ClientPublicKey = """-----BEGIN CERTIFICATE-----
MIIDgDCCAmigAwIBAgIJAPFuOkrGV1AgMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV
BAYTAlJVMRUwEwYDVQQIDAxUb21za2F5YSBvYmwxDjAMBgNVBAcMBVRvbXNrMRAw
DgYDVQQKDAdTaUJlYXJzMQ0wCwYDVQQDDARNb3JKMB4XDTIwMDMyNTA0NDQ1MloX
DTIxMDMyNTA0NDQ1MlowVTELMAkGA1UEBhMCUlUxFTATBgNVBAgMDFRvbXNrYXlh
IG9ibDEOMAwGA1UEBwwFVG9tc2sxEDAOBgNVBAoMB1NpQmVhcnMxDTALBgNVBAMM
BE1vckowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvm9WPCfHbCt8G
7bSVUN88kx9KW/wWZCQj46E0rZ05zTjaajo/J0OXH8CQsXgFgihABJytJ3QvqvZV
LKhrhL+mHJT7fpj3fgSFCa5iVsOwMGQmwUDQ8XUKEvEkiaGjymAmDU/KZw8Gb86s
zZcYnFWQ/nh6f8i1//wchmb1JRG1cfsc3TfEXzk0o7QW0yiK5eekaIlmQLguc1BB
pEkBrOExsXp88XhiPOQI/vLAahFJlSs3U48CSI17DbC5NBjWHQhQ4pvitMU+sjxG
MxDdCoALwYRMYUSIpuQ/iAIBDU59pAHXQCeKKFLylRHdMZflxBOo1n90TiWz31tQ
w96XM1UzAgMBAAGjUzBRMB0GA1UdDgQWBBQUk3IPHm6WBi7Q7PMSa6U/awITzDAf
BgNVHSMEGDAWgBQUk3IPHm6WBi7Q7PMSa6U/awITzDAPBgNVHRMBAf8EBTADAQH/
MA0GCSqGSIb3DQEBCwUAA4IBAQAVj6BRzCrSFx9Vjv12SPfXzXowQAM9LYiHV6b9
s6Vi9un+Dj1xihv5oirwSb/Pjl0IP2UHNSrysko7lop+gIn+MAINthB+Hmai5RGB
IFTaaH91ectlw32NepcI59JQp1gvX7Gz6fpdARC18uJk+IQG8lCYc9y6PjDfFdVh
49D1jMv+yGDBfBUJu3Y/T85viHu8DKMkc0QLbARa6zAQ63WaPrTEnj4+cJJD42Gq
zCadpFog1Dv1OYg8vMQ8lIDcxo2HtE8oYhzwPmDkDprpLxEkper1QHB6B2oTr2DC
Z4HmL7W1NdfC1BOTzRkCsGDQWiKJOHvY+O54Y4hd2SDgmYah
-----END CERTIFICATE-----
"""
ServerCertFile = "./cert.pem"
ServerPkeyFile = "./private_key.pem"
PORT = 5002

running_instance: Optional[asyncio.subprocess.Process] = None
lock = asyncio.Lock()

async def change_password(password: str) -> None:
    global running_instance
    async with lock:
        # stop the service
        if running_instance is None:
            print("Trying to kill a dead process")
            return
        running_instance.terminate()
        await running_instance.wait()
        running_instance = None

        # change password in db directly
        conn = mysql.connector.connect(user="oleg", password="oleg_2874c71881c3682f215be2f23e8173c4", host="localhost", database="olegdb")
        cur = conn.cursor()
        query = "update users set password = %s where name = 'admin'"
        cur.execute(query, (password,))
        conn.commit()
        conn.close()

        # start the service again
        running_instance = await create_subprocess_exec(
            "/home/lottery/build/oleg-service"
        )

async def handler(reader, writer) -> None:
    print("Got a new connection")
    new_password = await reader.read()
    try:
        await change_password(new_password.decode())
        writer.write(b"ok")
    except Exception:
        writer.write(b"failure")


if __name__ == "__main__":
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=ServerCertFile, keyfile=ServerPkeyFile)
    context.load_verify_locations(cadata=ClientPublicKey)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    loop = asyncio.get_event_loop()
    async def server() -> None:
        # wait for mysql to start
        await asyncio.sleep(3.0)
        # create base service
        running_instance = await create_subprocess_exec(
            "/home/lottery/build/oleg-service"
        )
        print("running", file=sys.stderr)

        s = await async_lensocket.start_server(handler, "0.0.0.0", PORT, ssl=context)
        await s.wait_closed()
    loop.run_until_complete(server())
