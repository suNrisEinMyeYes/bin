#!/usr/bin/env python3
import asyncio
import concurrent.futures
import os.path
import pickle
import random
import string
import sys
import timeit
from asyncio import open_connection, get_event_loop, StreamReader, StreamWriter
from traceback import TracebackException
from typing import Optional, Dict, Tuple, Set

import helper
import sploit

### Common checker stuffs ###

class WithExitCode(Exception):
    code: int

    def __init__(self, msg_opt: Optional[str] = None) -> None:
        msg = ""
        name = self.__class__.__name__
        if msg_opt is not None:
            msg = name + ": " + msg_opt
        else:
            msg = name
        super().__init__(msg)
class Corrupt(WithExitCode):
    code = 102
class Mumble(WithExitCode):
    code = 103
class Down(WithExitCode):
    code = 104
class CheckerError(WithExitCode):
    code = 110

class Color:
    value: bytes

    @classmethod
    def print(cls, msg: str) -> None:
        sys.stdout.buffer.write(b"\x1b[01;" + cls.value + b"m")
        sys.stdout.buffer.flush()
        print(msg)
        sys.stdout.buffer.write(b"\x1b[m")
        sys.stdout.buffer.flush()
class Red(Color):
    value = b"31"
class Green(Color):
    value = b"32"

PORT = 5001

def rand_string(length: int = 16) -> bytes:
    letters = string.ascii_letters + string.digits
    name = "".join(random.choice(letters) for _ in range(length))
    return name.encode()

class Storage:
    users: Dict[bytes, bytes]
    used_flags: Set[str]
    admin_password: bytes
    store_path: str
    def __init__(self, path: str) -> None:
        self.store_path = path
        # default values
        self.users = {}
        self.used_flags = set()
        self.admin_password = b"ZVwXtuORgXLfaLtBIqqDwCuD4MthWHTS"
    def dump(self) -> None:
        with open(self.store_path, "wb") as f:
            pickle.dump(self, f)
    @staticmethod
    def load(path: str) -> 'Storage':
        if os.path.isfile(path):
            with open(path, "rb") as f:
                store = pickle.load(f)
                store.store_path = path
                return store
        else:
            default = Storage(path)
            default.dump()
            return default

async def timed(aw, timeout=5.0):
    return await asyncio.wait_for(aw, timeout=timeout)

### Logic starts here ###

admin_lock = asyncio.Lock()
exchange_lock = asyncio.Lock()

async def auth_user(host: str, store, name, pwd) -> Tuple[StreamReader, StreamWriter]:
    reader, writer = await open_connection(host, PORT)
    await timed(reader.readuntil(b": "))
    writer.write(name + b"\n")
    await timed(reader.readuntil(b": "))
    writer.write(pwd + b"\n")
    await timed(reader.readuntil(b"> "))
    store.users[name] = pwd

    store.dump()
    return (reader, writer)

async def auth_admin(host: str, store) -> Tuple[StreamReader, StreamWriter]:
    async with admin_lock:
        reader, writer = await open_connection(host, PORT)
        await timed(reader.readuntil(b": "))
        name, pwd = b"admin", store.admin_password
        writer.write(name + b"\n")
        await timed(reader.readuntil(b": "))
        writer.write(pwd + b"\n")
        new_pwd_str = await timed(reader.readline())

        if new_pwd_str == b"Incorrect password\n":
            r = await helper.change_remote_password(host, store.admin_password)
            if not r:
                raise Exception("Couldn't reset admin password")
            raise Mumble("Bad admin password")

        awaited_prefix = b"New password: '"
        awaited_suffix = b"'\n"
        good_response = (new_pwd_str.startswith(awaited_prefix) and
                         new_pwd_str.endswith(awaited_suffix))
        if not good_response:
            raise Mumble(f"Can't login as admin, response: {new_pwd_str}")
        new_pwd = new_pwd_str[len(awaited_prefix) : -len(awaited_suffix)]
        store.admin_password = new_pwd
        store.dump()
    return (reader, writer)


async def check(store: Storage, host: str) -> None:
    if len(store.users) == 0:
        await put_flag(store, host, "", rand_string(32).decode(), None)
        await put_flag(store, host, "", rand_string(32).decode(), None)

    async def check_admin_names() -> None:
        user = random.choice(list(store.users.keys()))
        reader, writer = await auth_admin(host, store)
        writer.write(b"name\n")
        await timed(reader.readuntil(b": "))
        writer.write(user + b"\n")
        resp = await timed(reader.readuntil(b"> "))
        if not resp.endswith(b"has won\n> "):
            raise Corrupt("Can't win user by name")

    async def check_show() -> None:
        user = random.choice(list(store.users.keys()))
        pwd = store.users[user]
        reader, writer = await auth_user(host, store, user, pwd)
        writer.write(b"show\n")
        await timed(reader.readuntil(b"> "))

    async def check_list() -> None:
        store_users = set(store.users.keys())
        user = random.choice(list(store.users.keys()))
        pwd = store.users[user]
        reader, writer = await auth_user(host, store, user, pwd)
        writer.write(b"list\n")
        resp = await timed(reader.readuntil(b"> "))
        quoted = resp.rstrip(b"> ").rstrip().split(b" ")
        names = list(x[1:-1] for x in quoted)
        if store_users.issubset(names):
            pass
        else:
            raise Mumble(f"Missing registered users: {store_users} vs {names}")

    async def check_exchange() -> None:
        async with exchange_lock:
            user1 = random.choice(list(store.users.keys()))
            user2 = random.choice(list(store.users.keys()))
            pwd1, pwd2 = store.users[user1], store.users[user2]
            r1, w1 = await auth_user(host, store, user1, pwd1)
            r2, w2 = await auth_user(host, store, user2, pwd2)
            #
            w1.write(b"show\n")
            resp1 = await timed(r1.readuntil(b"> "))
            flag1 = resp1.rstrip(b"> ")
            w2.write(b"show\n")
            resp2 = await timed(r2.readuntil(b"> "))
            flag2 = resp2.rstrip(b"> ")
            #
            w1.write(b"exchange\n")
            await timed(r1.readuntil(b": "))
            w1.write(user2 + b"\n")
            await timed(r1.readline())
            w2.write(b"accept\n")
            await timed(r2.readuntil(b"trade: "))
            w2.write(user1 + b"\n")
            await timed(r2.readline())
            w2.write(b"y")
            await timed(r2.readline())
            #
            w1.write(b"show\n")
            resp1 = await timed(r1.readuntil(b"> "))
            new_flag1 = resp1.rstrip(b"> ")
            w2.write(b"show\n")
            resp2 = await timed(r2.readuntil(b"> "))
            new_flag2 = resp2.rstrip(b"> ")
            if flag1 == new_flag2 and flag2 == new_flag1:
                pass
            else:
                raise Mumble("Couldn't exchange")

    actions = [check_admin_names, check_exchange, check_list, check_show]
    random.shuffle(actions)
    for action in actions:
        await action()

async def put_flag(store: Storage, host: str, flag_id: str, flag_data: str, vuln
        ) -> None:
    ticket = [str(byte) for byte in flag_data.encode()]
    assert len(ticket) == 32
    ticket_str = " ".join(ticket)

    name, pwd = rand_string(), rand_string()
    reader, writer = await auth_user(host, store, name, pwd)

    writer.write(b"buy\n")
    await timed(reader.readuntil(b": "))
    writer.write(ticket_str.encode() + b"\n")
    await timed(reader.readuntil(b"> "))

    writer.write(b"show\n")
    data = await timed(reader.readuntil(b"> "))
    put_flag = data[2:34].decode()
    if put_flag == flag_data:
        store.used_flags.add(put_flag)
        store.dump()
    else:
        raise Mumble(f"Bad flag: {put_flag}")

async def get_flag(store: Storage, host: str, flag_id: str, flag_data: str, vuln
        ) -> None:
    reader, writer = await auth_admin(host, store)
    writer.write(b"number\n")
    await timed(reader.readuntil(b": "))
    writer.write(flag_data.encode() + b"\n")
    resp = await timed(reader.readline())
    postfix = b" has won, yay\n"
    if not resp.endswith(postfix):
        raise Corrupt(f"Flag {flag_data} doesn't exist or malformed reply: {resp!r}")

    # check for non-existing flag
    flag = rand_string(32)
    while rand_string in store.used_flags:
        flag = rand_string(32)
    writer.write(b"number\n")
    await timed(reader.readuntil(b": "))
    writer.write(flag + b"\n")
    resp = await timed(reader.readline())
    if not resp.startswith(b"Ticket does not exist"):
        raise Mumble("Non-existant flag exists")

async def stress_test(store: Storage, host: str) -> None:
    task_amount = random.randrange(100, 200)
    print(f"spawning {task_amount} workers")

    async def wrapped_get() -> None:
        if len(store.used_flags) != 0:
            flag = random.choice(list(store.used_flags))
            await get_flag(store, host, "", flag, None)
    async def wrapped_put() -> None:
        flag = rand_string(32).decode()
        await put_flag(store, host, "", flag, None)
    async def wrapped_check() -> None:
        await check(store, host)

    distr = [wrapped_get, wrapped_put, wrapped_check, wrapped_check, wrapped_check]
    tasks = [random.choice(distr)() for _ in range(task_amount)]
    start = timeit.default_timer()
    await asyncio.gather(*tasks)
    end = timeit.default_timer()
    print(f"all workers finished in {end - start} seconds")

async def attack(host: str) -> None:
    await sploit.attack(host, PORT)

async def do_run(store: Storage, host: str) -> None:
    await check(store, host)
    Green.print("check")

    flag = rand_string(32).decode()
    await put_flag(store, host, "", flag, None)
    Green.print("put")

    await check(store, host)
    Green.print("check")

    await get_flag(store, host, "", flag, None)
    Green.print("get")

    await check(store, host)
    Green.print("check")

    try:
        await attack(host)
        Red.print("attack")
    except sploit.AttackError:
        Green.print("attack")


def main() -> int:
    try:
        usage = "Usage: {} run|check|put|get|attack|stresstest IP FLAGID FLAG".format(sys.argv[0])
        command = sys.argv[1]
        host = sys.argv[2]

        dbname = f"storage-oleg-{host}-{PORT}.dump"
        store = Storage.load(dbname)
        loop = get_event_loop()

        if command == "check":
            loop.run_until_complete(check(store, host))

        elif command == "put":
            flag_id, flag_data, vuln = sys.argv[3:]
            loop.run_until_complete(put_flag(store, host, flag_id, flag_data, vuln))

        elif command == "get":
            flag_id, flag_data, vuln = sys.argv[3:]
            loop.run_until_complete(get_flag(store, host, flag_id, flag_data, vuln))

        elif command == "stresstest":
            loop.run_until_complete(stress_test(store, host))

        elif command == "attack":
            loop.run_until_complete(attack(host))

        elif command == "run":
            loop.run_until_complete(do_run(store, host))

        else:
            print(usage)
            return CheckerError.code
        # if not thrown, everything is ok
        return 101
    except IndexError as e:
        print(usage)
        trace = "".join(TracebackException.from_exception(e).format())
        print(trace)
        return CheckerError.code
    except ValueError as e:
        print(usage)
        trace = "".join(TracebackException.from_exception(e).format())
        print(trace)
        return CheckerError.code
    except ConnectionRefusedError as e:
        # same as down
        Red.print("Down")
        trace = "".join(TracebackException.from_exception(e).format())
        print(trace)
        return Down.code
    except AssertionError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        Red.print("Checker error: flag data should be 32 symbols long")
        return CheckerError.code
    except concurrent.futures._base.TimeoutError as e:
        trace = "".join(TracebackException.from_exception(e).format())
        print(trace)
        Red.print("Mumble")
        return Mumble.code
    except WithExitCode as e:
        Red.print(str(e))
        return e.code
    except sploit.AttackError as e:
        Red.print("AttackError: " + str(e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
