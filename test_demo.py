from unicorn import *
from unicorn.x86_const import *

import struct


def read(name):
    with open(name) as f:
        return f.read()


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


mu = Uc(UC_ARCH_X86, UC_MODE_64)

BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024 * 1024

mu.mem_map(BASE, 1024 * 1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE, read("./fibonacci"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)


def hook_code(mu, address, size, user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' % (address, size))


mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x00000000004004E0, 0x0000000000400575)
