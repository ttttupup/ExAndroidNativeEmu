from unicorn import *
from unicorn.arm_const import *

table = []
table1 = []


def bytes2bin(bytes):
    arr = []
    for v in [m for m in bytes]:
        arr.append(
            [(v & 128) >> 7, (v & 64) >> 6, (v & 32) >> 5, (v & 16) >> 4, (v & 8) >> 3, (v & 4) >> 2, (v & 2) >> 1,
             v & 1])
    return [i for j in arr for i in j]


def bin2bytes(arr):
    length = len(arr) // 8
    arr1 = [0 for _ in range(length)]
    for j in range(length):
        arr1[j] = arr[j * 8] << 7 | arr[j * 8 + 1] << 6 | arr[j * 8 + 2] << 5 | arr[j * 8 + 3] << 4 | arr[
            j * 8 + 4] << 3 | arr[j * 8 + 5] << 2 | arr[j * 8 + 6] << 1 | arr[j * 8 + 7]
    return bytes(arr1)


def read(name):
    with open(name, 'rb') as f:
        return f.read()


def hook_code(mu, address, size, user_data):
    if address == BASE + 0x5284:
        table.append(bytes2bin(mu.mem_read(PLAINTEXT_ADDR, 1)))


def sub_4B7C(input):
    table = [[0, 6, 0, 1], [1, 4, 1, 0], [2, 5, 0, 1], [3, 0, 0, 1], [4, 2, 0, 1], [5, 3, 0, 1], [6, 1, 1, 0],
             [7, 7, 0, 1]]
    arr = bytes2bin(input)
    arr1 = [0 for i in range(8)]
    for i in range(8):
        if arr[i] == 0:
            arr1[table[i][1]] = table[i][2]
        else:
            arr1[table[i][1]] = table[i][3]
    return bin2bytes(arr1)

def sub_12ECC(input):
    arr = [0x37, 0x92, 0x44, 0x68, 0xA5, 0x3D, 0xCC, 0x7F, 0xBB, 0xF, 0xD9, 0x88, 0xEE, 0x9A, 0xE9, 0x5A]
    key2 = b"80306f4370b39fd5630ad0529f77adb6"
    arr1 = [0 for _ in range(len(input))]
    for i in range(len(input)):
        r0 = int(input[i])
        r2 = arr[i & 0xf]
        r4 = int(key2[i & 7])
        r0 = r2 ^ r0
        r0 = r0 ^ r4
        r0 = r0 + r2
        r2 = r2 ^ r0
        r1 = int(key2[i & 7])
        r2 = r2 ^ r1
        arr1[i] = r2 & 0xff
    return bytes(arr1)

if __name__ == "__main__":
    # key0 = b'44e715a6e322ccb7d028f7a42fa55040'
    # mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    # BASE = 0x400000
    # STACK_ADDR = 0x0
    # STACK_SIZE = 1024
    # PLAINTEXT_ADDR = 1024 * 2
    # PLAINTEXT_SIZE = 1024
    # KEY_ADDR = 1024 * 3
    # KEY_SIZE = 1024
    # mu.mem_map(BASE, 1024 * 1024)
    # mu.mem_map(STACK_ADDR, STACK_SIZE)
    # mu.mem_map(PLAINTEXT_ADDR, PLAINTEXT_SIZE)
    # mu.mem_map(KEY_ADDR, KEY_SIZE)
    # mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 1)
    # # mu.mem_write(BASE, read("F:\\Code\\Pycharm\\JDSign\\libjdbitmapkit.so"))
    # mu.mem_write(BASE, read("tests/bin/libjdbitmapkit.so"))
    # mu.mem_write(KEY_ADDR, key0)
    #
    # for i in range(9):
    #     arr1 = [0 for j in range(8)]
    #     if i != 0:
    #         arr1[i - 1] = 1
    #     h = mu.hook_add(UC_HOOK_CODE, hook_code, arr1)
    #     mu.mem_write(PLAINTEXT_ADDR, bin2bytes(arr1))
    #     mu.reg_write(UC_ARM_REG_R0, KEY_ADDR)
    #     mu.reg_write(UC_ARM_REG_R1, 32)
    #     mu.reg_write(UC_ARM_REG_R2, 1)
    #     mu.reg_write(UC_ARM_REG_R3, PLAINTEXT_ADDR)
    #     mu.emu_start(BASE + 0x0004B7C + 1, BASE + 0x0005288)
    #     mu.hook_del(h)
    #
    # for i in range(8):
    #     for j in range(8):
    #         arr3 = []
    #         if table[0][j] != table[i + 1][j]:
    #             table1.append([i, j, table[0][j], table[i + 1][j]])
    # print(table1)


    key0 = b'44e715a6e322ccb7d028f7a42fa55040'
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    BASE = 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024 * 10
    PLAINTEXT_ADDR = 1024 * 10
    PLAINTEXT_SIZE = 1024
    KEY_ADDR = 1024 * 11
    KEY_SIZE = 1024
    mu.mem_map(BASE, 1024 * 1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(PLAINTEXT_ADDR, PLAINTEXT_SIZE)
    mu.mem_map(KEY_ADDR, KEY_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 1)
    # mu.mem_write(BASE, read("F:\\Code\\Pycharm\\JDSign\\libjdbitmapkit.so"))
    mu.mem_write(BASE, read("tests/bin/libjdbitmapkit.so"))
    mu.mem_write(KEY_ADDR, key0)

    arr = [[1, 0x0004B7C, 0x0005288], [2, 0x00061A0, 0x0006AE8], [3, 0x0007994, 0x000084A6],
           [4, 0x000091AC, 0x00009DF4],
           [5, 0x0000ABF8, 0x0000BA8C], [6, 0x0000C8C0, 0x0000D9A0], [7, 0x0000E7FC, 0x0000FC1C]]
    for m in arr:
        for i in range(m[0] * 8 + 1):
            arr1 = [0 for j in range(m[0] * 8)]
            if i != 0:
                arr1[i - 1] = 1
            h = mu.hook_add(UC_HOOK_CODE, hook_code, m)
            mu.mem_write(PLAINTEXT_ADDR, bin2bytes(arr1))
            mu.reg_write(UC_ARM_REG_R0, KEY_ADDR)
            mu.reg_write(UC_ARM_REG_R1, 32)
            mu.reg_write(UC_ARM_REG_R2, 1)
            mu.reg_write(UC_ARM_REG_R3, PLAINTEXT_ADDR)
            mu.emu_start(BASE + m[1] + 1, BASE + m[2])
            mu.hook_del(h)

        for i in range(m[0] * 8):
            for j in range(m[0] * 8):
                arr3 = []
                if table[0][j] != table[i + 1][j]:
                    table1.append([i, j, table[0][j], table[i + 1][j]])
        print("case %s 映射关系:" % (m[0] - 1))
        print(table1)
        table.clear()
        table1.clear()