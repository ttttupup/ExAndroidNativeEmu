from unicorn import *
from unicorn.arm_const import *

table = []


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
    if address == BASE + 0x119cc:
        arr2 = []
        for byte in mu.mem_read(PLAINTEXT_ADDR, 8):
            arr2.append(byte)
        table.append([user_data.index(1), bytes2bin(arr2).index(1)])


def sub_10EA4():
    table = [[0, 0], [1, 4], [2, 61], [3, 15], [4, 56], [5, 40], [6, 6], [7, 59], [8, 62], [9, 58], [10, 17], [11, 2],
             [12, 12], [13, 8], [14, 32], [15, 60], [16, 13], [17, 45], [18, 34], [19, 14], [20, 36], [21, 21],
             [22, 22], [23, 39], [24, 23], [25, 25], [26, 26], [27, 20], [28, 1], [29, 33], [30, 46], [31, 55],
             [32, 35], [33, 24], [34, 57], [35, 19], [36, 53], [37, 37], [38, 38], [39, 5], [40, 30], [41, 41],
             [42, 42], [43, 18], [44, 47], [45, 27], [46, 9], [47, 44], [48, 51], [49, 7], [50, 49], [51, 63], [52, 28],
             [53, 43], [54, 54], [55, 52], [56, 31], [57, 10], [58, 29], [59, 11], [60, 3], [61, 16], [62, 50],
             [63, 48]]
    arr = bytes2bin(input)
    arr1 = [0 for i in range(len(arr))]
    for i in range(len(table)):
        arr1[table[i][1]] = arr[table[i][0]]
    return bin2bytes(arr1)


if __name__ == "__main__":
    key0 = b'44e715a6e322ccb7d028f7a42fa55040'
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    BASE = 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024
    PLAINTEXT_ADDR = 1024 * 2
    PLAINTEXT_SIZE = 1024
    KEY_ADDR = 1024 * 3
    KEY_SIZE = 1024
    mu.mem_map(BASE, 1024 * 1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(PLAINTEXT_ADDR, PLAINTEXT_SIZE)
    mu.mem_map(KEY_ADDR, KEY_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE - 1)
    # mu.mem_write(BASE, read("F:\\Code\\Pycharm\\JDSign\\libjdbitmapkit.so"))
    mu.mem_write(BASE, read("tests/bin/libjdbitmapkit.so"))
    mu.mem_write(KEY_ADDR, key0)

    for i in range(64):
        arr1 = [0 for j in range(64)]
        arr1[i] = 1
        h = mu.hook_add(UC_HOOK_CODE, hook_code, arr1)
        mu.mem_write(PLAINTEXT_ADDR, bin2bytes(arr1))
        mu.reg_write(UC_ARM_REG_R1, KEY_ADDR)
        mu.reg_write(UC_ARM_REG_R2, 32)
        mu.reg_write(UC_ARM_REG_R3, PLAINTEXT_ADDR)
        mu.emu_start(BASE + 0x00010EA4 + 1, BASE + 0x000119D0)
        mu.hook_del(h)
    print(table)
