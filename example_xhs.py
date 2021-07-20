#!/usr/bin/env python
#-*- coding:utf-8 -*-
# author:dunchen
# datetime:2020/5/7 2:27 下午
# software: PyCharm



import logging
import posixpath
import sys
import uuid

from unicorn import UcError, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import *

from androidemu.emulator import Emulator

# 配置日志
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
# from samples import debug_utils
# import androidemu.utils.debug_utils
from androidemu.utils import debug_utils

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)


class Chain(metaclass=JavaClassDef, jvm_name='okhttp3/Interceptor$Chain',
               jvm_fields=[JavaFieldDef('appContext', 'Landroid/content/Context;', False)]):
    def __init__(self):
        pass

    @java_method_def(name='process', signature='(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;', native=True)
    def process(self, *args, **kwargs):
        logger.info("burn")


class RedEncNative(metaclass=JavaClassDef, jvm_name='com/xingin/shield/RedEncNative'):
    def __init__(self):
        pass

    @java_method_def(name='currentApplication', signature='()Landroid/app/Application;', native=False)
    def currentApplication(self, *args, **kwargs):
        # logger.info("burn"
        pass


class RedHttpInterceptor(metaclass=JavaClassDef, jvm_name='com/xingin/shield/http/RedHttpInterceptor'):
    def __init__(self):
        pass




# 初始化模拟器
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)
# emulator.system_properties["ro.build.version.sdk"] = "23"
emulator.java_classloader.add_class(RedEncNative)

emulator.java_classloader.add_class(RedHttpInterceptor)
emulator.java_classloader.add_class(Chain)
# emulator.java_classloader.add_class(Secure)
# 加载依赖的动态库
# emulator.load_library("tests/bin/libdl.so")
# emulator.load_library("tests/bin/libc.so", do_init=False)
# emulator.load_library("tests/bin/libstdc++.so")
# emulator.load_library("tests/bin/libm.so")
lib_module = emulator.load_library("tests/bin/libshield.so", do_init=False)

# 当前已经load的so
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# emulator.mu.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.call_native("")
try:
    # 运行jni onload 这里没有, 但不影响执行
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    print("Jni_onload success")
    # with open("./misc/app_process32", 'rb') as ap:
    #     data = ap.read()
    #     len1 = len(data) + 1024 - (len(data) % 1024)
    #     emulator.mu.mem_map(0xab006000, len1)
    #     emulator.mu.mem_write(0xab006000, data)

    # emulator.call_symbol(lib_module, "Java_com_component_secure_hellfire_Hellfire_burn")
    # print("result call: %i" % emulator.mu.reg_read(UC_ARM_REG_R0))

    # print(a)
    hellfire = Chain()
    # for method in hellfire.jvm_methods.values():
    #     if method.native:
    #         logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
    hellfire.process(emulator)
    # 执行完成, 退出虚拟机
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
