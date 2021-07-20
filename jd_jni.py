import logging
import posixpath
import sys
import os

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.classes.activity_thread import ActivityThread
from androidemu.java.classes.application import Application
from androidemu.java.classes.string import String
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
import androidemu.utils.debug_utils
from androidemu.java.jni_env import JNIEnv
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stdout, "./ins-jni.txt")


def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range" % (address,))
            sys.exit(-1)
        #
        # androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)
    #


#

def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    if (address == 0xCBC80640):
        logger.debug("read mutex")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder='little', signed=False)
        logger.debug(
            ">>> Memory READ at 0x%08X, data size = %u,  data value = 0x%08X, pc: 0x%08X," % (address, size, v, pc))
    #


#

def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if (address == 0xCBC80640):
        logger.debug("write mutex")
        logger.debug(
            ">>> Memory WRITE at 0x%08X, data size = %u, data value = 0x%08X, pc: 0x%08X" % (address, size, value, pc))
    #


#


# Create java class.

# class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager'):
#     def __init__(self):
#         pass
#
#     @java_method_def(name='getPackageInfo', signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;')
#     def getPackageInfo(self, mu):
#         pass
#
#
# class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo',
#                   jvm_fields=[JavaFieldDef('signatures', '[Landroid/content/pm/Signature;', False)]
#                   ):
#     def __init__(self):
#         pass


# class Signature(metaclass=JavaClassDef, jvm_name='android/content/pm/Signature'):
#     def __init__(self):
#         pass


class BitmapkitZip(metaclass=JavaClassDef, jvm_name='com/jingdong/common/utils/BitmapkitZip'):
    def __init__(self):
        pass


class ToastUtils(metaclass=JavaClassDef, jvm_name='com/jingdong/jdsdk/widget/ToastUtils'):
    def __init__(self):
        pass

    @java_method_def(name='longToast', signature='(Ljava/lang/String;)V', native=False)
    def longToast(self, mu):
        pass


logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)


# Register Java class.
# emulator.java_classloader.add_class(Activity)
# emulator.java_classloader.add_class(Application)
# emulator.java_classloader.add_class(PackageManager)
# emulator.java_classloader.add_class(PackageInfo)
# app = emulator.java_classloader.find_class_by_name("android/app/Application")
class BitmapkitUtils(metaclass=JavaClassDef, jvm_name='com/jingdong/common/utils/BitmapkitUtils',
                     jvm_fields=[JavaFieldDef('a', 'Landroid/app/Application;', is_static=True,
                                              static_value=ActivityThread.currentApplication(emulator))]):

    def __init__(self):
        pass

    @java_method_def(name='getSignFromJni',
                     signature='(Landroid/content/Context;'
                               'Ljava/lang/String;'
                               'Ljava/lang/String;'
                               'Ljava/lang/String;'
                               'Ljava/lang/String;'
                               'Ljava/lang/String;)Ljava/lang/String;',
                     native=True)
    def getSignFromJni(self, mu):
        pass

    # @java_method_def(name='a', signature='([Ljava/lang/String;)Ljava/lang/String;', native=True)
    # def a(self, mu):
    #     pass

    @java_method_def(name='getstring', signature='(Ljava/lang/String;)Ljava/lang/String;', native=True)
    def getstring(self, mu):
        pass

    @java_method_def(name='encodeJni', signature='([BZ)[B', native=True)
    def encodeJni(self, mu):
        pass

    @staticmethod
    @java_method_def(name='getApplicationByReflection', signature='()V', native=False)
    def getApplicationByReflection(mu):
        pass


emulator.java_classloader.add_class(BitmapkitZip)
emulator.java_classloader.add_class(ToastUtils)
emulator.java_classloader.add_class(BitmapkitUtils)
emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)

emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

by_name = emulator.java_classloader.find_class_by_name("android/app/Application")

# Load all libraries.
lib_module = emulator.load_library("tests/bin/libjdbitmapkit.so")

# androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)


    # Do native stuff.
    functionId = "newReceiveRvcCoupon"
    client = "android"
    device_id = "b90d3f7cc9b126a2"
    versionName = "9.3.2"
    partner = "jdtopc"
    networkType = "wifi"
    bbsid = "02da1df29b8abc205254003bc4ba310a"

    url = 'https://api.m.jd.com/client.action?functionId=%s&clientVersion=%s&build=86083&client=%s&d_brand=HUAWEI' \
          '&d_model=LIO-AN00&osVersion=7.7.1&screen=1552*900&partner=%s&sdkVersion=30&lang=zh_CN&uuid=%s' \
          '&area=22_2022_2029_43712&networkType=%s&wifiBssid=%s' % (
              functionId, versionName, client, partner, device_id, networkType, bbsid)
    body = '{"childActivityUrl":"openapp.jdmobile://virtual?params={"category":"jump","des":"couponCenter"}","eid":"","extend":"0271DFD6890D3B60ACB8BA8A9E49BEB17FE8E6323A36834B63FE69E95D38088ED97A885751544E4224E8CF85E0A4E266A213BE06482C2B115ACD30536499B3CBAFE96FE4762B98424FC283BB3EDD9BD5052C76611A69858C029895908D3EC83491EAA52E7067A415E72B82A9A990407050AC93F8FAD90D456227C60734534054","pageClickKey":"Coupons_GetCenter","rcType":"1","source":"couponCenter_app"}";'

    j_functionId = String(functionId)
    j_client = String(client)
    j_device_id = String(device_id)
    j_versionName = String(versionName)
    j_partner = String(partner)
    j_networkType = String(networkType)
    j_bbsid = String(bbsid)
    j_body = String(body)

    at = ActivityThread()
    ctx = at.currentApplication(emulator)
    bit_map_util = BitmapkitUtils()

    jd_sign = bit_map_util.getSignFromJni(emulator, ctx, j_functionId, j_body, j_device_id, j_client,j_versionName)
    # jd_sign = emulator.call_symbol(lib_module, 'Java_com_jingdong_common_utils_BitmapkitUtils_getSignFromJni',
    #                               emulator.java_vm.jni_env.address_ptr, 0x00,ctx, j_functionId, j_body, j_device_id,
    #                               j_client, j_versionName)

    logger.info(type(jd_sign))
    string = jd_sign.get_py_string()
    print(string)
    logger.info("jd sign:%s", string)

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
