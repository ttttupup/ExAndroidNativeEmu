import logging
import posixpath
import time

from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.classes.activity_thread import ActivityThread
from androidemu.java.classes.string import String
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def


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


class JdSign:
    def __init__(self):
        emulator.java_classloader.add_class(BitmapkitZip)
        emulator.java_classloader.add_class(ToastUtils)
        emulator.java_classloader.add_class(BitmapkitUtils)
        self.lib_module = emulator.load_library("tests/bin/libjdbitmapkit.so")
        emulator.call_symbol(self.lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    def hook_sign(self, functionId, device_id, body):
        try:
            client = "android"
            version_name = "9.3.2"
            j_function_id = String(functionId)
            j_client = String(client)
            j_device_id = String(device_id)
            j_version_name = String(version_name)
            j_body = String(body)

            at = ActivityThread()
            ctx = at.currentApplication(emulator)
            bit_map_util = BitmapkitUtils()
            start = time.time()
            jd_sign = bit_map_util.getSignFromJni(emulator, ctx, j_function_id, j_body, j_device_id, j_client,
                                                  j_version_name)

            # jd_sign = emulator.call_symbol(self.lib_module,
            #                                'Java_com_jingdong_common_utils_BitmapkitUtils_getSignFromJni',
            #                                emulator.java_vm.jni_env.address_ptr, 0x00, ctx, j_function_id, j_body,
            #                                j_device_id,
            #                                j_client, j_version_name)
            sign = jd_sign.get_py_string()
            end = time.time()
            logger.error("耗时：%s", end - start)
            return sign
        except UcError as e:
            print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
            raise
