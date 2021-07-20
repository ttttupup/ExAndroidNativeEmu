from .array import ByteArray
from ..java_class_def import JavaClassDef
from ..java_method_def import java_method_def


class Signature(metaclass=JavaClassDef, jvm_name='android/content/pm/Signature'):
    def __init__(self):
        pass

    @java_method_def(name='hashCode', signature='()I', native=False)
    def hashCode(self,mu):
        pass

    @java_method_def(name='toByteArray', signature='()[B', native=False)
    def toByteArray(self, mu):

        return ByteArray(list())
