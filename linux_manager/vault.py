"""Local, non-synchronizing macOS Keychain storage; no secret CLI arguments."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import json
import re
import sys
import hashlib

from .models import ManagerError


def vault_alias(scope, identifier):
    """Use the same validated opaque account format for auxiliary local secrets."""
    return hashlib.sha256((scope + ":" + identifier).encode()).hexdigest()[:16]


class LocalVault:
    SERVICE = "local.linuxservermanager.credentials"

    def __init__(self):
        self.native = None
        self.cache = {}

    def _initialize(self):
        if self.native:
            return
        if sys.platform != "darwin":
            raise ManagerError("本版保存登录信息需要 macOS 本机钥匙串。可以取消记住登录信息。")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        pointer, index = ctypes.c_void_p, ctypes.c_long
        signatures = {
            "CFDictionaryCreateMutable": ([pointer, index, pointer, pointer], pointer),
            "CFDictionarySetValue": ([pointer, pointer, pointer], None),
            "CFStringCreateWithCString": ([pointer, ctypes.c_char_p, ctypes.c_uint32], pointer),
            "CFDataCreate": ([pointer, ctypes.c_char_p, index], pointer),
            "CFDataGetLength": ([pointer], index),
            "CFDataGetBytePtr": ([pointer], pointer),
            "CFRelease": ([pointer], None),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.cf, name); function.argtypes = arguments; function.restype = result
        for name in ["SecItemAdd", "SecItemCopyMatching", "SecItemUpdate"]:
            function = getattr(self.sec, name); function.argtypes = [pointer, pointer]; function.restype = ctypes.c_int32
        self.sec.SecItemDelete.argtypes = [pointer]; self.sec.SecItemDelete.restype = ctypes.c_int32
        self.native = True

    def constant(self, name):
        library = self.cf if name.startswith("kCF") else self.sec
        return ctypes.c_void_p.in_dll(library, name).value

    @contextmanager
    def dictionary(self, values):
        self._initialize()
        callbacks = [ctypes.addressof(ctypes.c_void_p.in_dll(self.cf, name)) for name in ["kCFTypeDictionaryKeyCallBacks", "kCFTypeDictionaryValueCallBacks"]]
        dictionary = self.cf.CFDictionaryCreateMutable(None, 0, *callbacks)
        owned = []
        try:
            for name, value in values.items():
                if isinstance(value, bytes):
                    reference = self.cf.CFDataCreate(None, value, len(value)); owned.append(reference)
                elif isinstance(value, bool):
                    reference = self.constant("kCFBooleanTrue" if value else "kCFBooleanFalse")
                elif isinstance(value, tuple):
                    reference = self.constant(value[0])
                else:
                    reference = self.cf.CFStringCreateWithCString(None, value.encode(), 0x08000100); owned.append(reference)
                self.cf.CFDictionarySetValue(dictionary, self.constant(name), reference)
            yield dictionary
        finally:
            self.cf.CFRelease(dictionary)
            for reference in owned:
                self.cf.CFRelease(reference)

    def query(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{16}", identifier):
            raise ManagerError("登录档案编号无效。")
        return {"kSecClass": ("kSecClassGenericPassword",), "kSecAttrService": self.SERVICE, "kSecAttrAccount": identifier, "kSecAttrSynchronizable": False, "kSecUseDataProtectionKeychain": False}

    def check(self, status):
        if status:
            raise ManagerError("本机钥匙串未允许存取，登录信息尚未保存。请允许本程序访问钥匙串后重试，或取消“记住登录信息”。")

    def get(self, identifier):
        if identifier in self.cache:
            return dict(self.cache[identifier])
        result = ctypes.c_void_p()
        with self.dictionary(self.query(identifier) | {"kSecReturnData": True, "kSecMatchLimit": ("kSecMatchLimitOne",)}) as query:
            status = self.sec.SecItemCopyMatching(query, ctypes.byref(result))
        if status == -25300:
            self.cache[identifier] = {}
            return {}
        self.check(status)
        try:
            length = self.cf.CFDataGetLength(result)
            if not 0 <= length <= 16384:
                raise ManagerError("本机保存的登录资料无效，请重新填写。")
            values = json.loads(ctypes.string_at(self.cf.CFDataGetBytePtr(result), length))
            if not isinstance(values, dict):
                raise ManagerError("本机保存的登录资料无效，请重新填写。")
            self.cache[identifier] = values
            return dict(values)
        finally:
            self.cf.CFRelease(result)

    def put(self, identifier, values):
        encoded = json.dumps(values, ensure_ascii=False).encode()
        with self.dictionary(self.query(identifier)) as query, self.dictionary({"kSecValueData": encoded}) as data:
            status = self.sec.SecItemUpdate(query, data)
        if status == -25300:
            with self.dictionary(self.query(identifier) | {"kSecValueData": encoded}) as query:
                status = self.sec.SecItemAdd(query, None)
        self.check(status)
        self.cache[identifier] = dict(values)

    def delete(self, identifier):
        with self.dictionary(self.query(identifier)) as query:
            status = self.sec.SecItemDelete(query)
        if status != -25300:
            self.check(status)
        self.cache.pop(identifier, None)
