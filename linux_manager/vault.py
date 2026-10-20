"""Local, non-synchronizing macOS Keychain storage; no secret CLI arguments."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import json
import re
import sys
import hashlib
import threading
import fcntl
import os
from pathlib import Path
import stat

from .models import ManagerError


def vault_alias(scope, identifier):
    """Use the same validated opaque account format for auxiliary local secrets."""
    return hashlib.sha256((scope + ":" + identifier).encode()).hexdigest()[:16]


class LocalVault:
    SERVICE = "local.linuxservermanager.credentials"
    BUNDLE = vault_alias("vault", "local-credentials-v1")

    def __init__(self):
        self.native = None
        self.cache = {}
        self._records = None
        self._lock = threading.RLock()
        self._load_failed = False
        self._legacy_failed = False

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

    def _read_item(self, identifier, maximum=16384):
        result = ctypes.c_void_p()
        with self.dictionary(self.query(identifier) | {"kSecReturnData": True, "kSecMatchLimit": ("kSecMatchLimitOne",)}) as query:
            status = self.sec.SecItemCopyMatching(query, ctypes.byref(result))
        if status == -25300:
            return None
        self.check(status)
        try:
            length = self.cf.CFDataGetLength(result)
            if not 0 <= length <= maximum:
                raise ManagerError("本机保存的登录资料无效，请重新填写。")
            values = json.loads(ctypes.string_at(self.cf.CFDataGetBytePtr(result), length))
            if not isinstance(values, dict):
                raise ManagerError("本机保存的登录资料无效，请重新填写。")
            return values
        finally:
            self.cf.CFRelease(result)

    def _write_item(self, identifier, values):
        encoded = json.dumps(values, ensure_ascii=False).encode()
        with self.dictionary(self.query(identifier)) as query, self.dictionary({"kSecValueData": encoded}) as data:
            status = self.sec.SecItemUpdate(query, data)
        if status == -25300:
            with self.dictionary(self.query(identifier) | {"kSecValueData": encoded}) as query:
                status = self.sec.SecItemAdd(query, None)
        self.check(status)

    def _load_records(self, refresh=False):
        if self._records is not None and not refresh: return
        if self._load_failed and not refresh:
            raise ManagerError("本次未获准读取钥匙串；已停止重复请求。允许访问后请重新打开程序。")
        try: document = self._read_item(self.BUNDLE, maximum=4 * 1024 * 1024)
        except ManagerError:
            self._load_failed = True
            raise
        records = document.get("records") if document is not None else {}
        if document is not None and (document.get("version") != 1 or not isinstance(records, dict)):
            raise ManagerError("本机集中登录资料无效；原钥匙串记录已保留，未覆盖。")
        if len(records) > 10000 or any(not re.fullmatch(r"[a-f0-9]{16}", key) or not isinstance(value, dict)
                                       for key, value in records.items()):
            raise ManagerError("本机集中登录资料无效；原钥匙串记录已保留，未覆盖。")
        self._records = records
        self._load_failed = False
        self.cache.update({key: dict(value) for key, value in records.items()})

    @contextmanager
    def _write_lock(self):
        # Only a lock file goes on disk. The credentials remain in Keychain.
        directory = Path.home() / "Library/Caches/local.linuxservermanager"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ManagerError("本机凭据写入锁目录不可用，原记录未修改。")
        descriptor = os.open(directory / "vault.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ManagerError("本机凭据写入锁不可用，原记录未修改。")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _save_record(self, identifier, values, migrate=False):
        with self._write_lock():
            self._load_records(refresh=True)
            if migrate and identifier in self._records:
                return dict(self._records[identifier])
            records = dict(self._records)
            records[identifier] = dict(values)
            document = {"version": 1, "records": records}
            if len(records) > 10000 or len(json.dumps(document, ensure_ascii=False).encode()) > 4 * 1024 * 1024:
                raise ManagerError("本机登录资料超过存储上限，未覆盖原记录。")
            self._write_item(self.BUNDLE, document)
            self._records = records
            self.cache[identifier] = dict(values)
            return dict(values)

    def get(self, identifier):
        self.query(identifier)
        with self._lock:
            if identifier in self.cache:
                return dict(self.cache[identifier])
            self._load_records()
            if identifier in self.cache:
                return dict(self.cache[identifier])
            if identifier in self._records:
                # Callers remove an alias from cache to verify a sensitive
                # write. Always reread the actual Keychain item in this case.
                self._load_records(refresh=True)
                return dict(self._records.get(identifier, {}))
            if self._legacy_failed:
                raise ManagerError("本次未获准读取旧钥匙串记录；已停止重复请求。允许访问后请重新打开程序。")
            try: legacy = self._read_item(identifier)
            except ManagerError:
                self._legacy_failed = True
                raise
            if legacy is None:
                self.cache[identifier] = {}
                return {}
            # Migrate on first use; never erase the original legacy record.
            saved = self._save_record(identifier, legacy, migrate=True)
            self._load_records(refresh=True)
            if self._records.get(identifier) != saved:
                raise ManagerError("本机登录资料迁移回读未通过，原记录已保留。")
            return dict(saved)

    def put(self, identifier, values):
        self.query(identifier)
        if not isinstance(values, dict) or len(json.dumps(values, ensure_ascii=False).encode()) > 16384:
            raise ManagerError("本机登录资料无效或过长，未保存。")
        with self._lock:
            self._save_record(identifier, values)

    def delete(self, identifier):
        self.query(identifier)
        with self._lock:
            # A tombstone prevents an old per-item record from reappearing.
            # Also erase the old item when the user explicitly forgets it.
            self._save_record(identifier, {})
            with self.dictionary(self.query(identifier)) as query:
                status = self.sec.SecItemDelete(query)
            if status != -25300:
                self.check(status)
