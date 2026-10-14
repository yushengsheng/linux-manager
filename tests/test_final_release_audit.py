import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.final_release_audit import audit_archive
from tools.package_desktop import package_release


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.release = root / 'release'; self.release.mkdir()
        (self.release / '说明.md').write_text('release')
        self.archive = root / 'release.zip'
        self.checksum = root / 'release.sha256'

    def package(self, extra=None):
        with zipfile.ZipFile(self.archive, 'w') as archive:
            for file in self.release.iterdir():
                archive.write(file, self.release.name + '/' + file.name)
            if extra:
                archive.writestr(*extra)
        self.checksum.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() + '  ' + self.archive.name + '\n')

    def test_clean_archive_matches_the_delivery(self):
        self.package()
        audit_archive(self.release, self.archive, self.checksum)

    def test_changed_delivery_is_not_approved_with_a_valid_archive_checksum(self):
        self.package()
        (self.release / '说明.md').write_text('changed')
        with self.assertRaisesRegex(ValueError, '内容不一致'):
            audit_archive(self.release, self.archive, self.checksum)

    def test_private_data_and_traversal_are_rejected_even_with_matching_checksum(self):
        for name in ['release/profiles.json', 'release/../unexpected']:
            with self.subTest(name=name):
                self.package((name, '{}'))
                with self.assertRaises(ValueError):
                    audit_archive(self.release, self.archive, self.checksum)

    def test_missing_delivery_file_and_incorrect_checksum_are_rejected(self):
        self.package()
        (self.release / 'added.md').write_text('new')
        with self.assertRaisesRegex(ValueError, '缺少交付文件'):
            audit_archive(self.release, self.archive, self.checksum)
        self.checksum.write_text('0' * 64 + '  ' + self.archive.name)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            audit_archive(self.release, self.archive, self.checksum)

    def test_packaging_uses_utf8_and_preserves_executable_permissions_and_links(self):
        script = self.release / '启动程序'; script.write_text('script'); script.chmod(0o755)
        (self.release / '链接').symlink_to('启动程序')
        package_release(self.release, self.archive)
        audit_archive(self.release, self.archive, self.checksum)
        with zipfile.ZipFile(self.archive) as package:
            for name in ['说明.md', '启动程序', '链接']:
                self.assertTrue(package.getinfo('release/' + name).flag_bits & 0x800)
            self.assertEqual(package.getinfo('release/启动程序').external_attr >> 16 & 0o777, 0o755)
            self.assertEqual(package.read('release/链接'), os.readlink(self.release / '链接').encode())

    def test_failed_package_audit_preserves_the_existing_archive(self):
        self.archive.write_bytes(b'existing-package')
        (self.release / 'profiles.json').write_text('{}')
        with self.assertRaises(ValueError):
            package_release(self.release, self.archive)
        self.assertEqual(self.archive.read_bytes(), b'existing-package')
