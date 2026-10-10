import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from linux_manager.models import ManagerError
from linux_manager.official_packages import download_project, official_version


class OfficialPackageTests(unittest.TestCase):
    def release(self,payload=b'fictional archive'):
        version='v1.2.3';name='sing-box-1.2.3-linux-amd64.tar.gz'
        return {'draft':False,'prerelease':False,'tag_name':version,'assets':[{'id':1,'name':name,'size':len(payload),'digest':'sha256:'+hashlib.sha256(payload).hexdigest(),'browser_download_url':f'https://github.com/SagerNet/sing-box/releases/download/{version}/{name}'}]}

    def test_public_install_works_without_github_login(self):
        import json
        with mock.patch('linux_manager.official_packages.urllib.request.urlopen',return_value=io.BytesIO(json.dumps(self.release()).encode())),mock.patch('linux_manager.official_packages.github_cli',side_effect=AssertionError('login should not be required')):
            self.assertEqual(official_version('hysteria2'),'v1.2.3')

    def test_download_checks_digest_and_size_before_use(self):
        payload=b'fictional archive'
        with tempfile.TemporaryDirectory() as folder,mock.patch('linux_manager.official_packages.official_release',return_value=self.release(payload)),mock.patch('linux_manager.official_packages.urllib.request.urlopen',return_value=io.BytesIO(payload)):
            target=Path(folder)/'package';self.assertEqual(download_project('hysteria2','v1.2.3','x86_64',target),hashlib.sha256(payload).hexdigest())

    def test_corruption_and_missing_digest_are_rejected(self):
        for corrupted in [True,False]:
            release=self.release()
            if not corrupted:release['assets'][0].pop('digest')
            with self.subTest(corrupted=corrupted),tempfile.TemporaryDirectory() as folder,mock.patch('linux_manager.official_packages.official_release',return_value=release),mock.patch('linux_manager.official_packages.urllib.request.urlopen',return_value=io.BytesIO(b'corrupt')):
                with self.assertRaises(ManagerError):download_project('hysteria2','v1.2.3','x86_64',Path(folder)/'package')

    def test_mismatched_pinned_version_and_prereleases_are_rejected(self):
        import json
        for changed in [{'tag_name':'v1.2.4'},{'prerelease':True},{'draft':True}]:
            release=self.release()|changed
            with self.subTest(changed=changed),mock.patch('linux_manager.official_packages.urllib.request.urlopen',return_value=io.BytesIO(json.dumps(release).encode())):
                with self.assertRaises(ManagerError):official_version('hysteria2','v1.2.3')


if __name__=='__main__':unittest.main()
