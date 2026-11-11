import os
from pathlib import Path
import tempfile
import unittest
from vpn_keeper.config import load, read_password


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / 'config.toml'
        self.base = '[vpn]\nserver="https://vpn.example.com"\nusername="demo"\n'

    def tearDown(self):
        self.tmp.cleanup()

    def config(self, suffix=''):
        self.path.write_text(self.base + suffix)
        self.path.chmod(0o600)
        return load(str(self.path))

    def test_defaults(self):
        self.assertEqual(self.config().interface, 'vpnk0')

    def test_group_routes_ipv6(self):
        cfg = self.config('group="staff"\nroutes=["192.0.2.0/24","2001:db8::/64"]\nhealth_target="2001:db8::1"')
        self.assertEqual(len(cfg.routes), 2)

    def test_unknown_and_wrong_types(self):
        for suffix in ['second_password="x"', 'routes="x"', 'interval=true', 'max_failures=0', 'username2="x"', 'retry_initial=200', 'interval=nan', 'interval=inf', 'failure_threshold=1.2']:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.config(suffix)

    def test_reject_bad_routes_interfaces_and_paths(self):
        for suffix in ['routes=["192.0.2.1/24"]', 'routes=["$(touch /tmp/no)"]', 'interface="../x"', 'password_file="relative"', 'health_target="example.com"']:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.config(suffix)

    def test_reject_insecure_urls(self):
        for url in ['http://vpn.example.com', 'https://user:secret@vpn.example.com', 'https://vpn.example.com/?token=x', 'https://vpn.example.com/#x', 'https://vpn.example.com:bad']:
            self.base = f'[vpn]\nserver="{url}"\nusername="demo"\n'
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.config()

    def test_private_password_permissions(self):
        path = self.root / 'secret'
        path.write_text('synthetic-only\n')
        path.chmod(0o600)
        self.assertEqual(read_password(str(path)), 'synthetic-only')
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            read_password(str(path))

    def test_password_rejects_multiple_lines_and_empty(self):
        path = self.root / 'secret'
        for value in ['', 'a\nb', 'a\r', 'a\x00b', 'x' * 4097]:
            path.write_text(value)
            path.chmod(0o600)
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                read_password(str(path))

    def test_password_preserves_spaces(self):
        path = self.root / 'secret'
        path.write_text(' a b \n')
        path.chmod(0o600)
        self.assertEqual(read_password(str(path)), ' a b ')

    def test_symlink_and_fifo_rejected_without_blocking(self):
        target = self.root / 'target'
        target.write_text('test')
        link = self.root / 'link'
        link.symlink_to(target)
        with self.assertRaises(OSError):
            read_password(str(link))
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            read_password(str(fifo))

    def test_config_group_write_rejected(self):
        self.config()
        self.path.chmod(0o660)
        with self.assertRaises(ValueError):
            load(str(self.path))
