import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from vpn_keeper.cli import main, status
from vpn_keeper.config import Config
from vpn_keeper.runtime import SAFE_ENV, State, Supervisor, command, health, terminate, child_exited, probe

BINS = {'openconnect': '/usr/bin/openconnect', 'ip': '/usr/bin/ip', 'ping': '/usr/bin/ping', 'vpn-slice': '/usr/bin/vpn-slice'}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config('https://vpn.example.com', 'example', group='staff')

    def test_command_stdin_no_secret_and_noninteractive(self):
        args = command(self.cfg, BINS)
        self.assertIn('--passwd-on-stdin', args)
        self.assertIn('--non-inter', args)
        self.assertIn('--authgroup=staff', args)
        self.assertNotIn('--no-cert-check', args)
        self.assertNotIn('https_proxy', SAFE_ENV)

    def test_username_option_injection_is_not_an_option(self):
        args = command(dataclasses.replace(self.cfg, username='--no-cert-check'), BINS)
        self.assertIn('--user=--no-cert-check', args)
        self.assertNotIn('--no-cert-check', args)

    def test_routes_use_vpn_slice(self):
        cfg = dataclasses.replace(self.cfg, routes=['192.0.2.0/24'])
        self.assertIn('--script=/usr/bin/vpn-slice 192.0.2.0/24', command(cfg, BINS))

    @patch('vpn_keeper.runtime.probe')
    def test_up_address_and_exact_route(self, query):
        cfg = dataclasses.replace(self.cfg, routes=['192.0.2.0/24'])
        query.side_effect = [json.dumps([{'flags':['UP'], 'addr_info':[{'family':'inet', 'scope':'global'}]}]), json.dumps([{'dst':'192.0.2.0/24'}])]
        self.assertTrue(health(cfg, BINS))
        query.side_effect = [json.dumps([{'flags':['UP'], 'addr_info':[{'family':'inet', 'scope':'global'}]}]), json.dumps([{'dst':'192.0.20.0/24'}])]
        self.assertFalse(health(cfg, BINS))

    @patch('vpn_keeper.runtime.probe')
    def test_ipv6_and_default_routes(self, query):
        cfg = dataclasses.replace(self.cfg, routes=['::/0'])
        query.side_effect = [json.dumps([{'flags':['UP'], 'addr_info':[{'family':'inet6', 'scope':'global'}]}]), '[{"dst":"default"}]']
        self.assertTrue(health(cfg, BINS))
        self.assertIn('-6', query.call_args.args[0])

    @patch('vpn_keeper.runtime.probe')
    def test_health_errors_and_linklocal_fail_closed(self, query):
        for value in ['[]', 'bad-json', '[{"flags":["UP"],"addr_info":[{"family":"inet6","scope":"link"}]}]']:
            query.return_value = value
            self.assertFalse(health(self.cfg, BINS))
        query.side_effect = subprocess.TimeoutExpired('ip', 5)
        self.assertFalse(health(self.cfg, BINS))

    @patch('vpn_keeper.runtime.probe')
    def test_ping_bound_to_vpn_interface(self, query):
        query.side_effect = ['[{"flags":["UP"],"addr_info":[{"family":"inet","scope":"global"}]}]', b'']
        self.assertTrue(health(dataclasses.replace(self.cfg, health_target='192.0.2.1'), BINS))
        self.assertEqual(query.call_args.args[0][2:4], ['-I', 'vpnk0'])

    def test_backoff_bounded_and_capped(self):
        cfg = dataclasses.replace(self.cfg, max_failures=5, retry_initial=2, retry_max=5)
        stop = Mock()
        stop.is_set.return_value = False
        state = Mock()
        runner = Supervisor(cfg, BINS, state, stop)
        runner.session = Mock(return_value=False)
        self.assertEqual(runner.run(), 1)
        self.assertEqual(runner.session.call_count, 5)
        self.assertEqual([call.args[0] for call in stop.wait.call_args_list], [2,4,5,5])
        state.write.assert_called_with('failed', 5)

    def test_single_connection_does_not_retry(self):
        stop = Mock()
        stop.is_set.return_value = False
        runner = Supervisor(self.cfg, BINS, Mock(), stop, once=True)
        runner.session = Mock(return_value=False)
        self.assertEqual(runner.run(), 1)
        runner.session.assert_called_once()
        stop.wait.assert_not_called()

    def test_stable_session_resets_budget(self):
        stop = Mock()
        stop.is_set.return_value = False
        cfg = dataclasses.replace(self.cfg, max_failures=3)
        runner = Supervisor(cfg, BINS, Mock(), stop)
        runner.session = Mock(side_effect=[False, True, False, False])
        self.assertEqual(runner.run(), 1)
        self.assertEqual(runner.session.call_count, 4)

    @patch('vpn_keeper.runtime.child_exited', return_value=False)
    @patch('vpn_keeper.runtime.terminate')
    @patch('vpn_keeper.runtime.health', return_value=False)
    @patch('vpn_keeper.runtime.subprocess.Popen')
    @patch('vpn_keeper.runtime.time.monotonic', side_effect=[0, 61])
    def test_startup_timeout_cleans_owned_child(self, clock, popen, check, cleanup, exited):
        proc = popen.return_value
        proc.poll.return_value = None
        runner = Supervisor(self.cfg, BINS, Mock(), threading.Event(), password='synthetic')
        self.assertFalse(runner.session())
        cleanup.assert_called_once_with(proc)
        proc.stdin.write.assert_called_once_with(b'synthetic\n')
        self.assertNotIn('synthetic', str(popen.call_args))

    @patch('vpn_keeper.runtime.child_exited', return_value=False)
    @patch('vpn_keeper.runtime.terminate')
    @patch('vpn_keeper.runtime.health', side_effect=[True, False, False, False])
    @patch('vpn_keeper.runtime.subprocess.Popen')
    def test_health_failure_threshold(self, popen, check, cleanup, exited):
        popen.return_value.poll.return_value = None
        stop = Mock()
        stop.is_set.return_value = False
        state = Mock()
        runner = Supervisor(self.cfg, BINS, state, stop, password='synthetic')
        self.assertFalse(runner.session())
        self.assertEqual(check.call_count, 4)
        cleanup.assert_called_once()

    def test_real_local_fake_child_gets_only_stdin_secret_and_is_stopped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fake = root / 'fake-openconnect'
            output = root / 'captured.json'
            fake.write_text('#!/usr/bin/python3\nimport sys,os,json,time\ns=json.dumps({"stdin":sys.stdin.readline(),"args":sys.argv,"env":dict(os.environ)})\nopen(' + repr(str(output)) + ',"w").write(s)\ntime.sleep(30)\n')
            fake.chmod(0o700)
            state = State(root / 'state')
            state.acquire()
            stop = threading.Event()
            runner = Supervisor(dataclasses.replace(self.cfg, interval=0.01), dict(BINS, openconnect=str(fake)), state, stop, password='fixture-secret')
            def stop_when_received():
                deadline = time.monotonic() + 5
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                stop.set()
            worker = threading.Thread(target=stop_when_received)
            worker.start()
            try:
                with patch('vpn_keeper.runtime.health', return_value=True):
                    self.assertEqual(runner.run(), 0)
                worker.join(timeout=6)
                capture = json.loads(output.read_text())
                self.assertEqual(capture['stdin'], 'fixture-secret\n')
                self.assertNotIn('fixture-secret', str(capture['args']))
                self.assertNotIn('fixture-secret', str(capture['env']))
                self.assertNotIn('fixture-secret', (root/'state'/'status.json').read_text())
            finally:
                stop.set()
                state.close()

    def test_owned_process_group_termination(self):
        proc = subprocess.Popen(['/usr/bin/python3','-c','import time; time.sleep(30)'], start_new_session=True)
        terminate(proc, grace=0.1)
        self.assertIsNotNone(proc.poll())

    def test_reaped_leader_is_never_signalled(self):
        proc = Mock(returncode=0)
        with patch('vpn_keeper.runtime.os.killpg') as kill:
            with self.assertRaises(RuntimeError):
                terminate(proc, grace=0)
            kill.assert_not_called()

    def test_lost_child_ownership_is_never_signalled(self):
        proc = Mock(returncode=None, pid=123456)
        with patch('vpn_keeper.runtime.os.waitid', side_effect=ChildProcessError), patch('vpn_keeper.runtime.os.killpg') as kill:
            with self.assertRaises(ChildProcessError):
                terminate(proc, grace=0)
            kill.assert_not_called()

    def test_stop_interrupts_real_probe(self):
        stop = threading.Event()
        timer = threading.Timer(0.15, stop.set)
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                probe([sys.executable, '-c', 'import time; time.sleep(30)'], stop)
            self.assertLess(time.monotonic() - start, 2)
        finally:
            timer.join()

    def test_probe_timeout_is_bounded(self):
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            probe([sys.executable, '-c', 'import time; time.sleep(30)'], threading.Event(), timeout=0.15)
        self.assertLess(time.monotonic() - start, 2)

    def test_stop_prevents_launch_and_followup_queries(self):
        stop = threading.Event()
        stop.set()
        with patch('vpn_keeper.runtime.subprocess.Popen') as popen:
            self.assertFalse(health(self.cfg, BINS, stop))
            popen.assert_not_called()
        stop.clear()
        def first_query(*args):
            stop.set()
            return b'[{"flags":["UP"],"addr_info":[{"family":"inet","scope":"global"}]}]'
        cfg = dataclasses.replace(self.cfg, routes=['192.0.2.0/24', '2001:db8::/64'], health_target='192.0.2.1')
        with patch('vpn_keeper.runtime.probe', side_effect=first_query) as query:
            self.assertFalse(health(cfg, BINS, stop))
            self.assertEqual(query.call_count, 1)

    def test_descendants_cleaned_after_leader_exit_and_term(self):
        # Isolated Linux subreaper keeps the test's orphan fixtures out of PID 1.
        script = r"""
import ctypes, os, signal, subprocess, sys, tempfile, time
from pathlib import Path
from vpn_keeper.runtime import child_exited, terminate
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
with tempfile.TemporaryDirectory() as d:
    ready = Path(d) / 'ready'
    child = '''import os,signal,sys,time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open(sys.argv[1], 'w').write(str(os.getpid()))
    time.sleep(30)
else:
    while not os.path.exists(sys.argv[1]): time.sleep(.01)
    if sys.argv[2] == 'exit': sys.exit(0)
    time.sleep(30)
'''
    proc = subprocess.Popen([sys.executable, '-c', child, str(ready), sys.argv[1]], start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        while not ready.exists() or (sys.argv[1] == 'exit' and not child_exited(proc)):
            assert time.monotonic() < deadline
            time.sleep(.01)
    finally:
        terminate(proc, grace=.1)
    while True:
        try:
            pid, status = os.waitpid(-1, 0)
            assert os.waitstatus_to_exitcode(status) == -signal.SIGKILL
        except ChildProcessError:
            break
"""
        for mode in ('exit', 'term'):
            with self.subTest(mode=mode):
                subprocess.run([sys.executable, '-c', script, mode], check=True, timeout=5)


class StateTests(unittest.TestCase):
    def test_lock_duplicate_and_stale_status(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / 'state'
            first = State(directory)
            first.acquire()
            try:
                first.write('connected')
                self.assertTrue(status(directory)['running'])
                with self.assertRaises(ValueError):
                    State(directory).acquire()
            finally:
                first.close()
            self.assertEqual(status(directory), {'state':'stopped', 'running':False})

    def test_insecure_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'state'
            path.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                State(path).acquire()

    def test_status_missing_is_stopped(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(status(Path(d)/'missing')['running'])

    def test_validate_example_offline(self):
        with patch('vpn_keeper.cli.dependencies') as deps:
            self.assertEqual(main(['--config','examples/config.toml','validate']), 0)
            deps.assert_not_called()
