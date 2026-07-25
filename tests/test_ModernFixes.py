#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ck_wifikiller.__main__ as main_module
from ck_wifikiller.attack.pmkid import AttackPMKID
from ck_wifikiller.attack.wpa import AttackWPA
from ck_wifikiller.config import Configuration
from ck_wifikiller.model.handshake import Handshake
from ck_wifikiller.model.target import Target
from ck_wifikiller.tools.aireplay import Aireplay
from ck_wifikiller.tools.hashcat import Hashcat, HcxPcapTool


def _target_fields(bssid='AA:BB:CC:DD:EE:FE'):
    """构造最小合法 airodump 目标行。"""
    return [
        bssid,
        '2015-05-27 19:28:44',
        '2015-05-27 19:28:46',
        '6',
        '54',
        'WPA2',
        'CCMP',
        'PSK',
        '-58',
        '2',
        '0',
        '0.0.0.0',
        '8',
        'TestWifi',
        '',
    ]


class TestInputAndCommandSafety(unittest.TestCase):
    def test_target_rejects_malformed_bssid(self):
        for bssid in (
            'AA:BB:CC:DD:EE',
            'AA:BB:CC:DD:EE:GG',
            'AA:BB:CC:DD:EE:FF;id',
            'AA-BB-CC-DD-EE-FF',
        ):
            with self.subTest(bssid=bssid):
                with self.assertRaises(ValueError):
                    Target(_target_fields(bssid))

    def test_target_rejects_any_multicast_bssid(self):
        with self.assertRaises(ValueError):
            Target(_target_fields('03:00:00:00:00:01'))

    def test_handshake_aircrack_uses_argv_and_stdin(self):
        calls = []

        class FakeProcess:
            def __init__(self, command, **kwargs):
                calls.append({'command': command, 'stdin': None, 'kwargs': kwargs})

            def stdin(self, text):
                calls[-1]['stdin'] = text

            def get_output(self):
                return 'Passphrase not in dictionary', ''

        capfile = 'capture.cap"; id; #'
        handshake = Handshake(
            capfile,
            bssid='AA:BB:CC:DD:EE:FE',
            essid='TestWifi',
        )
        with patch('ck_wifikiller.model.handshake.Process', FakeProcess):
            pairs = handshake.aircrack_handshakes()

        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0]['command'], list)
        self.assertEqual(calls[0]['command'][-1], capfile)
        self.assertEqual(calls[0]['stdin'], '\n')
        self.assertEqual(pairs, [('AA:BB:CC:DD:EE:FE', None)])

    def test_packetforge_uses_argv_without_shell(self):
        calls = []

        def fake_call(command, **kwargs):
            calls.append((command, kwargs))
            return 'Wrote packet to: forged.cap', ''

        with patch.object(Configuration, 'interface', 'wlan0mon"; id; #'), \
                patch.object(Configuration, 'temp', return_value='/tmp/'), \
                patch('ck_wifikiller.tools.aireplay.Process.call', side_effect=fake_call):
            result = Aireplay.forge_packet(
                'replay.xor',
                'AA:BB:CC:DD:EE:FE',
                '02:00:00:00:00:02',
            )

        self.assertEqual(result, 'forged.cap')
        self.assertIsInstance(calls[0][0], list)
        self.assertEqual(calls[0][0][-1], 'wlan0mon"; id; #')
        self.assertNotIn('shell', calls[0][1])


class TestAttackResultPropagation(unittest.TestCase):
    def test_pmkid_returns_false_when_cracking_fails(self):
        attack = object.__new__(AttackPMKID)
        attack.target = SimpleNamespace(
            bssid='AA:BB:CC:DD:EE:FE',
            essid='TestWifi',
        )
        attack.crack_result = None
        attack.success = False
        attack.capture_pmkid = lambda: 'captured.hc22000'
        attack.crack_pmkid_file = lambda path: False

        with patch.object(Configuration, 'ignore_old_handshakes', True, create=True), \
                patch('ck_wifikiller.util.process.Process.exists', return_value=True), \
                patch.object(HcxPcapTool, 'exists', return_value=True):
            result = attack.run()

        self.assertFalse(result)
        self.assertFalse(attack.success)

    def test_wpa_cn_hit_creates_result_and_marks_success(self):
        target = SimpleNamespace(
            wps=0,
            bssid='AA:BB:CC:DD:EE:FE',
            essid='ChinaNet-Test',
        )
        handshake = SimpleNamespace(
            analyze=lambda: None,
            bssid=target.bssid,
            essid=target.essid,
            capfile='capture.cap',
        )
        attack = AttackWPA(target)
        attack.capture_handshake = lambda: handshake
        attack._cn_mask_pipeline = lambda value: 'mask-hit-key'

        class FakeResult:
            def __init__(self, bssid, essid, capfile, key):
                self.bssid = bssid
                self.essid = essid
                self.capfile = capfile
                self.key = key
                self.dumped = False

            def dump(self):
                self.dumped = True

        with patch.object(Configuration, 'wps_only', False, create=True), \
                patch.object(Configuration, 'use_pmkid_only', False, create=True), \
                patch.object(Configuration, 'wordlist', 'wordlist.txt', create=True), \
                patch.object(Configuration, 'cn_optimize', True, create=True), \
                patch('ck_wifikiller.attack.wpa.os.path.exists', return_value=True), \
                patch('ck_wifikiller.attack.wpa.Aircrack.crack_handshake', return_value=None), \
                patch('ck_wifikiller.attack.wpa.CrackResultWPA', FakeResult):
            result = attack.run()

        self.assertTrue(result)
        self.assertTrue(attack.success)
        self.assertEqual(attack.crack_result.key, 'mask-hit-key')
        self.assertTrue(attack.crack_result.dumped)


class TestHashcatArguments(unittest.TestCase):
    def test_increment_is_mask_only_and_never_below_wpa_minimum(self):
        commands = []

        class FakeProcess:
            def __init__(self, command):
                commands.append(command)

            def wait(self):
                return 0

            def stdout(self):
                return ''

        config_values = {
            'wordlist': 'wordlist.txt',
            'hashcat_mask': '?d?d?d?d?d?d?d?d',
            'hashcat_rules': 'best64.rule',
            'hashcat_increment': True,
            'hashcat_increment_max': 4,
            'hashcat_extra_args': '--session "two words"',
        }
        patches = [
            patch.object(Configuration, name, value, create=True)
            for name, value in config_values.items()
        ]
        for item in patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(patches)])

        with patch('ck_wifikiller.tools.hashcat.os.path.isfile', return_value=True), \
                patch('ck_wifikiller.tools.hashcat.Process', FakeProcess), \
                patch.object(Hashcat, 'should_use_force', return_value=False):
            Hashcat.crack_hc22000('capture.hc22000')

        dictionary_commands = [cmd for cmd in commands if cmd[cmd.index('-a') + 1] == '0']
        mask_commands = [cmd for cmd in commands if cmd[cmd.index('-a') + 1] == '3']
        self.assertTrue(dictionary_commands)
        self.assertTrue(mask_commands)
        for command in dictionary_commands:
            self.assertNotIn('--increment', command)
            self.assertIn('-r', command)
            self.assertIn('two words', command)
        for command in mask_commands:
            self.assertIn('--increment', command)
            self.assertNotIn('-r', command)
            minimum = command[command.index('--increment-min') + 1]
            maximum = command[command.index('--increment-max') + 1]
            self.assertEqual(minimum, '8')
            self.assertEqual(maximum, '8')
            self.assertIn('two words', command)


class TestEntrypoints(unittest.TestCase):
    def test_entry_point_returns_nonzero_on_runtime_error(self):
        class BrokenApp:
            def __init__(self):
                self._session = None

            def start(self):
                raise RuntimeError('boom')

        with patch.object(main_module, 'CKWifiKiller', BrokenApp), \
                patch.object(main_module.Color, 'pexception'), \
                patch.object(main_module.Color, 'pl'):
            result = main_module.entry_point()

        self.assertEqual(result, 1)

    def test_python_module_invocation_runs_cli(self):
        root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        completed = subprocess.run(
            [sys.executable, '-m', 'ck_wifikiller', '--help'],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('--no-update', completed.stdout)


if __name__ == '__main__':
    unittest.main()
