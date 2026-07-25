#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from ck_wifikiller.util.process import Process


class _FakeChild:
    """只记录调用顺序，不启动真实子进程。"""

    def __init__(self):
        self.communicated = False
        self.returncode = 0

    def poll(self):
        return None

    def wait(self):
        raise AssertionError('读取 PIPE 前不得先调用 wait()')

    def communicate(self):
        self.communicated = True
        self.returncode = 0
        return b'out', b'err'


class TestProcess(unittest.TestCase):
    def test_call_never_infers_shell_from_metacharacters(self):
        child = _FakeChild()
        with patch('ck_wifikiller.util.process.Popen', return_value=child) as popen:
            stdout, stderr = Process.call('printf hello | id')

        command = popen.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertIn('|', command)
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertEqual(stdout, 'out')
        self.assertEqual(stderr, 'err')

    def test_call_rejects_explicit_shell(self):
        with patch('ck_wifikiller.util.process.Popen') as popen:
            with self.assertRaises(ValueError):
                Process.call('printf hello | id', shell=True)
        popen.assert_not_called()

    def test_get_output_communicates_without_waiting_first(self):
        process = object.__new__(Process)
        process.pid = _FakeChild()
        process.out = None
        process.err = None

        stdout, stderr = process.get_output()

        self.assertTrue(process.pid.communicated)
        self.assertEqual(stdout, 'out')
        self.assertEqual(stderr, 'err')

    def test_wait_drains_pipes_with_communicate(self):
        process = object.__new__(Process)
        process.pid = _FakeChild()
        process.out = None
        process.err = None

        returncode = process.wait()

        self.assertTrue(process.pid.communicated)
        self.assertEqual(returncode, 0)


if __name__ == '__main__':
    unittest.main()
