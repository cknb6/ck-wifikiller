#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程封装 — 统一使用参数数组执行，禁止 shell 注入。"""

from __future__ import annotations

import time
import signal
import os
import shlex
from subprocess import Popen, PIPE, DEVNULL

from ..util.color import Color
from ..config import Configuration


class Process(object):
    ''' Represents a running/ran process '''

    @staticmethod
    def devnull():
        # 使用 DEVNULL 常量，避免每次 open('/dev/null') 泄漏文件描述符
        return DEVNULL

    @staticmethod
    def call(command, cwd=None, shell=False):
        """
        执行命令。
        - list/tuple: 直接作为参数数组
        - str: 使用 shlex 拆分为参数数组
        - shell=True: 明确拒绝，调用方必须改写为无 shell 形式
        """
        if shell:
            raise ValueError('shell=True is disabled; pass an argument list instead')

        if isinstance(command, (list, tuple)):
            cmd = list(command)
        elif isinstance(command, str):
            cmd = shlex.split(command)
        else:
            raise TypeError('command must be a string, list, or tuple')

        if not cmd:
            raise ValueError('command must not be empty')
        if not isinstance(cmd[0], str) or not cmd[0].strip():
            raise ValueError('command executable must be a non-empty string')

        if Configuration.verbose > 1:
            disp = ' '.join(str(arg) for arg in cmd)
            Color.pe('\n {C}[?]{W} Executing: {B}%s{W}' % disp)

        pid = Popen(cmd, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=False)
        (stdout, stderr) = pid.communicate()

        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8', errors='replace')
        if isinstance(stderr, bytes):
            stderr = stderr.decode('utf-8', errors='replace')

        if Configuration.verbose > 1 and stdout and stdout.strip():
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(stdout.strip().split('\n')))
        if Configuration.verbose > 1 and stderr and stderr.strip():
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(stderr.strip().split('\n')))

        return (stdout, stderr)

    @staticmethod
    def exists(program: str) -> bool:
        if not program or not isinstance(program, str) or '/' in program or '\\' in program:
            return False
        p = Process(['which', program])
        stdout = (p.stdout() or '').strip()
        return stdout != ''

    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0, stdin=PIPE):
        if isinstance(command, str):
            command = shlex.split(command)
        if not command:
            raise ValueError('command must not be empty')

        self.command = command

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} Executing: {B}%s{W}' % ' '.join(str(c) for c in command))

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()
        self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)

    def __del__(self):
        try:
            if self.pid and self.pid.poll() is None:
                self.interrupt()
        except Exception:
            pass

    def stdout(self):
        self.get_output()
        if Configuration.verbose > 1 and self.out and self.out.strip():
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(self.out.strip().split('\n')))
        return self.out

    def stderr(self):
        self.get_output()
        if Configuration.verbose > 1 and self.err and self.err.strip():
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(self.err.strip().split('\n')))
        return self.err

    def stdoutln(self):
        return self.pid.stdout.readline()

    def stderrln(self):
        return self.pid.stderr.readline()

    def stdin(self, text):
        if self.pid.stdin:
            self.pid.stdin.write(text.encode('utf-8'))
            self.pid.stdin.flush()

    def get_output(self):
        if self.out is None:
            (self.out, self.err) = self.pid.communicate()

        if isinstance(self.out, bytes):
            self.out = self.out.decode('utf-8', errors='replace')
        if isinstance(self.err, bytes):
            self.err = self.err.decode('utf-8', errors='replace')
        return (self.out, self.err)

    def poll(self):
        return self.pid.poll()

    def wait(self):
        self.get_output()
        return self.pid.returncode

    def running_time(self):
        return int(time.time() - self.start_time)

    def interrupt(self, wait_time=2.0):
        try:
            pid = self.pid.pid
            cmd = self.command
            if isinstance(cmd, list):
                cmd = ' '.join(str(c) for c in cmd)

            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} sending interrupt to PID %d (%s)' % (pid, cmd))

            os.kill(pid, signal.SIGINT)
            start_time = time.time()
            while self.pid.poll() is None:
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    if Configuration.verbose > 1:
                        Color.pe('\n {C}[?] {W} killing after %.2fs' % wait_time)
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
                    try:
                        self.pid.terminate()
                    except OSError:
                        pass
                    # 仍未退出则强制 SIGKILL，避免僵尸/挂死子进程
                    time.sleep(0.2)
                    if self.pid.poll() is None:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except OSError:
                            pass
                        try:
                            self.pid.kill()
                        except OSError:
                            pass
                    break
        except OSError as e:
            if 'No such process' in str(e) or getattr(e, 'errno', None) == 3:
                return
            raise
