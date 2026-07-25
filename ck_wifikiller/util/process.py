#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进程封装 — 默认禁止无必要 shell，降低注入风险。"""

from __future__ import annotations

import time
import signal
import os
import shlex
from subprocess import Popen, PIPE

from ..util.color import Color
from ..config import Configuration


class Process(object):
    ''' Represents a running/ran process '''

    @staticmethod
    def devnull():
        return open('/dev/null', 'w')

    @staticmethod
    def call(command, cwd=None, shell=False):
        """
        执行命令。
        - list: 永不 shell
        - str 且 shell=False: shlex 拆分
        - 显式 shell=True: 仅用于管道等（调用方负责安全）
        """
        if isinstance(command, (list, tuple)):
            shell = False
            cmd = list(command)
        else:
            cmd = command
            if not shell:
                # 旧逻辑: 有空格就 shell=True —— 已修复为 shlex.split
                if '|' in command or '>' in command or '<' in command or '&&' in command:
                    shell = True
                else:
                    cmd = shlex.split(command)
                    shell = False

        if Configuration.verbose > 1:
            disp = cmd if isinstance(cmd, str) else ' '.join(cmd)
            Color.pe('\n {C}[?]{W} Executing%s: {B}%s{W}' % (
                ' (shell)' if shell else '', disp))

        pid = Popen(cmd, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell)
        pid.wait()
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
        p = Process(['which', program])
        stdout = (p.stdout() or '').strip()
        return stdout != ''

    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0, stdin=PIPE):
        if isinstance(command, str):
            command = shlex.split(command)

        self.command = command

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} Executing: {B}%s{W}' % ' '.join(command))

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
        except AttributeError:
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
        if self.pid.poll() is None:
            self.pid.wait()
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
        self.pid.wait()

    def running_time(self):
        return int(time.time() - self.start_time)

    def interrupt(self, wait_time=2.0):
        try:
            pid = self.pid.pid
            cmd = self.command
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)

            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} sending interrupt to PID %d (%s)' % (pid, cmd))

            os.kill(pid, signal.SIGINT)
            start_time = time.time()
            while self.pid.poll() is None:
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    if Configuration.verbose > 1:
                        Color.pe('\n {C}[?] {W} killing after %.2fs' % wait_time)
                    os.kill(pid, signal.SIGTERM)
                    self.pid.terminate()
                    break
        except OSError as e:
            if 'No such process' in str(e):
                return
            raise
