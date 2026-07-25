#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..util.color import Color
from ..config import Configuration

import os
import time
from json import loads, dumps

class CrackResult(object):
    ''' Abstract class containing results from a crack session '''

    # 延迟读取，避免类定义时 Configuration 尚未 initialize
    cracked_file = 'cracked.txt'

    @classmethod
    def get_cracked_file(cls):
        try:
            return getattr(Configuration, 'cracked_file', None) or cls.cracked_file
        except Exception:
            return cls.cracked_file

    def __init__(self):
        self.date = int(time.time())
        self.readable_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.date))

    def dump(self):
        raise Exception('Unimplemented method: dump()')

    def to_dict(self):
        raise Exception('Unimplemented method: to_dict()')

    def print_single_line(self, longest_essid):
        raise Exception('Unimplemented method: print_single_line()')

    def print_single_line_prefix(self, longest_essid):
        essid = self.essid if self.essid else 'N/A'
        Color.p('{W} ')
        Color.p('{C}%s{W}' % essid.ljust(longest_essid))
        Color.p('  ')
        Color.p('{GR}%s{W}' % self.bssid.ljust(17))
        Color.p('  ')
        Color.p('{D}%s{W}' % self.readable_date.ljust(19))
        Color.p('  ')

    @classmethod
    def _read_results_list(cls, name):
        '''读取 cracked 文件；损坏/非列表时返回空列表，避免崩溃。'''
        if not os.path.exists(name):
            return []
        try:
            with open(name, 'r', encoding='utf-8', errors='replace') as fid:
                text = fid.read().strip()
            if not text:
                return []
            data = loads(text)
            if not isinstance(data, list):
                Color.pl('{!} {O}%s is not a JSON list, ignoring previous entries{W}' % name)
                return []
            return [item for item in data if isinstance(item, dict)]
        except Exception as e:
            Color.pl('{!} error while loading %s: %s' % (name, str(e)))
            return []

    def save(self):
        ''' Adds this crack result to the cracked file and saves it. '''
        name = CrackResult.get_cracked_file()
        saved_results = self._read_results_list(name)

        # Check for duplicates
        this_dict = self.to_dict()
        this_dict.pop('date', None)
        for entry in saved_results:
            compare = dict(this_dict)
            compare['date'] = entry.get('date')
            if entry == compare:
                # Skip if we already saved this BSSID+ESSID+TYPE+KEY
                Color.pl('{+} {C}%s{O} already exists in {G}%s{O}, skipping.' % (
                    self.essid, name))
                return

        saved_results.append(self.to_dict())
        # 原子写入，降低半截 JSON 风险
        tmp_name = name + '.tmp'
        with open(tmp_name, 'w', encoding='utf-8') as fid:
            fid.write(dumps(saved_results, indent=2))
            fid.flush()
            try:
                os.fsync(fid.fileno())
            except OSError:
                pass
        os.replace(tmp_name, name)
        Color.pl('{+} saved crack result to {C}%s{W} ({G}%d total{W})'
            % (name, len(saved_results)))

    @classmethod
    def display(cls):
        ''' Show cracked targets from cracked file '''
        name = cls.get_cracked_file()
        if not os.path.exists(name):
            Color.pl('{!} {O}file {C}%s{O} not found{W}' % name)
            return

        cracked_targets = cls._read_results_list(name)

        if len(cracked_targets) == 0:
            Color.pl('{!} {R}no results found in {O}%s{W}' % name)
            return

        Color.pl('\n{+} Displaying {G}%d{W} cracked target(s) from {C}%s{W}\n' % (
            len(cracked_targets), name))

        results = []
        for item in cracked_targets:
            try:
                results.append(cls.load(item))
            except (KeyError, TypeError, ValueError) as e:
                Color.pl('{!} {O}skipping malformed crack entry: %s{W}' % e)
        if not results:
            Color.pl('{!} {R}no valid results found in {O}%s{W}' % name)
            return
        results = sorted(results, key=lambda x: x.date, reverse=True)
        longest_essid = max([len(result.essid or 'ESSID') for result in results])

        # Header
        Color.p('{D} ')
        Color.p('ESSID'.ljust(longest_essid))
        Color.p('  ')
        Color.p('BSSID'.ljust(17))
        Color.p('  ')
        Color.p('DATE'.ljust(19))
        Color.p('  ')
        Color.p('TYPE'.ljust(5))
        Color.p('  ')
        Color.p('KEY')
        Color.pl('{D}')
        Color.p(' ' + '-' * (longest_essid + 17 + 19 + 5 + 11 + 12))
        Color.pl('{W}')
        # Results
        for result in results:
            result.print_single_line(longest_essid)
        Color.pl('')


    @classmethod
    def load_all(cls):
        path = cls.get_cracked_file()
        return cls._read_results_list(path)

    @staticmethod
    def load(json):
        ''' Returns an instance of the appropriate object given a json instance '''
        if not isinstance(json, dict):
            raise ValueError('crack result entry must be an object')
        rtype = json.get('type')
        if rtype == 'WPA':
            from .wpa_result import CrackResultWPA
            result = CrackResultWPA(json['bssid'],
                                    json['essid'],
                                    json['handshake_file'],
                                    json['key'])
        elif rtype == 'WEP':
            from .wep_result import CrackResultWEP
            result = CrackResultWEP(json['bssid'],
                                    json['essid'],
                                    json['hex_key'],
                                    json['ascii_key'])

        elif rtype == 'WPS':
            from .wps_result import CrackResultWPS
            result = CrackResultWPS(json['bssid'],
                                    json['essid'],
                                    json['pin'],
                                    json['psk'])

        elif rtype == 'PMKID':
            from .pmkid_result import CrackResultPMKID
            result = CrackResultPMKID(json['bssid'],
                                      json['essid'],
                                      json['pmkid_file'],
                                      json['key'])
        else:
            raise ValueError('unknown crack result type: %r' % rtype)
        result.date = int(json.get('date') or 0)
        result.readable_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.date))
        return result

if __name__ == '__main__':
    # Deserialize WPA object
    Color.pl('\nCracked WPA:')
    json = loads('{"bssid": "AA:BB:CC:DD:EE:FF", "essid": "Test Router", "key": "Key", "date": 1433402428, "handshake_file": "hs/capfile.cap", "type": "WPA"}')
    obj = CrackResult.load(json)
    obj.dump()

    # Deserialize WEP object
    Color.pl('\nCracked WEP:')
    json = loads('{"bssid": "AA:BB:CC:DD:EE:FF", "hex_key": "00:01:02:03:04", "ascii_key": "abcde", "essid": "Test Router", "date": 1433402915, "type": "WEP"}')
    obj = CrackResult.load(json)
    obj.dump()

    # Deserialize WPS object
    Color.pl('\nCracked WPS:')
    json = loads('{"psk": "the psk", "bssid": "AA:BB:CC:DD:EE:FF", "pin": "01234567", "essid": "Test Router", "date": 1433403278, "type": "WPS"}')
    obj = CrackResult.load(json)
    obj.dump()
