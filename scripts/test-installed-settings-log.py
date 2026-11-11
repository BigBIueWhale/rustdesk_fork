#!/usr/bin/env python3
"""Bounded snapshots of real held logs in the ordinary settings-preparation container."""

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest.mock import patch


if os.getuid() != 1000 or not Path('/.dockerenv').is_file():
    raise RuntimeError('log observations require the ordinary isolated preparation container')

spec = importlib.util.spec_from_file_location(
    'installed_settings', Path(__file__).with_name('test-linux-installed-settings.py'))
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)

with tempfile.TemporaryDirectory(dir='/out', prefix='log-observation-') as temporary:
    directory = Path(temporary)
    path = directory / 'current.log'
    with path.open('w+b', buffering=0) as writer:
        path.chmod(0o600)

        def reset(data):
            writer.seek(0)
            writer.truncate()
            writer.write(data)

        def snapshot(change=None):
            original = os.fstat
            changed = False

            def observe(fd):
                nonlocal changed
                result = original(fd)
                if not changed and change is not None:
                    changed = True
                    change()
                return result

            with patch.object(settings.os, 'fstat', side_effect=observe):
                return settings.owned_log(directory, os.getpid(), os.getuid())[1]

        def refused(change=None):
            try:
                snapshot(change)
            except RuntimeError:
                return
            raise AssertionError('invalid log observation was accepted')

        large = b'existing complete log record\n' * 16384
        reset(large)
        assert snapshot() == large

        reset(b'before\n')
        assert snapshot(lambda: writer.write(b'after\n')) == b'before\n'
        assert snapshot() == b'before\nafter\n'

        reset(b'complete\n\xf0\x9f')
        assert snapshot() == b'complete\n'
        writer.write(b'\x98\x80\n')
        assert snapshot() == b'complete\n\xf0\x9f\x98\x80\n'

        reset(b'to be truncated\n')
        refused(lambda: writer.truncate(0))

        writer.truncate(8 * 1024 * 1024 + 1)
        refused()

        reset(b'original\n')
        def replace():
            path.rename(directory / 'previous.log')
            path.write_bytes(b'replacement\n')
            path.chmod(0o600)
        refused(replace)

print('LINUX_INSTALLED_SETTINGS_LOG_TESTS=pass cases=6 large=bounded append=prefix '
      'partial-record=deferred truncate=refused oversize=refused replacement=refused cleanup=joined')
