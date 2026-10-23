#!/usr/bin/env python3
"""Prepare data-only tests from the production file entry, sort and row formatter."""

import hashlib
import os
from pathlib import Path
import sys


def between(source, first, last):
    if source.count(first) != 1 or source.count(last) != 1:
        raise ValueError('file-metadata source boundary is missing or ambiguous')
    begin, end = source.index(first), source.index(last)
    if begin >= end:
        raise ValueError('file-metadata source boundaries are reversed')
    return source[begin:end]


def main():
    if sys.argv[1:] != ['/source', '/work/project'] or (os.geteuid(), os.getegid()) != (1000, 1000):
        raise ValueError('file-metadata probe requires its isolated nonroot model-test entry')
    repo, project = Path(sys.argv[1]), Path(sys.argv[2])
    paths = ('flutter/lib/models/file_model.dart',
             'flutter/lib/models/file_timestamp.dart',
             'flutter/lib/desktop/pages/file_manager_page.dart',
             'flutter/test_probes/file_metadata_cases.dart.inc',
             'scripts/prepare-file-metadata-probe.py')
    inputs = {name: (repo / name).read_bytes() for name in paths}
    model = inputs[paths[0]].decode('utf-8')
    page = inputs[paths[2]].decode('utf-8')
    size = ('          final sizeStr =\n'
            '              entry.isFile ? readableFileSize(entry.size.toDouble()) : "";')
    row = between(page, size, '          var secondaryPosition =').split(size, 1)[1]
    parts = {
        'sort-kind': between(model, 'enum SortBy {', 'class JobID {'),
        'entry': between(model, 'class Entry {', 'enum JobState {'),
        'path-stat': between(model, 'class _PathStat {', 'class PathUtil {'),
        'sort': between(model, 'List<Entry> _sortList(', '\n/// Define a general queue'),
        'row': 'String fileMetadataRowText(Entry entry) {\n' + row + '\n  return lastModifiedStr;\n}\n',
    }
    for name, data in inputs.items():
        if name.startswith('flutter/') and (project / name[len('flutter/'):]).read_bytes() != data:
            raise ValueError('file-metadata project copy differs from source')
        print(f'FILE_METADATA_INPUT=observed path={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    for name, text in parts.items():
        data = text.encode('utf-8')
        print(f'FILE_METADATA_SOURCE=observed part={name} bytes={len(data)} '
              f'sha256={hashlib.sha256(data).hexdigest()}', flush=True)
    body = ("import 'dart:convert';\n"
            "import 'package:flutter_test/flutter_test.dart';\n"
            "import 'package:flutter_hbb/models/file_timestamp.dart';\n\n"
            + '\n'.join(parts.values()) + '\n' + inputs[paths[3]].decode('utf-8'))
    output = project / 'test_probes/file_metadata_probe_test.dart'
    with output.open('x', encoding='utf-8') as stream:
        stream.write(body)
    output.chmod(0o400)
    data = output.read_bytes()
    if data != body.encode('utf-8'):
        raise ValueError('file-metadata generated fixture differs')
    print(f'FILE_METADATA_FIXTURE=observed bytes={len(data)} '
          f'sha256={hashlib.sha256(data).hexdigest()} parts={len(parts)} bridge=absent', flush=True)


if __name__ == '__main__':
    main()
