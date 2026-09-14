import 'package:flutter_hbb/models/cm_file_owner.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('CM file-log envelopes have fixed exact-owner fields', () {
    final envelope = CmFileLogEnvelope.tryParse(<String, dynamic>{
      'id': '41',
      'registry_generation': '73',
      'action': 'transfer',
      'log': '[]',
    });
    expect(envelope, isNotNull);
    expect(envelope!.owner, const CmFileOwner(41, 73));
    expect(envelope.action, 'transfer');
    expect(envelope.log, '[]');

    expect(
      CmFileLogEnvelope.tryParse(<String, dynamic>{
        'id': '41',
        'registry_generation': '73',
        'transfer': '[]',
      }),
      isNull,
    );
    expect(
      CmFileLogEnvelope.tryParse(<String, dynamic>{
        'id': '41',
        'registry_generation': '73',
        'action': 'unknown',
        'log': '[]',
      }),
      isNull,
    );
    expect(
      CmFileLogEnvelope.tryParse(<String, dynamic>{
        'id': '0',
        'registry_generation': '73',
        'action': 'transfer',
        'log': '[]',
      }),
      isNull,
    );
  });

  test('same-ID replacement retires its table and delayed selection', () {
    final tables = CmFileOwnerTables<List<int>>(() => <int>[]);
    const predecessor = CmFileOwner(41, 73);
    const successor = CmFileOwner(41, 74);
    const other = CmFileOwner(42, 75);

    expect(tables.reconcile(const <CmFileOwner>[predecessor]), isFalse);
    final predecessorTable = tables.tableForPayload(predecessor, 41)!;
    predecessorTable.add(9);
    final selected = tables.reserveSelection(predecessor)!;
    expect(tables.commitSelection(predecessor, selected), predecessorTable);
    final delayed = tables.reserveSelection(predecessor)!;

    expect(tables.reconcile(const <CmFileOwner>[successor]), isTrue);
    expect(tables.tableFor(predecessor), isNull);
    expect(tables.tableForPayload(predecessor, 41), isNull);
    expect(tables.commitSelection(predecessor, delayed), isNull);

    final successorTable = tables.tableForPayload(successor, 41)!;
    expect(successorTable, isEmpty);
    expect(successorTable, isNot(same(predecessorTable)));
    expect(tables.tableForPayload(successor, 42), isNull);
    final successorSelection = tables.reserveSelection(successor)!;
    expect(
      tables.commitSelection(successor, successorSelection),
      successorTable,
    );

    expect(
      tables.reconcile(const <CmFileOwner>[successor, other]),
      isFalse,
    );
    expect(tables.isSelected(successor), isTrue);
  });
}
