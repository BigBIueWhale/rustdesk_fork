import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:get/get.dart';
import 'cm_file_owner.dart';
import 'file_model.dart';

class _CmFileJobTable {
  final jobs = <CmFileLog>[];
  final stopwatch = Stopwatch();
  int lastElapsed = 0;
}

class CmFileModel {
  final WeakReference<FFI> parent;
  final currentJobTable = RxList<CmFileLog>();
  final _ownerTables = CmFileOwnerTables<_CmFileJobTable>(_CmFileJobTable.new);

  CmFileModel(this.parent);

  void reconcileClients(Iterable<Client> clients) {
    final selectedRetired = _ownerTables.reconcile(clients.map(
        (client) => CmFileOwner(client.id, client.registryGeneration)));
    if (selectedRetired) {
      currentJobTable.clear();
    }
  }

  void updateCurrentClient(Client client) {
    final owner = CmFileOwner(client.id, client.registryGeneration);
    final selectionGeneration = _ownerTables.reserveSelection(owner);
    if (selectionGeneration == null) return;
    Future.delayed(Duration.zero, () {
      final ffi = parent.target;
      if (ffi == null ||
          !ffi.serverModel.ownsClientGeneration(
              owner.connectionId, owner.registryGeneration)) {
        _ownerTables.cancelSelection(owner, selectionGeneration);
        return;
      }
      final table = _ownerTables.commitSelection(owner, selectionGeneration);
      if (table != null) {
        currentJobTable.assignAll(table.jobs);
      }
    });
  }

  void onFileTransferLog(Map<String, dynamic> evt) {
    final envelope = CmFileLogEnvelope.tryParse(evt);
    if (envelope == null) {
      debugPrint('Rejected malformed CM file-log envelope');
      return;
    }
    final ffi = parent.target;
    if (ffi == null ||
        !ffi.serverModel.ownsClientGeneration(envelope.owner.connectionId,
            envelope.owner.registryGeneration)) {
      debugPrint('Rejected stale CM file-log owner');
      return;
    }
    switch (envelope.action) {
      case 'transfer':
        _onFileTransfer(ffi, envelope.owner, envelope.log);
        break;
      case 'remove':
        _onFileRemove(ffi, envelope.owner, envelope.log);
        break;
      case 'create_dir':
        _onDirCreate(ffi, envelope.owner, envelope.log);
        break;
      case 'rename':
        _onRename(ffi, envelope.owner, envelope.log);
        break;
    }
  }

  void _onFileTransfer(FFI ffi, CmFileOwner owner, String log) {
    try {
      final decoded = jsonDecode(log);
      final rawJobs = decoded is List<dynamic> ? decoded : <dynamic>[decoded];
      final jobs = rawJobs
          .map((job) => TransferJobSerdeData.fromJson(job))
          .toList(growable: false);
      if (jobs.any((job) => job.connId != owner.connectionId)) {
        debugPrint('Rejected CM file-log payload for a different connection');
        return;
      }
      final table = _ownerTables.tableFor(owner);
      if (table == null) {
        debugPrint('Rejected CM file log without an exact owner table');
        return;
      }
      if (jobs.isNotEmpty && !table.stopwatch.isRunning) {
        table.stopwatch.start();
      }
      final calcSpeed = table.stopwatch.elapsedMilliseconds -
              table.lastElapsed >=
          1000;
      if (calcSpeed) {
        table.lastElapsed = table.stopwatch.elapsedMilliseconds;
      }
      for (final job in jobs) {
        _dealOneJob(ffi, owner, table, job, calcSpeed);
      }
      _publishSelected(owner, table);
    } catch (e) {
      debugPrint("onFileTransferLog:$e");
    }
  }

  void _dealOneJob(FFI ffi, CmFileOwner owner, _CmFileJobTable table,
      TransferJobSerdeData data, bool calcSpeed) {
    CmFileLog? job = table.jobs.firstWhereOrNull((e) => e.id == data.id);
    if (job == null) {
      job = CmFileLog();
      table.jobs.add(job);
      _addUnread(ffi, owner);
    }
    job.id = data.id;
    job.action =
        data.isRemote ? CmFileAction.remoteToLocal : CmFileAction.localToRemote;
    job.fileName = data.path;
    job.totalSize = data.totalSize;
    job.finishedSize = data.finishedSize;
    if (job.finishedSize > data.totalSize) {
      job.finishedSize = data.totalSize;
    }

    if (job.finishedSize > 0) {
      if (job.finishedSize < job.totalSize) {
        job.state = JobState.inProgress;
      } else {
        job.state = JobState.done;
      }
    }
    if (data.done) {
      job.state = JobState.done;
    } else if (data.cancel || data.error == 'skipped') {
      job.state = JobState.done;
      job.err = 'skipped';
    } else if (data.error.isNotEmpty) {
      job.state = JobState.error;
      job.err = data.error;
    }
    if (calcSpeed) {
      job.speed = (data.transferred - job.lastTransferredSize) * 1.0;
      job.lastTransferredSize = data.transferred;
    }
  }

  void _onFileRemove(FFI ffi, CmFileOwner owner, String log) {
    try {
      final data = FileActionLog.fromJson(jsonDecode(log));
      final table = _ownerTables.tableForPayload(owner, data.connId);
      if (table == null) {
        debugPrint('Rejected CM remove log without an exact owner table');
        return;
      }
      final client = ffi.serverModel.clients.firstWhereOrNull((client) =>
          client.id == owner.connectionId &&
          client.registryGeneration == owner.registryGeneration);
      int removeUnreadCount = 0;
      if (data.dir) {
        bool isChild(String parent, String child) {
          if (child.startsWith(parent) && child.length > parent.length) {
            final suffix = child.substring(parent.length);
            return suffix.startsWith('/') || suffix.startsWith('\\');
          }
          return false;
        }

        removeUnreadCount = table.jobs
            .where((e) =>
                e.action == CmFileAction.remove &&
                isChild(data.path, e.fileName))
            .length;
        table.jobs.removeWhere((e) =>
            e.action == CmFileAction.remove && isChild(data.path, e.fileName));
      }
      table.jobs.add(CmFileLog()
        ..id = data.id
        ..fileName = data.path
        ..action = CmFileAction.remove
        ..state = JobState.done);
      final currentSelectedTab =
          ffi.serverModel.tabController.state.value.selectedTabInfo;
      if (!(ffi.chatModel.isShowCMSidePage &&
          currentSelectedTab.key == owner.connectionId.toString())) {
        // Wrong number if unreadCount changes during deletion, which rarely happens
        RxInt? rx = client?.unreadChatMessageCount;
        if (rx != null) {
          if (rx.value >= removeUnreadCount) {
            rx.value -= removeUnreadCount;
          }
          rx.value += 1;
        }
      }
      _publishSelected(owner, table);
    } catch (e) {
      debugPrint('$e');
    }
  }

  void _onDirCreate(FFI ffi, CmFileOwner owner, String log) {
    try {
      final data = FileActionLog.fromJson(jsonDecode(log));
      final table = _ownerTables.tableForPayload(owner, data.connId);
      if (table == null) {
        debugPrint(
            'Rejected CM create-directory log without an exact owner table');
        return;
      }
      table.jobs.add(CmFileLog()
        ..id = data.id
        ..fileName = data.path
        ..action = CmFileAction.createDir
        ..state = JobState.done);
      _addUnread(ffi, owner);
      _publishSelected(owner, table);
    } catch (e) {
      debugPrint('$e');
    }
  }

  void _onRename(FFI ffi, CmFileOwner owner, String log) {
    try {
      final data = FileRenamenLog.fromJson(jsonDecode(log));
      final table = _ownerTables.tableForPayload(owner, data.connId);
      if (table == null) {
        debugPrint('Rejected CM rename log without an exact owner table');
        return;
      }
      final fileName = '${data.path} -> ${data.newName}';
      table.jobs.add(CmFileLog()
        ..id = 0
        ..fileName = fileName
        ..action = CmFileAction.rename
        ..state = JobState.done);
      _addUnread(ffi, owner);
      _publishSelected(owner, table);
    } catch (e) {
      debugPrint('$e');
    }
  }

  void _addUnread(FFI ffi, CmFileOwner owner) {
    final client = ffi.serverModel.clients.firstWhereOrNull((client) =>
        client.id == owner.connectionId &&
        client.registryGeneration == owner.registryGeneration);
    final currentSelectedTab =
        ffi.serverModel.tabController.state.value.selectedTabInfo;
    if (!(ffi.chatModel.isShowCMSidePage &&
        currentSelectedTab.key == owner.connectionId.toString())) {
      client?.unreadChatMessageCount.value += 1;
    }
  }

  void _publishSelected(CmFileOwner owner, _CmFileJobTable table) {
    if (_ownerTables.isSelected(owner)) {
      currentJobTable.assignAll(table.jobs);
    }
  }
}

enum CmFileAction {
  none,
  remoteToLocal,
  localToRemote,
  remove,
  createDir,
  rename,
}

class CmFileLog {
  JobState state = JobState.none;
  var id = 0;
  var speed = 0.0;
  var finishedSize = 0;
  var totalSize = 0;
  CmFileAction action = CmFileAction.none;
  var fileName = "";
  var err = "";
  int lastTransferredSize = 0;

  String display() {
    if (state == JobState.done && err == "skipped") {
      return translate("Skipped");
    }
    return state.display();
  }

  bool isTransfer() {
    return action == CmFileAction.remoteToLocal ||
        action == CmFileAction.localToRemote;
  }
}

class TransferJobSerdeData {
  int connId;
  int id;
  String path;
  bool isRemote;
  int totalSize;
  int finishedSize;
  int transferred;
  bool done;
  bool cancel;
  String error;

  TransferJobSerdeData({
    required this.connId,
    required this.id,
    required this.path,
    required this.isRemote,
    required this.totalSize,
    required this.finishedSize,
    required this.transferred,
    required this.done,
    required this.cancel,
    required this.error,
  });

  TransferJobSerdeData.fromJson(dynamic d)
      : this(
          connId: d['connId'] ?? 0,
          id: int.tryParse(d['id'].toString()) ?? 0,
          path: d['dataSource'] ?? '',
          isRemote: d['isRemote'] ?? false,
          totalSize: d['totalSize'] ?? 0,
          finishedSize: d['finishedSize'] ?? 0,
          transferred: d['transferred'] ?? 0,
          done: d['done'] ?? false,
          cancel: d['cancel'] ?? false,
          error: d['error'] ?? '',
        );
}

class FileActionLog {
  int id = 0;
  int connId = 0;
  String path = '';
  bool dir = false;

  FileActionLog({
    required this.connId,
    required this.id,
    required this.path,
    required this.dir,
  });

  FileActionLog.fromJson(dynamic d)
      : this(
          connId: d['connId'] ?? 0,
          id: d['id'] ?? 0,
          path: d['path'] ?? '',
          dir: d['dir'] ?? false,
        );
}

class FileRenamenLog {
  int connId = 0;
  String path = '';
  String newName = '';

  FileRenamenLog({
    required this.connId,
    required this.path,
    required this.newName,
  });

  FileRenamenLog.fromJson(dynamic d)
      : this(
          connId: d['connId'] ?? 0,
          path: d['path'] ?? '',
          newName: d['newName'] ?? '',
        );
}
