import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/dialog.dart';
import 'package:flutter_hbb/utils/event_loop.dart';
import 'package:get/get.dart';
import 'package:path/path.dart' as path;
import 'package:flutter_hbb/web/dummy.dart'
    if (dart.library.html) 'package:flutter_hbb/web/web_unique.dart';

import '../consts.dart';
import 'model.dart';
import 'platform_model.dart';

enum SortBy {
  name,
  type,
  modified,
  size;

  @override
  String toString() {
    final str = this.name.toString();
    return "${str[0].toUpperCase()}${str.substring(1)}";
  }
}

class JobID {
  int _count = 0;
  int next() {
    try {
      if (!isWeb) {
        String v = bind.mainGetCommonSync(key: 'transfer-job-id');
        return int.parse(v);
      }
    } catch (e) {
      debugPrint("Failed to get transfer job id: $e");
    }
    // Finally increase the count if on the web or if failed to get the id.
    _count++;
    return _count;
  }
}

typedef GetSessionID = SessionID Function();
typedef GetDialogManager = OverlayDialogManager? Function();
typedef IsCurrentSession = bool Function(SessionID sessionId);
typedef GetPeerPlatform = String? Function();
typedef GetPeerVersion = String Function();
typedef ReadRemoteDirectory = Future<void> Function(
    SessionID sessionId, String path, bool showHidden);
typedef ReadRemoteDirectoryTree = Future<void> Function(SessionID sessionId,
    int actionId, String path, bool isRemote, bool showHidden);
typedef SendFilesRequest = Future<void> Function(
    SessionID sessionId,
    int actionId,
    String path,
    String to,
    int fileNum,
    bool includeHidden,
    bool isRemote,
    bool isDirectory);
typedef RemoveFileRequest = Future<void> Function(SessionID sessionId,
    int actionId, String path, bool isRemote, int fileNum);
typedef RemoveEmptyDirectoriesRequest = Future<void> Function(
    SessionID sessionId, int actionId, String path, bool isRemote);
typedef CreateDirectoryRequest = Future<void> Function(
    SessionID sessionId, int actionId, String path, bool isRemote);
typedef RenameFileRequest = Future<void> Function(SessionID sessionId,
    int actionId, String path, String newName, bool isRemote);
typedef CancelJobRequest = Future<void> Function(
    SessionID sessionId, int actionId);
typedef AddJobRequest = Future<void> Function(
    SessionID sessionId,
    bool isRemote,
    bool includeHidden,
    int actionId,
    String path,
    String to,
    int fileNum);
typedef ResumeJobRequest = Future<void> Function(
    SessionID sessionId, int actionId, bool isRemote);

class FileFetcherRequests {
  const FileFetcherRequests({
    required this.readDirectory,
    required this.readEmptyDirectories,
    required this.readDirectoryTree,
  });

  final ReadRemoteDirectory readDirectory;
  final ReadRemoteDirectory readEmptyDirectories;
  final ReadRemoteDirectoryTree readDirectoryTree;

  static final native = FileFetcherRequests(
    readDirectory: (sessionId, path, showHidden) => bind.sessionReadRemoteDir(
        sessionId: sessionId, path: path, includeHidden: showHidden),
    readEmptyDirectories: (sessionId, path, showHidden) =>
        bind.sessionReadRemoteEmptyDirsRecursiveSync(
            sessionId: sessionId, path: path, includeHidden: showHidden),
    readDirectoryTree: (sessionId, actionId, path, isRemote, showHidden) =>
        bind.sessionReadDirToRemoveRecursive(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            isRemote: isRemote,
            showHidden: showHidden),
  );
}

class FileControllerRequests {
  const FileControllerRequests({
    required this.sendFiles,
    required this.removeFile,
    required this.removeEmptyDirectories,
    required this.createDirectory,
    required this.renameFile,
  });

  final SendFilesRequest sendFiles;
  final RemoveFileRequest removeFile;
  final RemoveEmptyDirectoriesRequest removeEmptyDirectories;
  final CreateDirectoryRequest createDirectory;
  final RenameFileRequest renameFile;

  static final native = FileControllerRequests(
    sendFiles: (sessionId, actionId, path, to, fileNum, includeHidden,
            isRemote, isDirectory) =>
        bind.sessionSendFiles(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            to: to,
            fileNum: fileNum,
            includeHidden: includeHidden,
            isRemote: isRemote,
            isDir: isDirectory),
    removeFile: (sessionId, actionId, path, isRemote, fileNum) =>
        bind.sessionRemoveFile(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            isRemote: isRemote,
            fileNum: fileNum),
    removeEmptyDirectories: (sessionId, actionId, path, isRemote) =>
        bind.sessionRemoveAllEmptyDirs(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            isRemote: isRemote),
    createDirectory: (sessionId, actionId, path, isRemote) =>
        bind.sessionCreateDir(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            isRemote: isRemote),
    renameFile: (sessionId, actionId, path, newName, isRemote) =>
        bind.sessionRenameFile(
            sessionId: sessionId,
            actId: actionId,
            path: path,
            newName: newName,
            isRemote: isRemote),
  );
}

class JobControllerRequests {
  const JobControllerRequests({
    required this.cancelJob,
    required this.addJob,
    required this.resumeJob,
  });

  final CancelJobRequest cancelJob;
  final AddJobRequest addJob;
  final ResumeJobRequest resumeJob;

  static final native = JobControllerRequests(
    cancelJob: (sessionId, actionId) =>
        bind.sessionCancelJob(sessionId: sessionId, actId: actionId),
    addJob: (sessionId, isRemote, includeHidden, actionId, path, to, fileNum) =>
        bind.sessionAddJob(
            sessionId: sessionId,
            isRemote: isRemote,
            includeHidden: includeHidden,
            actId: actionId,
            path: path,
            to: to,
            fileNum: fileNum),
    resumeJob: (sessionId, actionId, isRemote) => bind.sessionResumeJob(
        sessionId: sessionId, actId: actionId, isRemote: isRemote),
  );
}

@immutable
class FileOverrideConfirmation {
  static const int maxReadPathCodeUnits = 32768;
  static const int _maxNativeInt = 0x7fffffff;

  const FileOverrideConfirmation({
    required this.jobId,
    required this.fileNum,
    required this.readPath,
    required this.isUpload,
    required this.isIdentical,
  });

  final int jobId;
  final int fileNum;
  final String readPath;
  final bool isUpload;
  final bool isIdentical;

  static FileOverrideConfirmation? tryParse(Map<String, dynamic> event) {
    final rawJobId = event['id'];
    final rawFileNum = event['file_num'];
    final readPath = event['read_path'];
    final rawIsUpload = event['is_upload'];
    final rawIsIdentical = event['is_identical'];
    if (event['name'] != 'override_file_confirm' ||
        rawJobId is! String ||
        rawFileNum is! String ||
        readPath is! String ||
        rawIsUpload is! String ||
        rawIsIdentical is! String) {
      return null;
    }
    final jobId = int.tryParse(rawJobId);
    final fileNum = int.tryParse(rawFileNum);
    final isUpload = _tryParseBool(rawIsUpload);
    final isIdentical = _tryParseBool(rawIsIdentical);
    if (jobId == null ||
        jobId <= 0 ||
        jobId > _maxNativeInt ||
        rawJobId != jobId.toString() ||
        fileNum == null ||
        fileNum < 0 ||
        fileNum > _maxNativeInt ||
        rawFileNum != fileNum.toString() ||
        readPath.isEmpty ||
        readPath.length > maxReadPathCodeUnits ||
        readPath.contains('\u0000') ||
        isUpload == null ||
        isIdentical == null) {
      return null;
    }
    return FileOverrideConfirmation(
      jobId: jobId,
      fileNum: fileNum,
      readPath: readPath,
      isUpload: isUpload,
      isIdentical: isIdentical,
    );
  }

  static bool? _tryParseBool(String value) {
    if (value == 'true') return true;
    if (value == 'false') return false;
    return null;
  }
}

class FileModel {
  final WeakReference<FFI> parent;
  late final FileFetcher fileFetcher;
  late final JobController jobController;

  late final FileController localController;
  late final FileController remoteController;

  late final GetSessionID getSessionID;
  late final GetDialogManager getDialogManager;
  SessionID get sessionId => getSessionID();
  late final FileDialogEventLoop evtLoop;
  SessionID? _ownedSessionId;

  FileModel(this.parent) {
    getSessionID = () => parent.target!.sessionId;
    getDialogManager = () => parent.target?.dialogManager;
    final isCurrentSession = _isCurrentSession;
    fileFetcher = FileFetcher(getSessionID);
    jobController = JobController(getSessionID, getDialogManager,
        isCurrentSession: isCurrentSession);
    localController = FileController(
        isLocal: true,
        getSessionID: getSessionID,
        getDialogManager: getDialogManager,
        isCurrentSession: isCurrentSession,
        getPeerPlatform: () => parent.target?.ffiModel.pi.platform,
        getPeerVersion: () => parent.target?.ffiModel.pi.version ?? '',
        jobController: jobController,
        fileFetcher: fileFetcher,
        getOtherSideDirectoryData: () => remoteController.directoryData());
    remoteController = FileController(
        isLocal: false,
        getSessionID: getSessionID,
        getDialogManager: getDialogManager,
        isCurrentSession: isCurrentSession,
        getPeerPlatform: () => parent.target?.ffiModel.pi.platform,
        getPeerVersion: () => parent.target?.ffiModel.pi.version ?? '',
        jobController: jobController,
        fileFetcher: fileFetcher,
        getOtherSideDirectoryData: () => localController.directoryData());
    evtLoop = FileDialogEventLoop();
    _ownedSessionId = getSessionID();
  }

  bool _isCurrentSession(SessionID expectedSessionId) =>
      _ownedSessionId == expectedSessionId &&
      parent.target?.isCurrentSession(expectedSessionId) == true;

  void beginSession(SessionID expectedSessionId) {
    if (parent.target?.isCurrentSession(expectedSessionId) != true) return;
    _ownedSessionId = null;
    unawaited(evtLoop.close());
    parent.target?.dialogManager.dismissAll();
    fileFetcher.cancelPending();
    jobController.clear();
    localController.resetForSession();
    remoteController.resetForSession();
    fileConfirmCheckboxRemember = false;
    _ownedSessionId = expectedSessionId;
  }

  Future<void> onReady(SessionID expectedSessionId) async {
    if (_ownedSessionId != expectedSessionId ||
        !_isCurrentSession(expectedSessionId)) return;
    await evtLoop.onReady();
    if (!_isCurrentSession(expectedSessionId)) return;
    if (!isWeb) {
      await localController.onReady(expectedSessionId);
      if (!_isCurrentSession(expectedSessionId)) return;
    }
    await remoteController.onReady(expectedSessionId);
  }

  Future<void> close(SessionID expectedSessionId) async {
    if (_ownedSessionId != expectedSessionId ||
        parent.target?.sessionId != expectedSessionId) return;
    // Retire every file-operation admission edge synchronously. Cleanup may
    // await native state persistence, but no old continuation may survive that
    // await and become work owned by a replacement mobile session.
    _ownedSessionId = null;
    final eventLoopClose = evtLoop.close();
    fileFetcher.cancelPending();
    jobController.clear();
    parent.target?.dialogManager.dismissAll();
    fileConfirmCheckboxRemember = false;
    await eventLoopClose;
    if (parent.target?.sessionId != expectedSessionId) return;
    await localController.close(expectedSessionId);
    if (parent.target?.sessionId != expectedSessionId) return;
    await remoteController.close(expectedSessionId);
  }

  Future<void> refreshAll(SessionID expectedSessionId) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    if (!isWeb) {
      await localController.refresh(expectedSessionId: expectedSessionId);
      if (!_isCurrentSession(expectedSessionId)) return;
    }
    await remoteController.refresh(expectedSessionId: expectedSessionId);
  }

  void receiveFileDir(
      Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!_isCurrentSession(expectedSessionId)) return;
    if (evt['is_local'] == "false") {
      // init remote home, the remote connection will send one dir event when established. TODO opt
      remoteController.initDirAndHome(evt);
    }
    fileFetcher.tryCompleteTask(
        expectedSessionId, evt['value'], evt['is_local']);
  }

  void receiveEmptyDirs(
      Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!_isCurrentSession(expectedSessionId)) return;
    fileFetcher.tryCompleteEmptyDirsTask(
        expectedSessionId, evt['value'], evt['is_local']);
  }

  // This method fixes a deadlock that occurred when the previous code directly
  // called jobController.jobError(evt) in the job_error event handler.
  //
  // The problem with directly calling jobController.jobError():
  //   1. fetchDirectoryRecursiveToRemove(jobID) reserves the recursive response
  //      owner before dispatch and waits for completion
  //   2. If the remote has no permission (or some other errors), it returns a FileTransferError
  //   3. The error triggers job_error event, which called jobController.jobError()
  //   4. jobController.jobError() calls getJob(jobID) to find the job in jobTable
  //   5. But addDeleteDirJob() is called AFTER fetchDirectoryRecursiveToRemove(),
  //      so the job doesn't exist yet in jobTable
  //   6. Result: jobController.jobError() does nothing useful, and
  //      readRecursiveTasks[jobID] never completes, causing a 2s timeout
  //
  // Solution: Before calling jobController.jobError(), we first check if there's
  // a pending readRecursiveTasks with this ID and complete it with the error.
  void handleJobError(Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!_isCurrentSession(expectedSessionId)) return;
    final id = int.tryParse(evt['id']?.toString() ?? '');
    if (id != null) {
      final err = evt['err']?.toString() ?? 'Unknown error';
      fileFetcher.tryCompleteRecursiveTaskWithError(
          expectedSessionId, id, err);
    }
    // Always call jobController.jobError(evt) to ensure all error events are processed,
    // even if the event does not have a valid job ID. This allows for generic error handling
    // or logging of unexpected errors.
    jobController.jobError(evt, expectedSessionId);
  }

  bool postOverrideFileConfirm(
      Map<String, dynamic> event, SessionID expectedSessionId) {
    if (!_isCurrentSession(expectedSessionId)) return false;
    final confirmation = FileOverrideConfirmation.tryParse(event);
    if (confirmation == null) return false;
    return evtLoop.pushEvent(_FileDialogEvent(WeakReference(this),
        expectedSessionId, FileDialogType.overwrite, confirmation));
  }

  Future<void> overrideFileConfirm(FileOverrideConfirmation confirmation,
      {required SessionID expectedSessionId,
      bool? overrideConfirm,
      bool skip = false}) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    final id = confirmation.jobId;
    if (jobController.getJob(id) == -1) {
      throw StateError('File confirmation has no matching job');
    }
    // If `skip == true`, it means to skip this file without showing dialog.
    // Because `resp` may be null after the user operation or the last remembered operation,
    // and we should distinguish them.
    final resp = overrideConfirm ??
        (!skip
            ? await showFileConfirmDialog(translate("Overwrite"),
                confirmation.readPath, true, confirmation.isIdentical)
            : null);
    if (!_isCurrentSession(expectedSessionId)) return;
    if (false == resp) {
      final canceled = await jobController.cancelJob(id,
          expectedSessionId: expectedSessionId);
      if (!canceled) return;
      if (!_isCurrentSession(expectedSessionId)) return;
      final currentJobIndex = jobController.getJob(id);
      if (currentJobIndex == -1) return;
      final job = jobController.jobTable[currentJobIndex];
      job.state = JobState.done;
      jobController.jobTable.refresh();
    } else {
      var need_override = false;
      if (resp == null) {
        // skip
        need_override = false;
      } else {
        // overwrite
        need_override = true;
      }
      // Update the loop config.
      if (fileConfirmCheckboxRemember) {
        evtLoop.setSkip(!need_override);
      }
      await bind.sessionSetConfirmOverrideFile(
          sessionId: expectedSessionId,
          actId: id,
          fileNum: confirmation.fileNum,
          needOverride: need_override,
          remember: fileConfirmCheckboxRemember,
          isUpload: confirmation.isUpload);
      if (!_isCurrentSession(expectedSessionId)) return;
    }
    // Update the loop config.
    if (fileConfirmCheckboxRemember) {
      evtLoop.setOverrideConfirm(resp);
    }
  }

  bool fileConfirmCheckboxRemember = false;

  Future<bool?> showFileConfirmDialog(
      String title, String content, bool showCheckbox, bool isIdentical) async {
    fileConfirmCheckboxRemember = false;
    return await parent.target?.dialogManager.show<bool?>(
        (setState, Function(bool? v) close, context) {
      cancel() => close(false);
      submit() => close(true);
      return CustomAlertDialog(
        title: Row(
          children: [
            const Icon(Icons.warning_rounded, color: Colors.red),
            Text(title).paddingOnly(
              left: 10,
            ),
          ],
        ),
        contentBoxConstraints:
            BoxConstraints(minHeight: 100, minWidth: 400, maxWidth: 400),
        content: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(translate("This file exists, skip or overwrite this file?"),
                  style: const TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 5),
              Text(content),
              Offstage(
                offstage: !isIdentical,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(height: 12),
                    Text(translate("identical_file_tip"),
                        style: const TextStyle(fontWeight: FontWeight.w500))
                  ],
                ),
              ),
              showCheckbox
                  ? CheckboxListTile(
                      contentPadding: const EdgeInsets.all(0),
                      dense: true,
                      controlAffinity: ListTileControlAffinity.leading,
                      title: Text(
                        translate("Do this for all conflicts"),
                      ),
                      value: fileConfirmCheckboxRemember,
                      onChanged: (v) {
                        if (v == null) return;
                        setState(() => fileConfirmCheckboxRemember = v);
                      },
                    )
                  : const SizedBox.shrink()
            ]),
        actions: [
          dialogButton(
            "Cancel",
            icon: Icon(Icons.close_rounded),
            onPressed: cancel,
            isOutline: true,
          ),
          dialogButton(
            "Skip",
            icon: Icon(Icons.navigate_next_rounded),
            onPressed: () => close(null),
            isOutline: true,
          ),
          dialogButton(
            "OK",
            icon: Icon(Icons.done_rounded),
            onPressed: submit,
          ),
        ],
        onSubmit: submit,
        onCancel: cancel,
      );
    }, useAnimation: false);
  }

  Future<void> onSelectedFiles(
      dynamic obj, SessionID expectedSessionId) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    localController.selectedItems.clear();
    int? jobID;
    try {
      int handleIndex = int.parse(obj['handleIndex']);
      final file = jsonDecode(obj['file']);
      var entry = Entry.fromJson(file);
      entry.path = entry.name;
      final otherSideData = remoteController.directoryData();
      final toPath = otherSideData.directory.path;
      final isWindows = otherSideData.options.isWindows;
      final showHidden = otherSideData.options.showHidden;
      jobID = jobController.addTransferJob(entry, false, expectedSessionId);
      if (jobID == null) return;
      await webSendLocalFiles(
        handleIndex: handleIndex,
        actId: jobID,
        path: entry.path,
        to: PathUtil.join(toPath, entry.name, isWindows),
        fileNum: 0,
        includeHidden: showHidden,
        isRemote: false,
      );
      if (!_isCurrentSession(expectedSessionId)) return;
    } catch (error) {
      if (!_isCurrentSession(expectedSessionId)) return;
      if (jobID != null) {
        jobController.updateJobStatus(expectedSessionId, jobID,
            error: error.toString(), state: JobState.error);
      }
      debugPrint("Failed to send selected web files: $error");
    }
  }

  Future<void> sendEmptyDirs(
      dynamic obj, SessionID expectedSessionId) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    late final List<dynamic> emptyDirs;
    try {
      emptyDirs = jsonDecode(obj['dirs'] as String);
    } catch (e) {
      debugPrint("Failed to decode sendEmptyDirs: $e");
      return;
    }
    final otherSideData = remoteController.directoryData();
    final toPath = otherSideData.directory.path;
    final isPeerWindows = otherSideData.options.isWindows;

    final isLocalWindows = isWindows || isWebOnWindows;
    for (var dir in emptyDirs) {
      if (!_isCurrentSession(expectedSessionId)) return;
      if (isLocalWindows != isPeerWindows) {
        dir = PathUtil.convert(dir, isLocalWindows, isPeerWindows);
      }
      var peerPath = PathUtil.join(toPath, dir, isPeerWindows);
      await remoteController.createDirWithRemote(peerPath, true,
          expectedSessionId: expectedSessionId);
    }
  }
}

class DirectoryData {
  final DirectoryOptions options;
  final FileDirectory directory;
  DirectoryData(this.directory, this.options);
}

@immutable
class _FileOperationEntry {
  const _FileOperationEntry({
    required this.entryType,
    required this.name,
    required this.path,
    required this.size,
  });

  factory _FileOperationEntry.fromEntry(Entry entry) => _FileOperationEntry(
      entryType: entry.entryType,
      name: entry.name,
      path: entry.path,
      size: entry.size);

  final int entryType;
  final String name;
  final String path;
  final int size;

  bool get isFile => entryType > 3;
  bool get isDirectory => entryType < 3;

  Entry toEntry() => Entry()
    ..entryType = entryType
    ..name = name
    ..path = path
    ..size = size;
}

class _RemoveConfirmationState {
  bool remember = false;
}

class FileController {
  final bool isLocal;
  final GetSessionID getSessionID;
  SessionID get sessionId => getSessionID();
  final GetDialogManager getDialogManager;
  final IsCurrentSession isCurrentSession;
  final GetPeerPlatform getPeerPlatform;
  final GetPeerVersion getPeerVersion;
  final FileControllerRequests _requests;

  final FileFetcher fileFetcher;

  final options = DirectoryOptions().obs;
  final directory = FileDirectory().obs;

  final history = RxList<String>.empty(growable: true);
  final sortBy = SortBy.name.obs;
  var sortAscending = true;
  final JobController jobController;

  final DirectoryData Function() getOtherSideDirectoryData;
  late final SelectedItems selectedItems = SelectedItems(isLocal: isLocal);

  FileController(
      {required this.isLocal,
      required this.getSessionID,
      required this.getDialogManager,
      required this.isCurrentSession,
      required this.getPeerPlatform,
      required this.getPeerVersion,
      required this.jobController,
      required this.fileFetcher,
      required this.getOtherSideDirectoryData,
      FileControllerRequests? requests})
      : _requests = requests ?? FileControllerRequests.native;

  void resetForSession() {
    directory.value.clear();
    options.value.clear();
    history.clear();
    selectedItems.clear();
  }

  String get homePath => options.value.home;
  void set homePath(String path) => options.value.home = path;
  OverlayDialogManager? get dialogManager => getDialogManager();

  String get shortPath {
    final dirPath = directory.value.path;
    if (dirPath.startsWith(homePath)) {
      var path = dirPath.replaceFirst(homePath, "");
      if (path.isEmpty) return "";
      if (path[0] == "/" || path[0] == "\\") {
        // remove more '/' or '\'
        path = path.replaceFirst(path[0], "");
      }
      return path;
    } else {
      return dirPath.replaceFirst(homePath, "");
    }
  }

  DirectoryData directoryData() {
    return DirectoryData(directory.value, options.value);
  }

  bool _isCurrentSession(SessionID expectedSessionId) =>
      isCurrentSession(expectedSessionId);

  Future<void> onReady(SessionID expectedSessionId) async {
    if (!_isCurrentSession(expectedSessionId)) return;
    if (isLocal) {
      final home = await bind.mainGetHomeDir();
      if (!_isCurrentSession(expectedSessionId)) return;
      options.value.home = home;
    }
    final showHidden = (await bind.sessionGetPeerOption(
      sessionId: expectedSessionId,
      name: isLocal ? "local_show_hidden" : "remote_show_hidden",
    ))
        .isNotEmpty;
    if (!_isCurrentSession(expectedSessionId)) return;
    options.value.showHidden = showHidden;
    options.value.isWindows = isLocal
        ? isWindows
        : getPeerPlatform() == kPeerPlatformWindows;

    await Future.delayed(Duration(milliseconds: 100));
    if (!_isCurrentSession(expectedSessionId)) return;

    final savedDir = (await bind.sessionGetPeerOption(
        sessionId: expectedSessionId,
        name: isLocal ? "local_dir" : "remote_dir"));
    if (!_isCurrentSession(expectedSessionId)) return;
    Future<bool> tryOpenReadyDirs() async {
      final dirs = <String>{
        if (directory.value.path.isNotEmpty) directory.value.path,
        if (savedDir.isNotEmpty) savedDir,
        options.value.home,
      };
      for (final dir in dirs) {
        if (await _openDirectoryPath(dir,
            isBack: true, expectedSessionId: expectedSessionId)) {
          return true;
        }
        if (!_isCurrentSession(expectedSessionId)) return false;
      }
      return false;
    }

    var opened = await tryOpenReadyDirs();
    if (!_isCurrentSession(expectedSessionId)) return;

    await Future.delayed(Duration(seconds: 1));
    if (!_isCurrentSession(expectedSessionId)) return;

    if (!opened) {
      // The peer may become ready during the reconnect delay, so retry the
      // same candidates instead of only retrying the default home directory.
      await tryOpenReadyDirs();
    }
  }

  Future<void> close(SessionID expectedSessionId) async {
    if (sessionId != expectedSessionId) return;
    // save config
    Map<String, String> msgMap = {};
    msgMap[isLocal ? "local_dir" : "remote_dir"] = directory.value.path;
    msgMap[isLocal ? "local_show_hidden" : "remote_show_hidden"] =
        options.value.showHidden ? "Y" : "";
    for (final msg in msgMap.entries) {
      await bind.sessionPeerOption(
          sessionId: expectedSessionId, name: msg.key, value: msg.value);
      if (sessionId != expectedSessionId) return;
    }
    directory.value.clear();
    options.value.clear();
  }

  void toggleShowHidden(
      {bool? showHidden, SessionID? expectedSessionId}) {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    options.value.showHidden = showHidden ?? !options.value.showHidden;
    unawaited(refresh(expectedSessionId: selectedSessionId));
  }

  void changeSortStyle(SortBy sort,
      {bool? isLocal,
      bool ascending = true,
      SessionID? expectedSessionId}) {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    sortBy.value = sort;
    sortAscending = ascending;
    directory.update((dir) {
      dir?.changeSortStyle(sort, ascending: ascending);
    });
  }

  Future<bool> refresh({SessionID? expectedSessionId}) async {
    // "." can be both a refresh command and a real remote directory path.
    // Refresh must bypass openDirectory's command dispatch to avoid recursion.
    return await _openDirectoryPath(directory.value.path,
        isBack: true, expectedSessionId: expectedSessionId);
  }

  Future<bool> openDirectory(String path,
      {bool isBack = false, SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return false;
    if (!isBack && path == ".") {
      return await refresh(expectedSessionId: selectedSessionId);
    }
    if (!isBack && path == "..") {
      return await _goToParentDirectory(
          isBack: isBack, expectedSessionId: selectedSessionId);
    }
    return await _openDirectoryPath(path,
        isBack: isBack, expectedSessionId: selectedSessionId);
  }

  Future<List<Entry>?> listWindowsDrives(
      {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return null;
    final showHidden = options.value.showHidden;
    try {
      final fd = await fileFetcher.fetchDirectory(
          '/', isLocal, showHidden,
          expectedSessionId: selectedSessionId);
      if (!_isCurrentSession(selectedSessionId)) return null;
      return fd.entries
          .map((entry) => Entry()
            ..entryType = entry.entryType
            ..modifiedTime = entry.modifiedTime
            ..name = entry.name
            ..path = entry.path
            ..size = entry.size)
          .toList(growable: false);
    } catch (error) {
      if (_isCurrentSession(selectedSessionId)) {
        debugPrint('listWindowsDrives failed: $error');
      }
      return null;
    }
  }

  Future<bool> _openDirectoryPath(String path,
      {bool isBack = false, SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return false;
    if (!isBack) {
      pushHistory();
    }
    final showHidden = options.value.showHidden;
    final isWindows = options.value.isWindows;
    // process /C:\ -> C:\ on Windows
    if (isWindows && path.length > 1 && path[0] == '/') {
      path = path.substring(1);
      if (path[path.length - 1] != '\\') {
        path = "$path\\";
      }
    }
    try {
      final fd = await fileFetcher.fetchDirectory(path, isLocal, showHidden,
          expectedSessionId: selectedSessionId);
      if (!_isCurrentSession(selectedSessionId)) return false;
      fd.format(isWindows, sort: sortBy.value);
      directory.value = fd;
      return true;
    } catch (e) {
      debugPrint("Failed to openDirectory $path: $e");
      return false;
    }
  }

  void pushHistory() {
    if (history.isNotEmpty && history.last == directory.value.path) {
      return;
    }
    history.add(directory.value.path);
  }

  void goToHomeDirectory({SessionID? expectedSessionId}) {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    if (isLocal) {
      unawaited(openDirectory(homePath,
          expectedSessionId: selectedSessionId));
      return;
    }
    homePath = "";
    unawaited(openDirectory(homePath,
        expectedSessionId: selectedSessionId));
  }

  void goBack({SessionID? expectedSessionId}) {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    if (history.isEmpty) return;
    final path = history.removeAt(history.length - 1);
    if (path.isEmpty) return;
    if (directory.value.path == path) {
      goBack(expectedSessionId: selectedSessionId);
      return;
    }
    unawaited(_openDirectoryPath(path,
            isBack: true, expectedSessionId: selectedSessionId)
        .then<void>((_) {}));
  }

  void goToParentDirectory({SessionID? expectedSessionId}) {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    unawaited(_goToParentDirectory(expectedSessionId: selectedSessionId)
        .then<void>((_) {}));
  }

  Future<bool> _goToParentDirectory(
      {bool isBack = false, SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return false;
    final isWindows = options.value.isWindows;
    final dirPath = directory.value.path;
    var parent = PathUtil.dirname(dirPath, isWindows);
    // specially for C:\, D:\, goto '/'
    if (parent == dirPath && isWindows) {
      return await _openDirectoryPath('/',
          isBack: isBack, expectedSessionId: selectedSessionId);
    }
    return await _openDirectoryPath(parent,
        isBack: isBack, expectedSessionId: selectedSessionId);
  }

  // TODO deprecated this
  void initDirAndHome(Map<String, dynamic> evt) {
    try {
      final fd = FileDirectory.fromJson(jsonDecode(evt['value']));
      fd.format(options.value.isWindows, sort: sortBy.value);
      if (fd.id > 0) {
        final jobIndex = jobController.getJob(fd.id);
        if (jobIndex != -1) {
          final job = jobController.jobTable[jobIndex];
          var totalSize = 0;
          var fileCount = fd.entries.length;
          for (var element in fd.entries) {
            totalSize += element.size;
          }
          job.totalSize = totalSize;
          job.fileCount = fileCount;
          debugPrint("update receive details: ${fd.path}");
          jobController.jobTable.refresh();
        }
      } else if (options.value.home.isEmpty) {
        options.value.home = fd.path;
        debugPrint("init remote home: ${fd.path}");
        directory.value = fd;
      }
    } catch (e) {
      debugPrint("initDirAndHome err=$e");
    }
  }

  /// sendFiles from current side (FileController.isLocal) to other side (SelectedItems).
  Future<void> sendFiles(
      SelectedItems items, DirectoryData otherSideData,
      {SessionID? expectedSessionId}) async {
    if (items.isLocal != isLocal) {
      return;
    }
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    final entries = items.items
        .map(_FileOperationEntry.fromEntry)
        .toList(growable: false);
    final isRemoteToLocal = !isLocal;
    final toPath = otherSideData.directory.path;
    final isPeerWindows = otherSideData.options.isWindows;
    final showHidden = otherSideData.options.showHidden;
    final sourceRootPath = directory.value.path;
    final isSourceWindows = options.value.isWindows;
    final peerVersion = getPeerVersion();

    for (final from in entries) {
      if (!_isCurrentSession(selectedSessionId)) return;
      final jobID = jobController.addTransferJob(
          from.toEntry(), isRemoteToLocal, selectedSessionId);
      if (jobID == null) return;
      final destination =
          PathUtil.join(toPath, from.name, isPeerWindows);
      try {
        await _requests.sendFiles(selectedSessionId, jobID, from.path,
            destination, 0, showHidden, isRemoteToLocal, from.isDirectory);
      } catch (error) {
        if (!_isCurrentSession(selectedSessionId)) return;
        jobController.updateJobStatus(selectedSessionId, jobID,
            error: error.toString(), state: JobState.error);
        rethrow;
      }
      if (!_isCurrentSession(selectedSessionId)) return;
      debugPrint('path: ${from.path}, to: $destination');
    }

    if (isWeb ||
        (!isLocal && versionCmp(peerVersion, '1.3.3') < 0)) {
      return;
    }
    final createRemotely = isLocal;
    for (final item in entries) {
      if (!_isCurrentSession(selectedSessionId)) return;
      if (!item.isDirectory) {
        continue;
      }
      final emptyDirs = await fileFetcher.readEmptyDirs(
          item.path, isLocal, showHidden,
          expectedSessionId: selectedSessionId);
      if (!_isCurrentSession(selectedSessionId)) return;
      if (emptyDirs.isEmpty) {
        continue;
      }
      for (final emptyDir in emptyDirs) {
        final target = PathUtil.getOtherSidePath(sourceRootPath,
            emptyDir.path, isSourceWindows, toPath, isPeerWindows);
        final created = await createDirWithRemote(target, createRemotely,
            expectedSessionId: selectedSessionId);
        if (!created) return;
      }
    }
  }

  Future<void> removeAction(SelectedItems items,
      {SessionID? expectedSessionId}) async {
    if (items.isLocal != isLocal) {
      debugPrint("Failed to removeFile, wrong files");
      return;
    }
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    final selectedEntries = items.items
        .map(_FileOperationEntry.fromEntry)
        .toList(growable: false);
    final isWindows = options.value.isWindows;
    final manager = dialogManager;
    final confirmationState = _RemoveConfirmationState();
    for (final item in selectedEntries) {
      if (!_isCurrentSession(selectedSessionId)) return;
      final jobID = jobController.allocateJobId(selectedSessionId);
      if (jobID == null) return;
      var title = "";
      var content = "";
      late final List<_FileOperationEntry> entries;
      if (item.isFile) {
        title = translate("Are you sure you want to delete this file?");
        content = item.name;
        entries = [item];
      } else if (item.isDirectory) {
        title = translate("Not an empty directory");
        manager?.showLoading(translate("Waiting"));
        final FileDirectory fd;
        try {
          fd = await fileFetcher.fetchDirectoryRecursiveToRemove(
              jobID, item.path, items.isLocal, true,
              expectedSessionId: selectedSessionId);
        } catch (error) {
          if (!_isCurrentSession(selectedSessionId)) return;
          manager?.dismissAll();
          if (manager != null) {
            msgBox(selectedSessionId, 'custom-error-nook-nocancel-hasclose',
                translate("Error"), error.toString(), '', manager);
          } else {
            debugPrint("removeAction error msgbox failed: $error");
          }
          continue;
        }
        if (!_isCurrentSession(selectedSessionId)) return;
        if (fd.path.isEmpty) {
          fd.path = item.path;
        }
        fd.format(isWindows);
        manager?.dismissAll();
        if (fd.entries.isEmpty) {
          final deleteJobId = jobController.addDeleteDirJob(
              item.toEntry(), !isLocal, 0, selectedSessionId);
          if (deleteJobId == null) return;
          final confirm = await _showRemoveDialog(
              translate(
                  "Are you sure you want to delete this empty directory?"),
              item.name,
              false,
              selectedSessionId,
              manager,
              confirmationState);
          if (!_isCurrentSession(selectedSessionId)) return;
          if (confirm == true) {
            await _sendRemoveEmptyDir(
                selectedSessionId, item.path, deleteJobId);
          } else {
            jobController.updateJobStatus(selectedSessionId, deleteJobId,
                error: "cancel", state: JobState.done);
          }
          continue;
        }
        entries = fd.entries
            .map(_FileOperationEntry.fromEntry)
            .toList(growable: false);
      } else {
        entries = [];
      }
      int deleteJobId;
      if (item.isDirectory) {
        final id = jobController.addDeleteDirJob(
            item.toEntry(), !isLocal, entries.length, selectedSessionId);
        if (id == null) return;
        deleteJobId = id;
      } else {
        final id = jobController.addDeleteFileJob(
            item.toEntry(), !isLocal, selectedSessionId);
        if (id == null) return;
        deleteJobId = id;
      }

      for (var i = 0; i < entries.length; i++) {
        if (!_isCurrentSession(selectedSessionId)) return;
        final dirShow = item.isDirectory
            ? "${translate("Are you sure you want to delete the file of this directory?")}\n"
            : "";
        final count = entries.length > 1 ? "${i + 1}/${entries.length}" : "";
        content = "$dirShow\n\n${entries[i].path}".trim();
        final confirm = await _showRemoveDialog(
          count.isEmpty ? title : "$title ($count)",
          content,
          item.isDirectory,
          selectedSessionId,
          manager,
          confirmationState,
        );
        if (!_isCurrentSession(selectedSessionId)) return;
        try {
          if (confirm == true) {
            final res = await _removeFileAndWait(selectedSessionId,
                entries[i].path, i, deleteJobId);
            if (!_isCurrentSession(selectedSessionId)) return;
            if (item.isDirectory &&
                res['file_num'] == (entries.length - 1).toString()) {
              await _sendRemoveEmptyDir(
                  selectedSessionId, item.path, deleteJobId);
            }
          } else {
            jobController.updateJobStatus(selectedSessionId, deleteJobId,
                file_num: i, error: "cancel");
          }
          if (confirmationState.remember) {
            if (confirm == true) {
              for (var j = i + 1; j < entries.length; j++) {
                final res = await _removeFileAndWait(selectedSessionId,
                    entries[j].path, j, deleteJobId);
                if (!_isCurrentSession(selectedSessionId)) return;
                if (item.isDirectory &&
                    res['file_num'] == (entries.length - 1).toString()) {
                  await _sendRemoveEmptyDir(
                      selectedSessionId, item.path, deleteJobId);
                }
              }
            } else {
              jobController.updateJobStatus(selectedSessionId, deleteJobId,
                  error: "cancel",
                  file_num: entries.length,
                  state: JobState.done);
            }
            break;
          }
        } catch (error) {
          if (!_isCurrentSession(selectedSessionId)) return;
          jobController.updateJobStatus(selectedSessionId, deleteJobId,
              file_num: i,
              error: error.toString(),
              state: JobState.error);
          rethrow;
        }
      }
    }
    if (_isCurrentSession(selectedSessionId)) {
      await refresh(expectedSessionId: selectedSessionId);
    }
  }

  Future<bool?> _showRemoveDialog(
      String title,
      String content,
      bool showCheckbox,
      SessionID expectedSessionId,
      OverlayDialogManager? manager,
      _RemoveConfirmationState confirmationState) async {
    if (!_isCurrentSession(expectedSessionId) || manager == null) return null;
    final result = await manager.show<bool>(
        (setState, Function(bool v) close, context) {
      cancel() => close(false);
      submit() => close(true);
      return CustomAlertDialog(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.warning_rounded, color: Colors.red),
            Expanded(
              child: Text(title).paddingOnly(
                left: 10,
              ),
            ),
          ],
        ),
        contentBoxConstraints:
            BoxConstraints(minHeight: 100, minWidth: 400, maxWidth: 400),
        content: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(content),
            Text(
              translate("This is irreversible!"),
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                color: Colors.red,
              ),
            ).paddingOnly(top: 20),
            showCheckbox
                ? CheckboxListTile(
                    contentPadding: const EdgeInsets.all(0),
                    dense: true,
                    controlAffinity: ListTileControlAffinity.leading,
                    title: Text(
                      translate("Do this for all conflicts"),
                    ),
                    value: confirmationState.remember,
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => confirmationState.remember = v);
                    },
                  )
                : const SizedBox.shrink()
          ],
        ),
        actions: [
          dialogButton(
            "Cancel",
            icon: Icon(Icons.close_rounded),
            onPressed: cancel,
            isOutline: true,
          ),
          dialogButton(
            "OK",
            icon: Icon(Icons.done_rounded),
            onPressed: submit,
          ),
        ],
        onSubmit: submit,
        onCancel: cancel,
      );
    }, useAnimation: false);
    if (!_isCurrentSession(expectedSessionId)) return null;
    return result;
  }

  Future<Map<String, dynamic>> _removeFileAndWait(SessionID expectedSessionId,
      String path, int fileNum, int actionId) {
    return jobController.dispatchAndWaitForResult(
        expectedSessionId: expectedSessionId,
        actionId: actionId,
        fileNum: fileNum,
        dispatch: () => _requests.removeFile(
            expectedSessionId, actionId, path, !isLocal, fileNum));
  }

  Future<bool> _sendRemoveEmptyDir(SessionID expectedSessionId, String path,
      int actionId) async {
    if (!_isCurrentSession(expectedSessionId)) return false;
    history.removeWhere((element) => element.contains(path));
    await _requests.removeEmptyDirectories(
        expectedSessionId, actionId, path, !isLocal);
    return _isCurrentSession(expectedSessionId);
  }

  Future<bool> createDirWithRemote(String path, bool isRemote,
      {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return false;
    final actionId = jobController.allocateJobId(selectedSessionId);
    if (actionId == null) return false;
    await _requests.createDirectory(
        selectedSessionId, actionId, path, isRemote);
    return _isCurrentSession(selectedSessionId);
  }

  Future<bool> createDir(String path, {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    return await createDirWithRemote(path, !isLocal,
        expectedSessionId: selectedSessionId);
  }

  Future<void> renameAction(Entry item, bool isLocal,
      {SessionID? expectedSessionId}) async {
    if (isLocal != this.isLocal) return;
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!_isCurrentSession(selectedSessionId)) return;
    final ownedItem = _FileOperationEntry.fromEntry(item);
    final manager = dialogManager;
    if (manager == null) return;
    final textEditingController = TextEditingController(text: ownedItem.name);
    String? errorText;
    try {
      await manager.show((setState, close, context) {
        textEditingController.addListener(() {
          if (errorText != null && _isCurrentSession(selectedSessionId)) {
            setState(() {
              errorText = null;
            });
          }
        });
        submit() async {
          if (!_isCurrentSession(selectedSessionId)) return;
          final newName = textEditingController.text;
          if (newName.isEmpty || newName == ownedItem.name) {
            close();
            return;
          }
          if (directory.value.entries.any((e) => e.name == newName)) {
            setState(() {
              errorText = translate("Already exists");
            });
            return;
          }
          final targetIsWindows = options.value.isWindows;
          if (!PathUtil.validName(newName, targetIsWindows)) {
            setState(() {
              if (ownedItem.isDirectory) {
                errorText = translate("Invalid folder name");
              } else {
                errorText = translate("Invalid file name");
              }
            });
            return;
          }
          final actionId = jobController.allocateJobId(selectedSessionId);
          if (actionId == null) return;
          try {
            await _requests.renameFile(selectedSessionId, actionId,
                ownedItem.path, newName, !isLocal);
          } catch (error) {
            if (!_isCurrentSession(selectedSessionId)) return;
            setState(() {
              errorText = error.toString();
            });
            return;
          }
          if (!_isCurrentSession(selectedSessionId)) return;
          close();
        }

        return CustomAlertDialog(
          content: Column(
            children: [
              DialogTextField(
                title: '${translate('Rename')} ${ownedItem.name}',
                controller: textEditingController,
                errorText: errorText,
              ),
            ],
          ),
          actions: [
            dialogButton(
              "Cancel",
              icon: Icon(Icons.close_rounded),
              onPressed: close,
              isOutline: true,
            ),
            dialogButton(
              "OK",
              icon: Icon(Icons.done_rounded),
              onPressed: submit,
            ),
          ],
          onSubmit: submit,
          onCancel: close,
        );
      });
    } finally {
      textEditingController.dispose();
    }
  }
}

const _kOneWayFileTransferError = 'one-way-file-transfer-tip';
const _kMaxNativeFileJobInt = 0x7fffffff;

class JobController {
  static final JobID jobID = JobID();
  final jobTable = List<JobProgress>.empty(growable: true).obs;
  final JobResultListener jobResultListener;
  final GetSessionID getSessionID;
  final GetDialogManager getDialogManager;
  final IsCurrentSession isCurrentSession;
  final JobControllerRequests _requests;
  final int Function() _nextJobId;
  SessionID get sessionId => getSessionID();
  OverlayDialogManager? get alogManager => getDialogManager();
  int _lastTimeShowMsgbox = DateTime.now().millisecondsSinceEpoch;

  JobController(this.getSessionID, this.getDialogManager,
      {required this.isCurrentSession,
      JobControllerRequests? requests,
      int Function()? nextJobId,
      Duration resultTimeout = const Duration(seconds: 5)})
      : _requests = requests ?? JobControllerRequests.native,
        _nextJobId = nextJobId ?? JobController.jobID.next,
        jobResultListener = JobResultListener(requestTimeout: resultTimeout);

  int? allocateJobId(SessionID expectedSessionId) {
    if (!isCurrentSession(expectedSessionId)) return null;
    final id = _nextJobId();
    if (id <= 0 || id > _kMaxNativeFileJobInt) {
      throw StateError('Invalid file-job action ID');
    }
    return id;
  }

  int getJob(int id) {
    return jobTable.indexWhere((element) => element.id == id);
  }

  // return jobID
  int? addTransferJob(
      Entry from, bool isRemoteToLocal, SessionID expectedSessionId) {
    final jobID = allocateJobId(expectedSessionId);
    if (jobID == null) return null;
    jobTable.add(JobProgress()
      ..type = JobType.transfer
      ..fileName = path.basename(from.path)
      ..jobName = from.path
      ..totalSize = from.size
      ..state = JobState.inProgress
      ..id = jobID
      ..isRemoteToLocal = isRemoteToLocal);
    return jobID;
  }

  int? addDeleteFileJob(
      Entry file, bool isRemote, SessionID expectedSessionId) {
    final jobID = allocateJobId(expectedSessionId);
    if (jobID == null) return null;
    jobTable.add(JobProgress()
      ..type = JobType.deleteFile
      ..fileName = path.basename(file.path)
      ..jobName = file.path
      ..totalSize = file.size
      ..state = JobState.none
      ..id = jobID
      ..isRemoteToLocal = isRemote);
    return jobID;
  }

  int? addDeleteDirJob(Entry file, bool isRemote, int fileCount,
      SessionID expectedSessionId) {
    final jobID = allocateJobId(expectedSessionId);
    if (jobID == null) return null;
    jobTable.add(JobProgress()
      ..type = JobType.deleteDir
      ..fileName = path.basename(file.path)
      ..jobName = file.path
      ..fileCount = fileCount
      ..totalSize = file.size
      ..state = JobState.none
      ..id = jobID
      ..isRemoteToLocal = isRemote);
    return jobID;
  }

  static int? _eventInt(Object? value, {bool positive = false}) {
    if (value is! String) return null;
    final parsed = int.tryParse(value);
    if (parsed == null || value != parsed.toString()) return null;
    if (positive ? parsed <= 0 : parsed < 0) return null;
    if (parsed > _kMaxNativeFileJobInt) return null;
    return parsed;
  }

  void tryUpdateJobProgress(
      Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!isCurrentSession(expectedSessionId)) return;
    try {
      final id = _eventInt(evt['id'], positive: true);
      final fileNum = _eventInt(evt['file_num']);
      if (id == null || fileNum == null) return;
      final jobIndex = getJob(id);
      if (jobIndex >= 0 && jobTable.length > jobIndex) {
        final job = jobTable[jobIndex];
        job.fileNum = fileNum;
        job.speed = double.parse(evt['speed']);
        job.finishedSize = int.parse(evt['finished_size']);
        job.recvJobRes = true;
        jobTable.refresh();
      }
    } catch (e) {
      debugPrint("Failed to tryUpdateJobProgress, evt: ${evt.toString()}");
    }
  }

  Future<bool> jobDone(
      Map<String, dynamic> evt, SessionID expectedSessionId) async {
    if (!isCurrentSession(expectedSessionId)) return false;
    final id = _eventInt(evt['id'], positive: true);
    final eventFileNum = _eventInt(evt['file_num']);
    if (id == null || eventFileNum == null) return false;
    jobResultListener.tryComplete(expectedSessionId, evt);
    int? fileNum = eventFileNum;
    double? speed = 0;
    final jobIndex = getJob(id);
    if (jobIndex == -1) return false;
    final job = jobTable[jobIndex];
    job.recvJobRes = true;
    if (job.type == JobType.deleteFile) {
      job.state = JobState.done;
    } else if (job.type == JobType.deleteDir) {
      if (fileNum != null) {
        if (fileNum < job.fileNum) return true; // file_num can be 0 at last
        job.fileNum = fileNum;
        if (fileNum >= job.fileCount - 1) {
          job.state = JobState.done;
        }
      }
    } else {
      try {
        speed = double.tryParse(evt['speed']);
      } catch (_) {}
      if (fileNum != null) job.fileNum = fileNum;
      if (speed != null) job.speed = speed;
      job.state = JobState.done;
    }
    jobTable.refresh();
    if (job.type == JobType.deleteDir) {
      return job.state == JobState.done;
    } else {
      return true;
    }
  }

  void jobError(Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!isCurrentSession(expectedSessionId)) return;
    final id = _eventInt(evt['id'], positive: true);
    final errValue = evt['err'];
    if (id == null || errValue is! String) return;
    final err = errValue;
    jobResultListener.tryCompleteError(expectedSessionId, evt);
    final jobIndex = getJob(id);
    if (jobIndex != -1) {
      final job = jobTable[jobIndex];
      job.state = JobState.error;
      job.err = err;
      job.recvJobRes = true;
      if (job.type == JobType.transfer) {
        int? fileNum = int.tryParse(evt['file_num']);
        if (fileNum != null) job.fileNum = fileNum;
        if (err == "skipped") {
          job.state = JobState.done;
          job.finishedSize = job.totalSize;
        }
      } else if (job.type == JobType.deleteDir) {
        final fileNum = _eventInt(evt['file_num']);
        if (fileNum != null) job.fileNum = fileNum;
      }
      jobTable.refresh();
    }
    if (err == _kOneWayFileTransferError) {
      if (DateTime.now().millisecondsSinceEpoch - _lastTimeShowMsgbox > 3000) {
        final dm = alogManager;
        if (dm != null) {
          _lastTimeShowMsgbox = DateTime.now().millisecondsSinceEpoch;
          msgBox(expectedSessionId, 'custom-nocancel', 'Error', err, '', dm);
        }
      }
    }
    debugPrint("jobError $evt");
  }

  void updateJobStatus(SessionID expectedSessionId, int id,
      {int? file_num, String? error, JobState? state}) {
    if (!isCurrentSession(expectedSessionId)) return;
    final jobIndex = getJob(id);
    if (jobIndex < 0) return;
    final job = jobTable[jobIndex];
    job.recvJobRes = true;
    if (file_num != null) {
      job.fileNum = file_num;
    }
    if (error != null) {
      job.err = error;
      job.state = JobState.error;
    }
    if (state != null) {
      job.state = state;
    }
    if (job.type == JobType.deleteFile && error == null) {
      job.state = JobState.done;
    }
    jobTable.refresh();
  }

  Future<bool> cancelJob(int id, {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!isCurrentSession(selectedSessionId)) return false;
    await _requests.cancelJob(selectedSessionId, id);
    return isCurrentSession(selectedSessionId);
  }

  Future<Map<String, dynamic>> dispatchAndWaitForResult(
      {required SessionID expectedSessionId,
      required int actionId,
      required int fileNum,
      required Future<void> Function() dispatch}) {
    if (!isCurrentSession(expectedSessionId)) {
      return Future.error(StateError('Superseded file-transfer session'));
    }
    return jobResultListener.dispatchAndWait(
        expectedSessionId: expectedSessionId,
        actionId: actionId,
        fileNum: fileNum,
        dispatch: dispatch);
  }

  Future<void> loadLastJob(
      Map<String, dynamic> evt, SessionID expectedSessionId) async {
    if (!isCurrentSession(expectedSessionId)) return;
    debugPrint("load last job: $evt");
    final encoded = evt['value'];
    if (encoded is! String) return;
    final Object? decoded;
    try {
      decoded = json.decode(encoded);
    } catch (_) {
      return;
    }
    if (decoded is! Map<String, dynamic>) return;
    final jobDetail = decoded;
    final remoteValue = jobDetail['remote'];
    final toValue = jobDetail['to'];
    final showHiddenValue = jobDetail['show_hidden'];
    final fileNumValue = jobDetail['file_num'];
    final isRemoteValue = jobDetail['is_remote'];
    if (remoteValue is! String ||
        toValue is! String ||
        showHiddenValue is! bool ||
        fileNumValue is! int ||
        fileNumValue < 0 ||
        fileNumValue > _kMaxNativeFileJobInt ||
        isRemoteValue is! bool) return;
    final remote = remoteValue;
    final to = toValue;
    final showHidden = showHiddenValue;
    final fileNum = fileNumValue;
    final isRemote = isRemoteValue;
    bool isAutoStart = jobDetail['auto_start'] == true;
    int currJobId = -1;
    if (isAutoStart) {
      // Ensure jobDetail['id'] exists and is an int
      final id = jobDetail['id'];
      if (id is int && id > 0 && id <= _kMaxNativeFileJobInt) {
        currJobId = id;
      }
    }
    if (currJobId < 0) {
      // If id is missing or invalid, disable auto-start and assign a new job id
      isAutoStart = false;
      final allocated = allocateJobId(expectedSessionId);
      if (allocated == null) return;
      currJobId = allocated;
    }

    if (!isAutoStart) {
      if (!(isDesktop || isWebDesktop)) {
        // Don't add to job table if not auto start on mobile.
        // Because mobile does not support job list view now.
        return;
      }

      // Add to job table if not auto start on desktop.
      String fileName = path.basename(isRemote ? remote : to);
      final jobProgress = JobProgress()
        ..type = JobType.transfer
        ..fileName = fileName
        ..jobName = isRemote ? remote : to
        ..id = currJobId
        ..isRemoteToLocal = isRemote
        ..fileNum = fileNum
        ..remote = remote
        ..to = to
        ..showHidden = showHidden
        ..state = JobState.paused;
      jobTable.add(jobProgress);
    }

    await _requests.addJob(expectedSessionId, isRemote, showHidden,
        currJobId, isRemote ? remote : to, isRemote ? to : remote, fileNum);
    if (!isCurrentSession(expectedSessionId)) return;

    if (isAutoStart) {
      await _requests.resumeJob(expectedSessionId, currJobId, isRemote);
    }
  }

  Future<bool> resumeJob(int jobId, {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (!isCurrentSession(selectedSessionId)) return false;
    final jobIndex = getJob(jobId);
    if (jobIndex != -1) {
      final job = jobTable[jobIndex];
      final actionId = job.id;
      final isRemote = job.isRemoteToLocal;
      await _requests.resumeJob(selectedSessionId, actionId, isRemote);
      if (!isCurrentSession(selectedSessionId)) return false;
      final currentIndex = getJob(actionId);
      if (currentIndex == -1) return false;
      jobTable[currentIndex].state = JobState.inProgress;
      jobTable.refresh();
      return true;
    } else {
      debugPrint("jobId $jobId is not exists");
      return false;
    }
  }

  void updateFolderFiles(
      Map<String, dynamic> evt, SessionID expectedSessionId) {
    if (!isCurrentSession(expectedSessionId)) return;
    // ret: "{\"id\":1,\"num_entries\":12,\"total_size\":1264822.0}"
    Map<String, dynamic> info = json.decode(evt['info']);
    int id = info['id'];
    int num_entries = info['num_entries'];
    double total_size = info['total_size'];
    final jobIndex = getJob(id);
    if (jobIndex != -1) {
      final job = jobTable[jobIndex];
      job.fileCount = num_entries;
      job.totalSize = total_size.toInt();
      jobTable.refresh();
    }
    debugPrint("update folder files: $info");
  }

  void clear() {
    jobTable.clear();
    jobResultListener.clear();
  }

  bool clearForSession(SessionID expectedSessionId) {
    if (!isCurrentSession(expectedSessionId)) return false;
    clear();
    return true;
  }

  bool removeJob(SessionID expectedSessionId, int id) {
    if (!isCurrentSession(expectedSessionId)) return false;
    final index = getJob(id);
    if (index == -1) return false;
    jobTable.removeAt(index);
    return true;
  }
}

class JobResultListener {
  JobResultListener(
      {this.maxPending = 64,
      this.requestTimeout = const Duration(seconds: 5)}) {
    if (maxPending < 1) {
      throw ArgumentError.value(maxPending, 'maxPending');
    }
    if (requestTimeout.inMicroseconds < 1) {
      throw ArgumentError.value(requestTimeout, 'requestTimeout');
    }
  }

  final int maxPending;
  final Duration requestTimeout;
  final Map<_JobResultKey, _PendingJobResult> _pending = {};

  Future<Map<String, dynamic>> dispatchAndWait(
      {required SessionID expectedSessionId,
      required int actionId,
      required int fileNum,
      required Future<void> Function() dispatch}) {
    if (actionId <= 0 ||
        actionId > _kMaxNativeFileJobInt ||
        fileNum < 0 ||
        fileNum > _kMaxNativeFileJobInt) {
      return Future.error(ArgumentError('Invalid file-job result owner'));
    }
    final key = _JobResultKey(expectedSessionId, actionId, fileNum);
    if (_pending.containsKey(key)) {
      return Future.error(StateError('File-job result is already pending'));
    }
    if (_pending.length >= maxPending) {
      return Future.error(StateError('File-job result capacity exhausted'));
    }
    final pending = _PendingJobResult();
    _pending[key] = pending;
    pending.startTimeout(requestTimeout, () {
      if (!identical(_pending[key], pending)) return;
      // Keep an exact bounded tombstone. A late response must be consumed by
      // this owner instead of completing a same-key retry. The same deadline
      // also covers a bridge dispatch that never settles after an early event.
      pending.completeError(TimeoutException(
          'File-job transaction did not settle', requestTimeout));
    });

    late final Future<void> dispatchResult;
    try {
      dispatchResult = dispatch();
    } catch (error, stackTrace) {
      _pending.remove(key);
      pending.completeError(error, stackTrace);
      return pending.future;
    }
    unawaited(dispatchResult.then<void>((_) {
      pending.markDispatchSettled();
      if (pending.responseReceived && identical(_pending[key], pending)) {
        _pending.remove(key);
      }
    }, onError: (Object error, StackTrace stackTrace) {
      if (identical(_pending[key], pending)) {
        _pending.remove(key);
        pending.completeError(error, stackTrace);
      }
    }));
    return pending.future;
  }

  bool tryComplete(
      SessionID expectedSessionId, Map<String, dynamic> event) {
    final actionId = JobController._eventInt(event['id'], positive: true);
    final fileNum = JobController._eventInt(event['file_num']);
    if (actionId == null || fileNum == null) return false;
    final key = _JobResultKey(expectedSessionId, actionId, fileNum);
    final pending = _pending[key];
    if (pending == null) return false;
    if (pending.isCompleted) {
      _retainLateResponseUntilDispatchSettles(key, pending);
      return false;
    }
    if (pending.responseReceived) return false;
    pending.complete(Map<String, dynamic>.unmodifiable(event));
    if (pending.dispatchSettled) {
      _pending.remove(key);
    }
    return true;
  }

  bool tryCompleteError(
      SessionID expectedSessionId, Map<String, dynamic> event) {
    final actionId = JobController._eventInt(event['id'], positive: true);
    final fileNum = JobController._eventInt(event['file_num']);
    final error = event['err'];
    if (actionId == null || fileNum == null || error is! String) return false;
    final key = _JobResultKey(expectedSessionId, actionId, fileNum);
    final pending = _pending[key];
    if (pending == null) return false;
    if (pending.isCompleted) {
      _retainLateResponseUntilDispatchSettles(key, pending);
      return false;
    }
    if (pending.responseReceived) return false;
    pending.completeResponseError(StateError(error));
    if (pending.dispatchSettled) {
      _pending.remove(key);
    }
    return true;
  }

  void _retainLateResponseUntilDispatchSettles(
      _JobResultKey key, _PendingJobResult pending) {
    if (!pending.markLateResponseReceived()) return;
    if (pending.dispatchSettled && identical(_pending[key], pending)) {
      _pending.remove(key);
    }
  }

  void clear() {
    final pending = _pending.values.toList(growable: false);
    _pending.clear();
    final error = StateError('Superseded file-transfer session');
    for (final result in pending) {
      result.completeError(error);
    }
  }
}

@immutable
class _JobResultKey {
  const _JobResultKey(this.sessionId, this.actionId, this.fileNum);

  final SessionID sessionId;
  final int actionId;
  final int fileNum;

  @override
  bool operator ==(Object other) =>
      other is _JobResultKey &&
      other.sessionId == sessionId &&
      other.actionId == actionId &&
      other.fileNum == fileNum;

  @override
  int get hashCode => Object.hash(sessionId, actionId, fileNum);
}

class _PendingJobResult {
  final Completer<Map<String, dynamic>> _done =
      Completer<Map<String, dynamic>>();
  Timer? _timer;
  bool _dispatchSettled = false;
  bool _responseReceived = false;
  Map<String, dynamic>? _responseValue;
  Object? _responseError;

  Future<Map<String, dynamic>> get future => _done.future;
  bool get dispatchSettled => _dispatchSettled;
  bool get isCompleted => _done.isCompleted;
  bool get responseReceived => _responseReceived;

  void startTimeout(Duration timeout, void Function() onTimeout) {
    _timer = Timer(timeout, onTimeout);
  }

  void complete(Map<String, dynamic> value) {
    if (_done.isCompleted) return;
    _responseReceived = true;
    _responseValue = value;
    _completeResponseIfDispatchSettled();
  }

  void completeError(Object error, [StackTrace? stackTrace]) {
    if (_done.isCompleted) return;
    _timer?.cancel();
    _timer = null;
    _done.completeError(error, stackTrace);
  }

  void completeResponseError(Object error) {
    if (_done.isCompleted) return;
    _responseReceived = true;
    _responseError = error;
    _completeResponseIfDispatchSettled();
  }

  void markDispatchSettled() {
    _dispatchSettled = true;
    _completeResponseIfDispatchSettled();
  }

  bool markLateResponseReceived() {
    if (!_done.isCompleted || _responseReceived) return false;
    _responseReceived = true;
    return true;
  }

  void _completeResponseIfDispatchSettled() {
    if (!_dispatchSettled || !_responseReceived || _done.isCompleted) return;
    _timer?.cancel();
    _timer = null;
    final error = _responseError;
    if (error != null) {
      _done.completeError(error);
      return;
    }
    final value = _responseValue;
    if (value == null) {
      _done.completeError(StateError('File-job result payload is missing'));
      return;
    }
    _done.complete(value);
  }
}

class FileFetcher {
  final Map<String, _PendingFileRequest<FileDirectory>> _remoteTasks = {};
  final Map<String, _PendingFileRequest<List<FileDirectory>>>
      _remoteEmptyDirsTasks = {};
  final Map<int, _PendingFileRequest<FileDirectory>> _readRecursiveTasks = {};

  final GetSessionID getSessionID;
  final FileFetcherRequests _requests;
  final int maxPending;
  final Duration requestTimeout;
  SessionID get sessionId => getSessionID();

  FileFetcher(this.getSessionID,
      {FileFetcherRequests? requests,
      this.maxPending = 64,
      this.requestTimeout = const Duration(seconds: 2)})
      : _requests = requests ?? FileFetcherRequests.native {
    if (maxPending < 1) {
      throw ArgumentError.value(maxPending, 'maxPending');
    }
    if (requestTimeout.inMicroseconds < 1) {
      throw ArgumentError.value(requestTimeout, 'requestTimeout');
    }
  }

  int get _pendingCount =>
      _remoteTasks.length +
      _remoteEmptyDirsTasks.length +
      _readRecursiveTasks.length;

  void cancelPending() {
    final directoryTasks = _remoteTasks.values.toList(growable: false);
    final emptyDirectoryTasks =
        _remoteEmptyDirsTasks.values.toList(growable: false);
    final recursiveTasks =
        _readRecursiveTasks.values.toList(growable: false);
    _remoteTasks.clear();
    _remoteEmptyDirsTasks.clear();
    _readRecursiveTasks.clear();
    final error = StateError('Superseded file-transfer session');
    for (final task in directoryTasks) {
      task.completeError(error);
    }
    for (final task in emptyDirectoryTasks) {
      task.completeError(error);
    }
    for (final task in recursiveTasks) {
      task.completeError(error);
    }
  }

  _PendingFileRequest<T> _reserve<K, T>(
      Map<K, _PendingFileRequest<T>> tasks,
      K key,
      SessionID expectedSessionId,
      bool isLocal,
      String operation) {
    if (tasks.containsKey(key)) {
      throw StateError('$operation is already pending');
    }
    if (_pendingCount >= maxPending) {
      throw StateError('File request capacity exhausted');
    }
    final pending = _PendingFileRequest<T>(expectedSessionId, isLocal);
    tasks[key] = pending;
    pending.startTimeout(requestTimeout, () {
      if (!identical(tasks[key], pending)) return;
      // The wire response has no per-request nonce. Keep this exact owner as a
      // bounded tombstone so a late response cannot complete a same-key retry.
      pending.completeError(TimeoutException(
          '$operation did not receive a response', requestTimeout));
    });
    return pending;
  }

  Future<T> _dispatchAndWait<K, T>(
      Map<K, _PendingFileRequest<T>> tasks,
      K key,
      _PendingFileRequest<T> pending,
      Future<void> Function() dispatch) {
    late final Future<void> dispatchResult;
    try {
      dispatchResult = dispatch();
    } catch (error, stackTrace) {
      if (identical(tasks[key], pending)) {
        tasks.remove(key);
      }
      pending.completeError(error, stackTrace);
      return pending.future;
    }

    unawaited(dispatchResult.then<void>((_) {
      pending.markDispatchSettled();
      if (pending.responseReceived && identical(tasks[key], pending)) {
        tasks.remove(key);
      }
    }, onError: (Object error, StackTrace stackTrace) {
      if (identical(tasks[key], pending)) {
        tasks.remove(key);
        pending.completeError(error, stackTrace);
      }
    }));
    return pending.future;
  }

  bool _complete<K, T>(
      Map<K, _PendingFileRequest<T>> tasks,
      K key,
      SessionID expectedSessionId,
      bool isLocal,
      T value) {
    final pending = tasks[key];
    if (pending == null ||
        pending.expectedSessionId != expectedSessionId ||
        pending.isLocal != isLocal) {
      return false;
    }
    if (pending.responseReceived) return false;
    if (pending.isCompleted) {
      // Consume the late response owned by a timed-out tombstone. It must not
      // escape to a same-key request admitted afterward.
      tasks.remove(key);
      return false;
    }
    pending.complete(value);
    if (pending.dispatchSettled) {
      tasks.remove(key);
    }
    return true;
  }

  static bool? _parseIsLocal(Object? value) {
    if (value == 'true') return true;
    if (value == 'false') return false;
    return null;
  }

  bool tryCompleteEmptyDirsTask(SessionID expectedSessionId, Object? msg,
      Object? isLocalValue) {
    final isLocal = _parseIsLocal(isLocalValue);
    if (msg is! String || isLocal == null) return false;
    try {
      final map = jsonDecode(msg);
      final String path = map["path"];
      final List<dynamic> fdJsons = map["empty_dirs"];
      final List<FileDirectory> fds =
          fdJsons.map((fdJson) => FileDirectory.fromJson(fdJson)).toList();
      return _complete(_remoteEmptyDirsTasks, path, expectedSessionId,
          isLocal, fds);
    } catch (e) {
      debugPrint("tryCompleteJob err: $e");
      return false;
    }
  }

  bool tryCompleteTask(SessionID expectedSessionId, Object? msg,
      Object? isLocalValue) {
    final isLocal = _parseIsLocal(isLocalValue);
    if (msg is! String || isLocal == null) return false;
    try {
      final fd = FileDirectory.fromJson(jsonDecode(msg));
      if (fd.id > 0) {
        return _complete(_readRecursiveTasks, fd.id, expectedSessionId,
            isLocal, fd);
      } else if (fd.id == 0 && fd.path.isNotEmpty) {
        return _complete(
            _remoteTasks, fd.path, expectedSessionId, isLocal, fd);
      }
    } catch (e) {
      debugPrint("tryCompleteJob err: $e");
    }
    return false;
  }

  // Complete a pending recursive read task with an error.
  // See FileModel.handleJobError() for why this is necessary.
  bool tryCompleteRecursiveTaskWithError(
      SessionID expectedSessionId, int id, String error) {
    final pending = _readRecursiveTasks[id];
    if (pending == null ||
        pending.expectedSessionId != expectedSessionId) {
      return false;
    }
    if (pending.responseReceived) return false;
    if (pending.isCompleted) {
      _readRecursiveTasks.remove(id);
      return false;
    }
    pending.completeResponseError(StateError(error));
    if (pending.dispatchSettled) {
      _readRecursiveTasks.remove(id);
    }
    return true;
  }

  Future<List<FileDirectory>> readEmptyDirs(
      String path, bool isLocal, bool showHidden,
      {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (isLocal) {
      final res = await bind.sessionReadLocalEmptyDirsRecursiveSync(
          sessionId: selectedSessionId,
          path: path,
          includeHidden: showHidden);

      final List<dynamic> fdJsons = jsonDecode(res);

      return fdJsons
          .map((fdJson) => FileDirectory.fromJson(fdJson))
          .toList();
    }
    final pending = _reserve(_remoteEmptyDirsTasks, path, selectedSessionId,
        false, 'Remote empty-directory request');
    return _dispatchAndWait(_remoteEmptyDirsTasks, path, pending,
        () => _requests.readEmptyDirectories(
            selectedSessionId, path, showHidden));
  }

  Future<FileDirectory> fetchDirectory(
      String path, bool isLocal, bool showHidden,
      {SessionID? expectedSessionId}) async {
    final selectedSessionId = expectedSessionId ?? sessionId;
    if (isLocal) {
      final res = await bind.sessionReadLocalDirSync(
          sessionId: selectedSessionId, path: path, showHidden: showHidden);
      return FileDirectory.fromJson(jsonDecode(res));
    }
    final pending = _reserve(_remoteTasks, path, selectedSessionId, false,
        'Remote directory request');
    return _dispatchAndWait(_remoteTasks, path, pending,
        () => _requests.readDirectory(selectedSessionId, path, showHidden));
  }

  Future<FileDirectory> fetchDirectoryRecursiveToRemove(
      int actID, String path, bool isLocal, bool showHidden,
      {SessionID? expectedSessionId}) async {
    // TODO test Recursive is show hidden default?
    final selectedSessionId = expectedSessionId ?? sessionId;
    final pending = _reserve(_readRecursiveTasks, actID, selectedSessionId,
        isLocal, 'Recursive directory request');
    return _dispatchAndWait(
        _readRecursiveTasks,
        actID,
        pending,
        () => _requests.readDirectoryTree(
            selectedSessionId, actID, path, !isLocal, showHidden));
  }
}

class _PendingFileRequest<T> {
  _PendingFileRequest(this.expectedSessionId, this.isLocal);

  final SessionID expectedSessionId;
  final bool isLocal;
  final Completer<T> _done = Completer<T>();
  Timer? _timer;
  bool _dispatchSettled = false;
  bool _responseReceived = false;

  Future<T> get future => _done.future;
  bool get dispatchSettled => _dispatchSettled;
  bool get isCompleted => _done.isCompleted;
  bool get responseReceived => _responseReceived;

  void startTimeout(Duration timeout, void Function() onTimeout) {
    if (_timer != null || _done.isCompleted) {
      throw StateError('File request timeout already started');
    }
    _timer = Timer(timeout, onTimeout);
  }

  void complete(T value) {
    if (_done.isCompleted) return;
    _responseReceived = true;
    _timer?.cancel();
    _timer = null;
    _done.complete(value);
  }

  void completeError(Object error, [StackTrace? stackTrace]) {
    if (_done.isCompleted) return;
    _timer?.cancel();
    _timer = null;
    _done.completeError(error, stackTrace);
  }

  void completeResponseError(Object error) {
    if (_done.isCompleted) return;
    _responseReceived = true;
    _timer?.cancel();
    _timer = null;
    _done.completeError(error);
  }

  void markDispatchSettled() {
    _dispatchSettled = true;
  }
}

class FileDirectory {
  List<Entry> entries = [];
  int id = 0;
  String path = "";

  FileDirectory();

  FileDirectory.fromJson(Map<String, dynamic> json) {
    id = json['id'];
    path = json['path'];
    json['entries'].forEach((v) {
      entries.add(Entry.fromJson(v));
    });
  }

  // generate full path for every entry , init sort style if need.
  format(bool isWindows, {SortBy? sort}) {
    for (var entry in entries) {
      entry.path = PathUtil.join(path, entry.name, isWindows);
    }
    if (sort != null) {
      changeSortStyle(sort);
    }
  }

  changeSortStyle(SortBy sort, {bool ascending = true}) {
    entries = _sortList(entries, sort, ascending);
  }

  clear() {
    entries = [];
    id = 0;
    path = "";
  }
}

class Entry {
  int entryType = 4;
  int modifiedTime = 0;
  String name = "";
  String path = "";
  int size = 0;

  Entry();

  Entry.fromJson(Map<String, dynamic> json) {
    entryType = json['entry_type'];
    modifiedTime = json['modified_time'];
    name = json['name'];
    size = json['size'];
  }

  bool get isFile => entryType > 3;

  bool get isDirectory => entryType < 3;

  bool get isDrive => entryType == 3;

  DateTime lastModified() {
    return DateTime.fromMillisecondsSinceEpoch(modifiedTime * 1000);
  }
}

enum JobState { none, inProgress, done, error, paused }

extension JobStateDisplay on JobState {
  String display() {
    switch (this) {
      case JobState.none:
        return translate("Waiting");
      case JobState.inProgress:
        return translate("Transfer file");
      case JobState.done:
        return translate("Finished");
      case JobState.error:
        return translate("Error");
      default:
        return "";
    }
  }
}

enum JobType { none, transfer, deleteFile, deleteDir }

class JobProgress {
  JobType type = JobType.none;
  JobState state = JobState.none;
  var recvJobRes = false;
  var id = 0;
  var fileNum = 0;
  var speed = 0.0;
  var finishedSize = 0;
  var totalSize = 0;
  var fileCount = 0;
  // [isRemote == true] means [remote -> local]
  // var isRemote = false;
  // to-do use enum
  var isRemoteToLocal = false;
  var jobName = "";
  var fileName = "";
  var remote = "";
  var to = "";
  var showHidden = false;
  var err = "";
  int lastTransferredSize = 0;

  double get percent =>
      totalSize > 0 ? (finishedSize.toDouble() / totalSize) : 0.0;
  String get percentText => '${(percent * 100).toStringAsFixed(0)}%';

  clear() {
    type = JobType.none;
    state = JobState.none;
    recvJobRes = false;
    id = 0;
    fileNum = 0;
    speed = 0;
    finishedSize = 0;
    jobName = "";
    fileName = "";
    fileCount = 0;
    remote = "";
    to = "";
    err = "";
  }

  String display() {
    if (type == JobType.transfer) {
      if (state == JobState.done && err == "skipped") {
        return translate("Skipped");
      }
    } else if (type == JobType.deleteFile) {
      if (err == "cancel") {
        return translate("Cancel");
      }
    }

    return state.display();
  }

  String getStatus() {
    int handledFileCount = recvJobRes ? fileNum + 1 : fileNum;
    if (handledFileCount >= fileCount) {
      handledFileCount = fileCount;
    }
    if (state == JobState.done) {
      handledFileCount = fileCount;
      finishedSize = totalSize;
    }
    final filesStr = "$handledFileCount/$fileCount files";
    final sizeStr = totalSize > 0 ? readableFileSize(totalSize.toDouble()) : "";
    final sizePercentStr = totalSize > 0 && finishedSize > 0
        ? "${readableFileSize(finishedSize.toDouble())} / ${readableFileSize(totalSize.toDouble())}"
        : "";
    if (type == JobType.deleteFile) {
      return display();
    } else if (type == JobType.deleteDir) {
      var res = '';
      if (state == JobState.done || state == JobState.error) {
        res = display();
      }
      if (filesStr.isNotEmpty) {
        if (res.isNotEmpty) {
          res += " ";
        }
        res += filesStr;
      }

      if (sizeStr.isNotEmpty) {
        if (res.isNotEmpty) {
          res += ", ";
        }
        res += sizeStr;
      }
      return res;
    } else if (type == JobType.transfer) {
      var res = "";
      if (state != JobState.inProgress && state != JobState.none) {
        res += display();
      }
      if (filesStr.isNotEmpty) {
        if (res.isNotEmpty) {
          res += ", ";
        }
        res += filesStr;
      }
      if (sizeStr.isNotEmpty && state != JobState.inProgress) {
        if (res.isNotEmpty) {
          res += ", ";
        }
        res += sizeStr;
      }
      if (sizePercentStr.isNotEmpty && state == JobState.inProgress) {
        if (res.isNotEmpty) {
          res += ", ";
        }
        res += sizePercentStr;
      }
      return res;
    }
    return '';
  }
}

class _PathStat {
  final String path;
  final DateTime dateTime;

  _PathStat(this.path, this.dateTime);
}

class PathUtil {
  static final windowsContext = path.Context(style: path.Style.windows);
  static final posixContext = path.Context(style: path.Style.posix);

  static String getOtherSidePath(String mainRootPath, String mainPath,
      bool isMainWindows, String otherRootPath, bool isOtherWindows) {
    final mainPathUtil = isMainWindows ? windowsContext : posixContext;
    final relativePath = mainPathUtil.relative(mainPath, from: mainRootPath);

    final names = mainPathUtil.split(relativePath);

    final otherPathUtil = isOtherWindows ? windowsContext : posixContext;

    String path = otherRootPath;

    for (var name in names) {
      path = otherPathUtil.join(path, name);
    }

    return path;
  }

  static String join(String path1, String path2, bool isWindows) {
    final pathUtil = isWindows ? windowsContext : posixContext;
    return pathUtil.join(path1, path2);
  }

  static List<String> split(String path, bool isWindows) {
    final pathUtil = isWindows ? windowsContext : posixContext;
    return pathUtil.split(path);
  }

  static String convert(String path, bool isMainWindows, bool isOtherWindows) {
    final mainPathUtil = isMainWindows ? windowsContext : posixContext;
    final otherPathUtil = isOtherWindows ? windowsContext : posixContext;
    return otherPathUtil.joinAll(mainPathUtil.split(path));
  }

  static String dirname(String path, bool isWindows) {
    final pathUtil = isWindows ? windowsContext : posixContext;
    return pathUtil.dirname(path);
  }

  static bool validName(String name, bool isWindows) {
    final unixFileNamePattern = RegExp(r'^[^/\0]+$');
    final windowsFileNamePattern = RegExp(r'^[^<>:"/\\|?*]+$');
    final reg = isWindows ? windowsFileNamePattern : unixFileNamePattern;
    return reg.hasMatch(name);
  }
}

class DirectoryOptions {
  String home;
  bool showHidden;
  bool isWindows;

  DirectoryOptions(
      {this.home = "", this.showHidden = false, this.isWindows = false});

  clear() {
    home = "";
    showHidden = false;
    isWindows = false;
  }
}

class SelectedItems {
  final bool isLocal;
  final items = RxList<Entry>.empty(growable: true);

  SelectedItems({required this.isLocal});

  void add(Entry e) {
    if (e.isDrive) return;
    if (!items.contains(e)) {
      items.add(e);
    }
  }

  void remove(Entry e) {
    items.remove(e);
  }

  void clear() {
    items.clear();
  }

  void selectAll(List<Entry> entries) {
    items.clear();
    items.addAll(entries);
  }

  static bool valid(RxList<Entry> items) {
    if (items.isNotEmpty) {
      // exclude DirDrive type
      return items.any((item) => !item.isDrive);
    }
    return false;
  }
}

// edited from [https://github.com/DevsOnFlutter/file_manager/blob/c1bf7f0225b15bcb86eba602c60acd5c4da90dd8/lib/file_manager.dart#L22]
List<Entry> _sortList(List<Entry> list, SortBy sortType, bool ascending) {
  if (sortType == SortBy.name) {
    // making list of only folders.
    final dirs = list
        .where((element) => element.isDirectory || element.isDrive)
        .toList();
    // sorting folder list by name.
    dirs.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    // making list of only flies.
    final files = list.where((element) => element.isFile).toList();
    // sorting files list by name.
    files.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    // first folders will go to list (if available) then files will go to list.
    return ascending
        ? [...dirs, ...files]
        : [...dirs.reversed.toList(), ...files.reversed.toList()];
  } else if (sortType == SortBy.modified) {
    // making the list of Path & DateTime
    List<_PathStat> pathStat = [];
    for (Entry e in list) {
      pathStat.add(_PathStat(e.name, e.lastModified()));
    }

    // sort _pathStat according to date
    pathStat.sort((b, a) => a.dateTime.compareTo(b.dateTime));

    // sorting [list] according to [_pathStat]
    list.sort((a, b) => pathStat
        .indexWhere((element) => element.path == a.name)
        .compareTo(pathStat.indexWhere((element) => element.path == b.name)));
    return ascending ? list : list.reversed.toList();
  } else if (sortType == SortBy.type) {
    // making list of only folders.
    final dirs = list.where((element) => element.isDirectory).toList();

    // sorting folders by name.
    dirs.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    // making the list of files
    final files = list.where((element) => element.isFile).toList();

    // sorting files list by extension.
    files.sort((a, b) => a.name
        .toLowerCase()
        .split('.')
        .last
        .compareTo(b.name.toLowerCase().split('.').last));
    return ascending
        ? [...dirs, ...files]
        : [...dirs.reversed.toList(), ...files.reversed.toList()];
  } else if (sortType == SortBy.size) {
    // create list of path and size
    Map<String, int> sizeMap = {};
    for (Entry e in list) {
      sizeMap[e.name] = e.size;
    }

    // making list of only folders.
    final dirs = list.where((element) => element.isDirectory).toList();
    // sorting folder list by name.
    dirs.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    // making list of only flies.
    final files = list.where((element) => element.isFile).toList();

    // creating sorted list of [_sizeMapList] by size.
    final List<MapEntry<String, int>> sizeMapList = sizeMap.entries.toList();
    sizeMapList.sort((b, a) => a.value.compareTo(b.value));

    // sort [list] according to [_sizeMapList]
    files.sort((a, b) => sizeMapList
        .indexWhere((element) => element.key == a.name)
        .compareTo(sizeMapList.indexWhere((element) => element.key == b.name)));
    return ascending
        ? [...dirs, ...files]
        : [...dirs.reversed.toList(), ...files.reversed.toList()];
  }
  return [];
}

/// Define a general queue which can accepts different dialog type.
///
/// [Visibility]
/// The `_FileDialogType` and `_DialogEvent` are invisible for other models.
enum FileDialogType { overwrite }

class _FileDialogEvent
    extends BaseEvent<FileDialogType, FileOverrideConfirmation> {
  final WeakReference<FileModel> fileModel;
  final SessionID expectedSessionId;
  bool? _overrideConfirm;
  bool _skip = false;

  _FileDialogEvent(
      this.fileModel, this.expectedSessionId, super.type, super.data);

  void setOverrideConfirm(bool? confirm) {
    _overrideConfirm = confirm;
  }

  void setSkip(bool skip) {
    _skip = skip;
  }

  @override
  EventCallback<FileOverrideConfirmation>? findCallback(FileDialogType type) {
    final model = fileModel.target;
    if (model == null || !model._isCurrentSession(expectedSessionId)) {
      return null;
    }
    switch (type) {
      case FileDialogType.overwrite:
        return (data) async {
          await model.overrideFileConfirm(data,
              expectedSessionId: expectedSessionId,
              overrideConfirm: _overrideConfirm,
              skip: _skip);
        };
    }
  }
}

class FileDialogEventLoop
    extends BaseEventLoop<FileDialogType, FileOverrideConfirmation> {
  static const int maxOwnedConfirmations = 64;

  FileDialogEventLoop() : super(maxOwnedEvents: maxOwnedConfirmations);

  bool? _overrideConfirm;
  bool _skip = false;

  @override
  void onEventsRetired() {
    _overrideConfirm = null;
    _skip = false;
  }

  @override
  Future<void> onPreConsume(
      BaseEvent<FileDialogType, FileOverrideConfirmation> evt) async {
    final event = evt as _FileDialogEvent;
    event.setOverrideConfirm(_overrideConfirm);
    event.setSkip(_skip);
    debugPrint(
        "FileDialogEventLoop: consuming<jobId: ${evt.data.jobId} overrideConfirm: $_overrideConfirm, skip: $_skip>");
  }

  @override
  Future<void> onEventsClear() {
    _overrideConfirm = null;
    _skip = false;
    return super.onEventsClear();
  }

  @override
  void onTerminalError(
      BaseEvent<FileDialogType, FileOverrideConfirmation>? event,
      Object error,
      StackTrace stackTrace) {
    final fileEvent = event;
    if (fileEvent is _FileDialogEvent) {
      final ffi = fileEvent.fileModel.target?.parent.target;
      if (ffi != null) {
        ffi.reportFileDialogFailure(fileEvent.expectedSessionId);
        return;
      }
    }
    super.onTerminalError(event, error, stackTrace);
  }

  void setOverrideConfirm(bool? confirm) {
    _overrideConfirm = confirm;
  }

  void setSkip(bool skip) {
    _skip = skip;
  }
}
