import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:bot_toast/bot_toast.dart';

import '../common.dart';

final syncAbOption = 'sync-ab-with-recent-sessions';
bool shouldSyncAb() {
  return bind.mainGetLocalOption(key: syncAbOption) == 'Y';
}

final sortAbTagsOption = 'sync-ab-tags';
bool shouldSortTags() {
  return bind.mainGetLocalOption(key: sortAbTagsOption) == 'Y';
}

final filterAbTagOption = 'filter-ab-by-intersection';
bool filterAbTagByIntersection() {
  return bind.mainGetLocalOption(key: filterAbTagOption) == 'Y';
}

const _personalAddressBookName = "My address book";
const _legacyAddressBookName = "Legacy address book";

const kUntagged = "Untagged";

enum ForcePullAb {
  listAndCurrent,
  current,
}

class AbModel {
  final addressbooks = Map<String, BaseAb>.fromEntries([]).obs;
  final RxString _currentName = ''.obs;
  RxString get currentName => _currentName;
  final _dummyAb = DummyAb();
  BaseAb get current => addressbooks[_currentName.value] ?? _dummyAb;

  RxList<Peer> get currentAbPeers => current.peers;
  RxList<String> get currentAbTags => current.tags;
  RxList<String> get selectedTags => current.selectedTags;

  RxBool get currentAbLoading => current.abLoading;
  bool get currentAbEmpty => current.peers.isEmpty && current.tags.isEmpty;
  final _listPullError = ''.obs;
  RxString get abPullError =>
      _listPullError.value.isNotEmpty ? _listPullError : current.pullError;
  RxString get currentAbPushError => current.pushError;
  String? _personalAbGuid;
  RxBool legacyMode = false.obs;

  // Only handles peers add/remove
  final Map<String, VoidCallback> _peerIdUpdateListeners = {};

  final sortTags = shouldSortTags().obs;
  final filterByIntersection = filterAbTagByIntersection().obs;

  var _syncAllFromRecent = true;
  var _syncFromRecentLock = false;
  var _timerCounter = 0;
  var _cacheLoadOnceFlag = false;
  var _pulledOnce = false;
  var listInitialized = false;
  var _maxPeerOneAb = 0;

  late final Peers peersModel;

  WeakReference<FFI> parent;

  AbModel(this.parent) {
    addressbooks.clear();
    peersModel = Peers(
        name: PeersModelName.addressBook,
        getInitPeers: () => currentAbPeers,
        loadEvent: LoadEvent.addressBook);
    if (desktopType == DesktopType.main) {
      Timer.periodic(Duration(milliseconds: 500), (timer) async {
        if (_timerCounter++ % 6 == 0) {
          if (!gFFI.userModel.isLogin) return;
          if (!listInitialized) return;
          if (!current.initialized || !current.canWrite()) return;
          _syncFromRecent();
        }
      });
    }
  }

  reset() async {
    print("reset ab model");
    addressbooks.clear();
    _currentName.value = '';
    _listPullError.value = '';
    _pulledOnce = false;
    await bind.mainClearAb();
    listInitialized = false;
  }

  void clearPullErrors() {
    _listPullError.value = '';
    current.pullError.value = '';
  }

// #region ab
  /// Pulls the address book data from the server.
  ///
  /// If `force` is `ForcePullAb.listAndCurrent`, the function will pull the list of address books, current address book, and try initialize personal address book.
  /// If `force` is `ForcePullAb.current`, the function will only pull the current address book.
  /// If `quiet` is true, the function will not display any notifications or errors.
  var _pulling = false;
  Future<void> pullAb(
      {required ForcePullAb? force, required bool quiet}) async {
    if (bind.isDisableAb()) return;
    if (!gFFI.userModel.isLogin) return;
    if (gFFI.userModel.networkError.isNotEmpty) return;
    if (_pulling) return;
    if (force == null && _pulledOnce) {
      return;
    }
    _pulling = true;
    if (!quiet) {
      _listPullError.value = '';
      current.pullError.value = '';
    }
    try {
      await _pullAb(force: force, quiet: quiet);
      _refreshTab();
    } catch (_) {}
    _pulling = false;
    _pulledOnce = true;
  }

  Future<void> _pullAb(
      {required ForcePullAb? force, required bool quiet}) async {
    if (force == null && listInitialized && current.initialized) return;
    debugPrint("pullAb, force: $force, quiet: $quiet");
    if (!listInitialized || force == ForcePullAb.listAndCurrent) {
      try {
        // Read personal guid every time to avoid upgrading the server without closing the main window
        _personalAbGuid = null;
        // `true`: continue init. `false`: stop, error already recorded.
        if (!await _getPersonalAbGuid(quiet: quiet)) {
          return;
        }
        legacyMode.value = _personalAbGuid == null;
        if (!legacyMode.value && _maxPeerOneAb == 0) {
          await _getAbSettings(quiet: quiet);
        }
        if (_personalAbGuid != null) {
          debugPrint("pull ab list");
          List<AbProfile> abProfiles = List.empty(growable: true);
          abProfiles.add(AbProfile(_personalAbGuid!, _personalAddressBookName,
              gFFI.userModel.userName.value, null, ShareRule.read.value, null));
          // get all address book name
          await _getSharedAbProfiles(abProfiles, quiet: quiet);
          addressbooks.removeWhere((key, value) =>
              abProfiles.firstWhereOrNull((e) => e.name == key) == null);
          for (int i = 0; i < abProfiles.length; i++) {
            AbProfile p = abProfiles[i];
            if (addressbooks.containsKey(p.name)) {
              addressbooks[p.name]?.setSharedProfile(p);
            } else {
              addressbooks[p.name] = Ab(p, p.guid == _personalAbGuid);
            }
          }
        } else {
          // only legacy address book
          addressbooks
              .removeWhere((key, value) => key != _legacyAddressBookName);
          if (!addressbooks.containsKey(_legacyAddressBookName)) {
            addressbooks[_legacyAddressBookName] = LegacyAb();
          }
        }
        // set current address book name
        if (!listInitialized) {
          listInitialized = true;
          trySetCurrentToLast();
        }
        if (!addressbooks.containsKey(_currentName.value)) {
          setCurrentName(legacyMode.value
              ? _legacyAddressBookName
              : _personalAddressBookName);
        }
        // pull current address book
        await current.pullAb(quiet: quiet);
        // try initialize personal address book
        if (!current.isPersonal()) {
          final personalAb = addressbooks[_personalAddressBookName];
          if (personalAb != null && !personalAb.initialized) {
            await personalAb.pullAb(quiet: quiet);
          }
        }
      } catch (e) {
        debugPrint("pull ab list error: $e");
        _setListPullError(e, quiet: quiet);
      }
    } else if (listInitialized &&
        (!current.initialized || force == ForcePullAb.current)) {
      try {
        await current.pullAb(quiet: quiet);
      } catch (e) {
        debugPrint("pull current Ab error: $e");
      }
    }
    _callbackPeerUpdate();
    if (listInitialized && current.initialized) {
      _saveCache();
    }
  }

  void _setListPullError(Object err, {required bool quiet, int? statusCode}) {
    if (!quiet) {
      _listPullError.value =
          '${translate('pull_ab_failed_tip')}: ${translate(err.toString())}';
    }
    if (statusCode == 401) {
      gFFI.userModel.reset(resetOther: true);
    }
  }

  Future<bool> _getAbSettings({required bool quiet}) async {
    _maxPeerOneAb = 0;
    return true;
  }

  /// R-SV6/R-G4: account-synced address books are compiled out. Returning true
  /// keeps the model in local legacy mode without contacting an API server.
  Future<bool> _getPersonalAbGuid({required bool quiet}) async {
    _personalAbGuid = null;
    return true;
  }

  Future<bool> _getSharedAbProfiles(List<AbProfile> profiles,
      {required bool quiet}) async {
    return true;
  }

// #endregion

// #region rule
  List<String> addressBooksCanWrite() {
    List<String> list = [];
    addressbooks.forEach((key, value) async {
      if (value.canWrite()) {
        list.add(key);
      }
    });
    return list;
  }

// #endregion

// #region peer
  Future<String?> addIdToCurrent(String id, String alias, String password,
      List<dynamic> tags, String note) async {
    if (currentAbPeers.where((element) => element.id == id).isNotEmpty) {
      return "$id already exists in address book $_currentName";
    }
    Map<String, dynamic> peer = {
      'id': id,
      'alias': alias,
      'tags': tags,
    };
    // avoid set existing password to empty
    if (password.isNotEmpty) {
      peer['password'] = password;
    }
    if (note.isNotEmpty) {
      peer['note'] = note;
    }
    final ret = await addPeersTo([peer], _currentName.value);
    _syncAllFromRecent = true;
    return ret;
  }

  // Use Map<String, dynamic> rather than Peer to distinguish between empty and null
  Future<String?> addPeersTo(
    List<Map<String, dynamic>> ps,
    String name,
  ) async {
    final ab = addressbooks[name];
    if (ab == null) {
      return 'no such addressbook: $name';
    }
    for (var p in ps) {
      ab.removeNonExistentTags(p);
    }
    String? errMsg = await ab.addPeers(ps);
    await pullNonLegacyAfterChange(name: name);
    if (name == _currentName.value) {
      _refreshTab();
    }
    _syncAllFromRecent = true;
    _saveCache();
    return errMsg;
  }

  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    bool ret = await current.changeTagForPeers(ids, tags);
    await pullNonLegacyAfterChange();
    currentAbPeers.refresh();
    _saveCache();
    return ret;
  }

  Future<bool> changeAlias({required String id, required String alias}) async {
    bool res = await current.changeAlias(id: id, alias: alias);
    await pullNonLegacyAfterChange();
    currentAbPeers.refresh();
    _saveCache();
    return res;
  }

  Future<bool> changeNote({required String id, required String note}) async {
    bool res = await current.changeNote(id: id, note: note);
    await pullNonLegacyAfterChange();
    currentAbPeers.refresh();
    // no need to save cache
    return res;
  }

  Future<bool> changePersonalHashPassword(String id, String hash) async {
    var ret = false;
    final personalAb = addressbooks[_personalAddressBookName];
    if (personalAb != null) {
      ret = await personalAb.changePersonalHashPassword(id, hash);
      await personalAb.pullAb(quiet: true);
    } else {
      final legacyAb = addressbooks[_legacyAddressBookName];
      if (legacyAb != null) {
        ret = await legacyAb.changePersonalHashPassword(id, hash);
      }
    }
    _saveCache();
    return ret;
  }

  Future<bool> changeSharedPassword(
      String abName, String id, String password) async {
    final ab = addressbooks[abName];
    if (ab == null) return false;
    final ret = await ab.changeSharedPassword(id, password);
    await ab.pullAb(quiet: true);
    return ret;
  }

  Future<bool> deletePeers(List<String> ids) async {
    final ret = await current.deletePeers(ids);
    await pullNonLegacyAfterChange();
    currentAbPeers.refresh();
    _refreshTab();
    _saveCache();
    if (legacyMode.value && current.isPersonal()) {
      // non-legacy mode not add peers automatically
      Future.delayed(Duration(seconds: 2), () async {
        if (!shouldSyncAb()) return;
        var hasSynced = false;
        for (var id in ids) {
          if (await bind.mainPeerExists(id: id)) {
            hasSynced = true;
            break;
          }
        }
        if (hasSynced) {
          BotToast.showText(
              contentColor: Colors.lightBlue,
              text: translate('synced_peer_readded_tip'));
          _syncAllFromRecent = true;
        }
      });
    }
    _callbackPeerUpdate();
    return ret;
  }

// #endregion

// #region tags
  Future<bool> addTags(List<String> tagList) async {
    tagList.removeWhere((e) => e == kUntagged);
    final ret = await current.addTags(tagList, {});
    await pullNonLegacyAfterChange();
    _saveCache();
    return ret;
  }

  Future<bool> renameTag(String oldTag, String newTag) async {
    final ret = await current.renameTag(oldTag, newTag);
    await pullNonLegacyAfterChange();
    selectedTags.value = selectedTags.map((e) {
      if (e == oldTag) {
        return newTag;
      } else {
        return e;
      }
    }).toList();
    _saveCache();
    return ret;
  }

  Future<bool> setTagColor(String tag, Color color) async {
    final ret = await current.setTagColor(tag, color);
    await pullNonLegacyAfterChange();
    _saveCache();
    return ret;
  }

  Future<bool> deleteTag(String tag) async {
    final ret = await current.deleteTag(tag);
    await pullNonLegacyAfterChange();
    _saveCache();
    return ret;
  }

// #endregion

// #region sync from recent
  Future<void> _syncFromRecent({bool push = true}) async {
    if (!_syncFromRecentLock) {
      _syncFromRecentLock = true;
      await _syncFromRecentWithoutLock(push: push);
      _syncFromRecentLock = false;
    }
  }

  Future<void> _syncFromRecentWithoutLock({bool push = true}) async {
    Future<List<Peer>> getRecentPeers() async {
      try {
        List<String> filteredPeerIDs;
        if (_syncAllFromRecent) {
          _syncAllFromRecent = false;
          filteredPeerIDs = [];
        } else {
          final new_stored_str = await bind.mainGetNewStoredPeers();
          if (new_stored_str.isEmpty) return [];
          filteredPeerIDs = (jsonDecode(new_stored_str) as List<dynamic>)
              .map((e) => e.toString())
              .toList();
          if (filteredPeerIDs.isEmpty) return [];
        }
        final loadStr = await bind.mainLoadRecentPeersForAb(
            filter: jsonEncode(filteredPeerIDs));
        if (loadStr.isEmpty) {
          return [];
        }
        List<dynamic> mapPeers = jsonDecode(loadStr);
        List<Peer> recents = List.empty(growable: true);
        for (var m in mapPeers) {
          if (m is Map<String, dynamic>) {
            recents.add(Peer.fromJson(m));
          }
        }
        return recents;
      } catch (e) {
        debugPrint('getRecentPeers: $e');
      }
      return [];
    }

    try {
      if (!shouldSyncAb()) return;
      final recents = await getRecentPeers();
      if (recents.isEmpty) return;
      debugPrint("sync from recent, len: ${recents.length}");
      if (current.canWrite() && current.initialized) {
        await current.syncFromRecent(recents);
      }
    } catch (e) {
      debugPrint('_syncFromRecentWithoutLock: $e');
    }
  }

  void setShouldAsync(bool v) async {
    await bind.mainSetLocalOption(
        key: syncAbOption, value: v ? 'Y' : defaultOptionNo);
    _syncAllFromRecent = true;
    _timerCounter = 0;
  }

// #endregion

// #region cache
  _saveCache() {
    try {
      var ab_entries = _serializeCache();
      Map<String, dynamic> m = <String, dynamic>{
        "access_token": bind.mainGetLocalOption(key: 'access_token'),
        "ab_entries": ab_entries,
      };
      bind.mainSaveAb(json: jsonEncode(m));
    } catch (e) {
      debugPrint('ab save:$e');
    }
  }

  List<dynamic> _serializeCache() {
    var res = [];
    addressbooks.forEach((key, value) {
      if (!value.isPersonal() && key != current.name()) return;
      res.add({
        "guid": value.sharedProfile()?.guid ?? '',
        "name": key,
        "tags": value.tags,
        "peers": value.peers
            .map((e) => e.toCustomJson(includingHash: value.isPersonal()))
            .toList(),
        "tag_colors": jsonEncode(value.tagColors)
      });
    });
    return res;
  }

  trySetCurrentToLast() {
    final name = bind.getLocalFlutterOption(k: kOptionCurrentAbName);
    if (addressbooks.containsKey(name)) {
      _currentName.value = name;
    }
  }

  Future<void> loadCache() async {
    try {
      if (_cacheLoadOnceFlag || currentAbLoading.value) return;
      _cacheLoadOnceFlag = true;
      final access_token = bind.mainGetLocalOption(key: 'access_token');
      if (access_token.isEmpty) return;
      final cache = await bind.mainLoadAb();
      if (currentAbLoading.value) return;
      final data = jsonDecode(cache);
      if (data == null || data['access_token'] != access_token) return;
      _deserializeCache(data);
      legacyMode.value = addressbooks.containsKey(_legacyAddressBookName);
      trySetCurrentToLast();
    } catch (e) {
      debugPrint("load ab cache: $e");
    }
  }

  _deserializeCache(dynamic data) {
    if (data == null) return;
    reset();
    final abEntries = data['ab_entries'];
    if (abEntries is List) {
      for (var i = 0; i < abEntries.length; i++) {
        var abEntry = abEntries[i];
        if (abEntry is Map<String, dynamic>) {
          var guid = abEntry['guid'];
          var name = abEntry['name'];
          final BaseAb ab;
          if (name == _legacyAddressBookName) {
            ab = LegacyAb();
          } else {
            if (name == null || guid == null) {
              continue;
            }
            ab = Ab(AbProfile(guid, name, '', '', ShareRule.read.value, null),
                name == _personalAddressBookName);
          }
          addressbooks[name] = ab;
          if (abEntry['tags'] is List) {
            ab.tags.value =
                (abEntry['tags'] as List).map((e) => e.toString()).toList();
          }
          if (abEntry['peers'] is List) {
            for (var peer in abEntry['peers']) {
              ab.peers.add(Peer.fromJson(peer));
            }
          }
          if (abEntry['tag_colors'] is String) {
            Map<String, dynamic> map = jsonDecode(abEntry['tag_colors']);
            ab.tagColors.value = Map<String, int>.from(map);
          }
        }
      }
      if (abEntries.isNotEmpty) {
        _callbackPeerUpdate();
      }
    }
  }

// #endregion

// #region tools
  Peer? find(String id) {
    return currentAbPeers.firstWhereOrNull((e) => e.id == id);
  }

  bool idContainByCurrent(String id) {
    return currentAbPeers.where((element) => element.id == id).isNotEmpty;
  }

  void unsetSelectedTags() {
    selectedTags.clear();
  }

  List<dynamic> getPeerTags(String id) {
    final it = currentAbPeers.where((p0) => p0.id == id);
    if (it.isEmpty) {
      return [];
    } else {
      return it.first.tags;
    }
  }

  String getPeerNote(String id) {
    final it = currentAbPeers.where((p0) => p0.id == id);
    if (it.isEmpty) {
      return '';
    } else {
      return it.first.note;
    }
  }

  Color getCurrentAbTagColor(String tag) {
    if (tag == kUntagged) {
      return MyTheme.accent;
    }
    int? colorValue = current.tagColors[tag];
    if (colorValue != null) {
      return Color(colorValue);
    }
    return str2color2(tag, existing: current.tagColors.values.toList());
  }

  List<String> addressBookNames() {
    return addressbooks.keys.toList();
  }

  String personalAddressBookName() {
    return _personalAddressBookName;
  }

  Future<void> setCurrentName(String name) async {
    final oldName = _currentName.value;
    if (addressbooks.containsKey(name)) {
      _currentName.value = name;
    } else {
      if (addressbooks.containsKey(_personalAddressBookName)) {
        _currentName.value = _personalAddressBookName;
      } else if (addressbooks.containsKey(_legacyAddressBookName)) {
        _currentName.value = _legacyAddressBookName;
      } else {
        _currentName.value = '';
      }
    }
    if (!current.initialized) {
      await current.pullAb(quiet: false);
    }
    _refreshTab();
    if (oldName != _currentName.value) {
      _syncAllFromRecent = true;
      _saveCache();
    }
  }

  bool isCurrentAbFull(bool warn) {
    final res = current.isFull();
    if (res && warn) {
      BotToast.showText(
          contentColor: Colors.red, text: translate('exceed_max_devices'));
    }
    return res;
  }

  void _refreshTab() {
    platformFFI.tryHandle({'name': LoadEvent.addressBook});
  }

  // should not call this function in a loop call stack
  Future<void> pullNonLegacyAfterChange({String? name}) async {
    if (name == null) {
      if (current.name() != _legacyAddressBookName) {
        return await current.pullAb(quiet: true);
      }
    } else if (name != _legacyAddressBookName) {
      final ab = addressbooks[name];
      if (ab != null) {
        return await ab.pullAb(quiet: true);
      }
    }
  }

  List<String> idExistIn(String id) {
    List<String> v = [];
    addressbooks.forEach((key, value) {
      if (value.peers.any((e) => e.id == id)) {
        v.add(key);
      }
    });
    return v;
  }

  List<Peer> allPeers() {
    List<Peer> v = [];
    addressbooks.forEach((key, value) {
      v.addAll(value.peers.map((e) => Peer.copy(e)).toList());
    });
    return v;
  }

  String translatedName(String name) {
    if (name == _personalAddressBookName || name == _legacyAddressBookName) {
      return translate(name);
    } else {
      return name;
    }
  }

  void _callbackPeerUpdate() {
    for (var listener in _peerIdUpdateListeners.values) {
      listener();
    }
  }

  void addPeerUpdateListener(String key, VoidCallback listener) {
    _peerIdUpdateListeners[key] = listener;
  }

  void removePeerUpdateListener(String key) {
    _peerIdUpdateListeners.remove(key);
  }

  String? getdefaultSharedPassword() {
    if (current.isPersonal()) {
      return null;
    }
    final profile = current.sharedProfile();
    if (profile == null) {
      return null;
    }
    try {
      if (profile.info is Map) {
        final password = (profile.info as Map)['password'];
        if (password is String && password.isNotEmpty) {
          return password;
        }
      }
      return null;
    } catch (e) {
      debugPrint("getdefaultSharedPassword: $e");
      return null;
    }
  }

// #endregion
}

abstract class BaseAb {
  final peers = List<Peer>.empty(growable: true).obs;
  final RxList<String> tags = <String>[].obs;
  final RxMap<String, int> tagColors = Map<String, int>.fromEntries([]).obs;
  final selectedTags = List<String>.empty(growable: true).obs;

  final pullError = "".obs;
  final pushError = "".obs;
  final abLoading = false
      .obs; // Indicates whether the UI should show a loading state for the address book.
  var abPulling =
      false; // Tracks whether a pull operation is currently in progress to prevent concurrent pulls. Unlike abLoading, this is not tied to UI updates.
  bool initialized = false;

  String name();

  bool isPersonal() {
    return name() == _personalAddressBookName ||
        name() == _legacyAddressBookName;
  }

  bool isLegacy() {
    return name() == _legacyAddressBookName;
  }

  Future<void> pullAb({quiet = false}) async {
    if (abPulling) return;
    abPulling = true;
    if (!quiet) {
      abLoading.value = true;
      pullError.value = "";
    }
    initialized = false;
    debugPrint("pull ab \"${name()}\"");
    try {
      initialized = await pullAbImpl(quiet: quiet);
    } catch (e) {
      debugPrint("Error occurred while pulling address book: $e");
    } finally {
      abLoading.value = false;
      abPulling = false;
    }
  }

  Future<bool> pullAbImpl({quiet = false});

  Future<String?> addPeers(List<Map<String, dynamic>> ps);
  removeHash(Map<String, dynamic> p) {
    p.remove('hash');
  }

  removePassword(Map<String, dynamic> p) {
    p.remove('password');
  }

  removeNonExistentTags(Map<String, dynamic> p) {
    try {
      final oldTags = p.remove('tags');
      if (oldTags is List) {
        final newTags = oldTags.where((e) => tagContainBy(e)).toList();
        p['tags'] = newTags;
      }
    } catch (e) {
      print("removeNonExistentTags: $e");
    }
  }

  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags);

  Future<bool> changeAlias({required String id, required String alias});

  Future<bool> changeNote({required String id, required String note});

  Future<bool> changePersonalHashPassword(String id, String hash);

  Future<bool> changeSharedPassword(String id, String password);

  Future<bool> deletePeers(List<String> ids);

  Future<bool> addTags(List<String> tagList, Map<String, int> tagColorMap);

  bool tagContainBy(String tag) {
    return tags.where((element) => element == tag).isNotEmpty;
  }

  Future<bool> renameTag(String oldTag, String newTag);

  Future<bool> setTagColor(String tag, Color color);

  Future<bool> deleteTag(String tag);

  bool isFull();

  void setSharedProfile(AbProfile profile);

  AbProfile? sharedProfile();

  bool canWrite();

  bool fullControl();

  Future<void> syncFromRecent(List<Peer> recents);
}

class LegacyAb extends BaseAb {
  bool get emtpy => peers.isEmpty && tags.isEmpty;
  // licensedDevices is obtained from personal ab, shared ab restrict it in server
  var licensedDevices = 0;

  LegacyAb();

  @override
  AbProfile? sharedProfile() {
    return null;
  }

  @override
  void setSharedProfile(AbProfile? profile) {}

  @override
  bool canWrite() {
    return true;
  }

  @override
  bool fullControl() {
    return true;
  }

  @override
  bool isFull() {
    return licensedDevices > 0 && peers.length >= licensedDevices;
  }

  @override
  String name() {
    return _legacyAddressBookName;
  }

  @override
  Future<bool> pullAbImpl({quiet = false}) async {
    return true;
  }

  Future<bool> pushAb(
      {bool toastIfFail = true, bool toastIfSucc = true}) async {
    debugPrint("pushAb: toastIfFail:$toastIfFail, toastIfSucc:$toastIfSucc");
    pushError.value = '';
    // R-SV6/R-G4: no account-backed address-book server exists in this fork.
    // Keep the disabled legacy tab scaffold local-only.
    peers.refresh();
    if (toastIfSucc) {
      showToast(translate('Successful'));
    }
    return true;
  }

// #region Peer
  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    bool full = false;
    for (var p in ps) {
      if (!isFull()) {
        p.remove('password'); // legacy ab ignore password
        final index = peers.indexWhere((e) => e.id == p['id']);
        if (index >= 0) {
          _merge(Peer.fromJson(p), peers[index]);
          _mergePeerFromGroup(peers[index]);
        } else {
          peers.add(Peer.fromJson(p));
        }
      } else {
        full = true;
        break;
      }
    }
    await pushAb(toastIfSucc: false, toastIfFail: false);
    if (full) {
      return translate("exceed_max_devices");
    } else {
      return null;
    }
  }

  _mergePeerFromGroup(Peer p) {
    final g = gFFI.groupModel.peers.firstWhereOrNull((e) => p.id == e.id);
    if (g == null) return;
    if (p.username.isEmpty) {
      p.username = g.username;
    }
    if (p.hostname.isEmpty) {
      p.hostname = g.hostname;
    }
    if (p.platform.isEmpty) {
      p.platform = g.platform;
    }
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    peers.map((e) {
      if (ids.contains(e.id)) {
        e.tags = tags;
      }
    }).toList();
    return await pushAb();
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    final it = peers.where((element) => element.id == id);
    if (it.isEmpty) {
      return false;
    }
    it.first.alias = alias;
    return await pushAb();
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    // no need to implement
    return false;
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    // no need to implement
    return false;
  }

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {
    bool peerSyncEqual(Peer a, Peer b) {
      return a.hash == b.hash &&
          a.username == b.username &&
          a.platform == b.platform &&
          a.hostname == b.hostname &&
          a.alias == b.alias;
    }

    bool needSync = false;
    for (var i = 0; i < recents.length; i++) {
      var r = recents[i];
      var index = peers.indexWhere((e) => e.id == r.id);
      if (index < 0) {
        if (!isFull()) {
          peers.add(r);
          needSync = true;
        }
      } else {
        Peer old = Peer.copy(peers[index]);
        _merge(r, peers[index]);
        if (!peerSyncEqual(peers[index], old)) {
          needSync = true;
        }
      }
    }
    if (needSync) {
      await pushAb(toastIfSucc: false, toastIfFail: false);
      gFFI.abModel._refreshTab();
    }
    // Pull cannot be used for sync to avoid cyclic sync.
  }

  void _merge(Peer r, Peer p) {
    p.hash = r.hash.isEmpty ? p.hash : r.hash;
    p.username = r.username.isEmpty ? p.username : r.username;
    p.hostname = r.hostname.isEmpty ? p.hostname : r.hostname;
    p.platform = r.platform.isEmpty ? p.platform : r.platform;
    p.alias = p.alias.isEmpty ? r.alias : p.alias;
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    bool changed = false;
    final it = peers.where((element) => element.id == id);
    if (it.isNotEmpty) {
      if (it.first.hash != hash) {
        it.first.hash = hash;
        changed = true;
      }
    }
    if (changed) {
      return await pushAb(toastIfSucc: false, toastIfFail: false);
    }
    return true;
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    peers.removeWhere((e) => ids.contains(e.id));
    return await pushAb();
  }
// #endregion

// #region Tag
  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    for (var e in tagList) {
      if (!tagContainBy(e)) {
        tags.add(e);
      }
      if (tagColors[e] == null) {
        tagColors[e] = str2color2(e, existing: tagColors.values.toList()).value;
      }
    }
    return await pushAb();
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    if (tags.contains(newTag)) {
      BotToast.showText(
          contentColor: Colors.red, text: 'Tag $newTag already exists');
      return false;
    }
    tags.value = tags.map((e) {
      if (e == oldTag) {
        return newTag;
      } else {
        return e;
      }
    }).toList();
    for (var peer in peers) {
      peer.tags = peer.tags.map((e) {
        if (e == oldTag) {
          return newTag;
        } else {
          return e;
        }
      }).toList();
    }
    int? oldColor = tagColors[oldTag];
    if (oldColor != null) {
      tagColors.remove(oldTag);
      tagColors.addAll({newTag: oldColor});
    }
    return await pushAb();
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    if (tags.contains(tag)) {
      tagColors[tag] = color.value;
    }
    return await pushAb();
  }

  @override
  Future<bool> deleteTag(String tag) async {
    gFFI.abModel.selectedTags.remove(tag);
    tags.removeWhere((element) => element == tag);
    tagColors.remove(tag);
    for (var peer in peers) {
      if (peer.tags.isEmpty) {
        continue;
      }
      if (peer.tags.contains(tag)) {
        peer.tags.remove(tag);
      }
    }
    return await pushAb();
  }

// #endregion

  Map<String, dynamic> _serialize() {
    final peersJsonData =
        peers.map((e) => e.toCustomJson(includingHash: true)).toList();
    for (var e in tags) {
      if (tagColors[e] == null) {
        tagColors[e] = str2color2(e, existing: tagColors.values.toList()).value;
      }
    }
    final tagColorJsonData = jsonEncode(tagColors);
    return {
      "tags": tags,
      "peers": peersJsonData,
      "tag_colors": tagColorJsonData
    };
  }

  _deserialize(dynamic data) {
    if (data == null) return;
    final oldOnlineIDs = peers.where((e) => e.online).map((e) => e.id).toList();
    tags.clear();
    tagColors.clear();
    peers.clear();
    if (data['tags'] is List) {
      tags.value = (data['tags'] as List).map((e) => e.toString()).toList();
    }
    if (data['peers'] is List) {
      for (final peer in data['peers']) {
        peers.add(Peer.fromJson(peer));
      }
    }
    if (isFull()) {
      peers.removeRange(licensedDevices, peers.length);
    }
    // restore online
    peers
        .where((e) => oldOnlineIDs.contains(e.id))
        .map((e) => e.online = true)
        .toList();
    if (data['tag_colors'] is String) {
      Map<String, dynamic> map = jsonDecode(data['tag_colors']);
      tagColors.value = Map<String, int>.from(map);
    }
    // add color to tag
    final tagsWithoutColor =
        tags.toList().where((e) => !tagColors.containsKey(e)).toList();
    for (var t in tagsWithoutColor) {
      tagColors[t] = str2color2(t, existing: tagColors.values.toList()).value;
    }
  }
}

class Ab extends BaseAb {
  AbProfile profile;
  late final bool personal;
  bool get emtpy => peers.isEmpty && tags.isEmpty;

  Ab(this.profile, this.personal);

  @override
  String name() {
    if (personal) {
      return _personalAddressBookName;
    } else {
      return profile.name;
    }
  }

  @override
  AbProfile? sharedProfile() {
    return profile;
  }

  @override
  void setSharedProfile(AbProfile profile) {
    this.profile = profile;
  }

  @override
  bool isFull() {
    return gFFI.abModel._maxPeerOneAb > 0 &&
        peers.length >= gFFI.abModel._maxPeerOneAb;
  }

  @override
  bool canWrite() {
    if (personal) {
      return true;
    } else {
      return profile.rule == ShareRule.readWrite.value ||
          profile.rule == ShareRule.fullControl.value;
    }
  }

  @override
  bool fullControl() {
    if (personal) {
      return true;
    } else {
      return profile.rule == ShareRule.fullControl.value;
    }
  }

  @override
  Future<bool> pullAbImpl({quiet = false}) async {
    return true;
  }

// #region Peers
  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    for (var p in ps) {
      if (peers.firstWhereOrNull((e) => e.id == p['id']) != null) {
        continue;
      }
      if (isFull()) {
        return translate("exceed_max_devices");
      }
      if (personal) {
        removePassword(p);
      } else {
        removeHash(p);
      }
      peers.add(Peer.fromJson(p));
    }
    return null;
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    for (var peer in peers) {
      if (ids.contains(peer.id)) {
        peer.tags = tags;
      }
    }
    return true;
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    final it = peers.where((element) => element.id == id);
    if (it.isEmpty) {
      return false;
    }
    it.first.alias = alias;
    return true;
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    final it = peers.where((element) => element.id == id);
    if (it.isEmpty) {
      return false;
    }
    it.first.note = note;
    return true;
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    if (!personal) return false;
    final it = peers.where((element) => element.id == id);
    if (it.isNotEmpty) {
      it.first.hash = hash;
    }
    return true;
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    if (personal) return false;
    final it = peers.where((element) => element.id == id);
    if (it.isNotEmpty) {
      it.first.password = password;
    }
    return true;
  }

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {
    var uiUpdate = false;
    for (var p in peers) {
      final r = recents.firstWhereOrNull((e) => e.id == p.id);
      if (r == null) {
        continue;
      }
      if (p.sameServer != true &&
          r.username.isNotEmpty &&
          p.username != r.username) {
        p.username = r.username;
        uiUpdate = true;
      }
      if (p.sameServer != true &&
          r.hostname.isNotEmpty &&
          p.hostname != r.hostname) {
        p.hostname = r.hostname;
        uiUpdate = true;
      }
      if (p.sameServer != true &&
          r.platform.isNotEmpty &&
          p.platform != r.platform) {
        p.platform = r.platform;
        uiUpdate = true;
      }
      if (personal && r.hash.isNotEmpty && p.hash != r.hash) {
        p.hash = r.hash;
        uiUpdate = true;
      }
    }
    if (uiUpdate && gFFI.abModel.currentName.value == profile.name) {
      peers.refresh();
      gFFI.abModel._saveCache();
    }
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    peers.removeWhere((e) => ids.contains(e.id));
    return true;
  }
// #endregion

// #region Tags
  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    for (var t in tagList) {
      if (!tagContainBy(t)) {
        tags.add(t);
      }
      tagColors[t] =
          tagColorMap[t] ?? str2color2(t, existing: tagColors.values.toList()).value;
    }
    return true;
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    if (tags.contains(newTag)) {
      BotToast.showText(
          contentColor: Colors.red, text: 'Tag $newTag already exists');
      return false;
    }
    tags.value = tags.map((e) => e == oldTag ? newTag : e).toList();
    for (var peer in peers) {
      peer.tags = peer.tags.map((e) => e == oldTag ? newTag : e).toList();
    }
    final oldColor = tagColors[oldTag];
    if (oldColor != null) {
      tagColors.remove(oldTag);
      tagColors[newTag] = oldColor;
    }
    return true;
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    if (tags.contains(tag)) {
      tagColors[tag] = color.value;
    }
    return true;
  }

  @override
  Future<bool> deleteTag(String tag) async {
    gFFI.abModel.selectedTags.remove(tag);
    tags.removeWhere((element) => element == tag);
    tagColors.remove(tag);
    for (var peer in peers) {
      peer.tags.remove(tag);
    }
    return true;
  }

// #endregion
}

// DummyAb is for current ab is null
class DummyAb extends BaseAb {
  @override
  bool isFull() {
    return false;
  }

  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    return "dummpy";
  }

  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    return false;
  }

  @override
  bool canWrite() {
    return false;
  }

  @override
  bool fullControl() {
    return false;
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    return false;
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    return false;
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    return false;
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    return false;
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List tags) async {
    return false;
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    return false;
  }

  @override
  Future<bool> deleteTag(String tag) async {
    return false;
  }

  @override
  String name() {
    return "dummpy";
  }

  @override
  Future<bool> pullAbImpl({quiet = false}) async {
    return false;
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    return false;
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    return false;
  }

  @override
  AbProfile? sharedProfile() {
    return null;
  }

  @override
  void setSharedProfile(AbProfile profile) {}

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {}
}
