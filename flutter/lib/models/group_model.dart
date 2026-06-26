import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'dart:convert';

class GroupModel {
  final RxBool groupLoading = false.obs;
  final RxString groupLoadError = "".obs;
  final RxList<DeviceGroupPayload> deviceGroups = RxList.empty(growable: true);
  final RxList<UserPayload> users = RxList.empty(growable: true);
  final RxList<Peer> peers = RxList.empty(growable: true);
  final RxBool isSelectedDeviceGroup = false.obs;
  final RxString selectedAccessibleItemName = ''.obs;
  final RxString searchAccessibleItemNameText = ''.obs;
  WeakReference<FFI> parent;
  var initialized = false;
  var _cacheLoadOnceFlag = false;

  final Map<String, VoidCallback> _peerIdUpdateListeners = {};

  bool get emtpy => deviceGroups.isEmpty && users.isEmpty && peers.isEmpty;

  late final Peers peersModel;

  GroupModel(this.parent) {
    peersModel = Peers(
        name: PeersModelName.group,
        getInitPeers: () => peers,
        loadEvent: LoadEvent.group);
  }

  Future<void> pull({force = true, quiet = false}) async {
    if (bind.isDisableGroupPanel()) return;
    if (!gFFI.userModel.isLogin || groupLoading.value) return;
    if (gFFI.userModel.networkError.isNotEmpty) return;
    if (!force && initialized) return;
    if (!quiet) {
      groupLoading.value = true;
      groupLoadError.value = "";
    }
    try {
      await _pull();
      _tryHandlePullError();
    } catch (e) {
      print("pull accessibles error: $e");
    }
    groupLoading.value = false;
    initialized = true;
    platformFFI.tryHandle({'name': LoadEvent.group});
    _saveCache();
  }

  Future<void> _pull() async {
    // R-SV6/R-G4: account-synced "accessible devices" are compiled out.
    // The tab is structurally disabled; if reached, keep the model empty and local.
    deviceGroups.clear();
    users.clear();
    peers.clear();
    selectedAccessibleItemName.value = '';
    groupLoadError.value = '';
    _callbackPeerUpdate();
  }

  void _saveCache() {
    try {
      final map = (<String, dynamic>{
        "access_token": bind.mainGetLocalOption(key: 'access_token'),
        "device_groups": deviceGroups.map((e) => e.toGroupCacheJson()).toList(),
        "users": users.map((e) => e.toGroupCacheJson()).toList(),
        'peers': peers.map((e) => e.toGroupCacheJson()).toList()
      });
      bind.mainSaveGroup(json: jsonEncode(map));
    } catch (e) {
      debugPrint('group save:$e');
    }
  }

  Future<void> loadCache() async {
    try {
      if (_cacheLoadOnceFlag || groupLoading.value || initialized) return;
      _cacheLoadOnceFlag = true;
      final access_token = bind.mainGetLocalOption(key: 'access_token');
      if (access_token.isEmpty) return;
      final cache = await bind.mainLoadGroup();
      if (groupLoading.value) return;
      final data = jsonDecode(cache);
      if (data == null || data['access_token'] != access_token) return;
      deviceGroups.clear();
      users.clear();
      peers.clear();
      if (data['device_groups'] is List) {
        for (var u in data['device_groups']) {
          deviceGroups.add(DeviceGroupPayload.fromJson(u));
        }
      }
      if (data['users'] is List) {
        for (var u in data['users']) {
          users.add(UserPayload.fromJson(u));
        }
      }
      if (data['peers'] is List) {
        for (final peer in data['peers']) {
          peers.add(Peer.fromJson(peer));
        }
        _callbackPeerUpdate();
      }
    } catch (e) {
      debugPrint("load group cache: $e");
    }
  }

  reset() async {
    initialized = false;
    groupLoadError.value = '';
    deviceGroups.clear();
    users.clear();
    peers.clear();
    selectedAccessibleItemName.value = '';
    await bind.mainClearGroup();
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

  void _tryHandlePullError() {
    String errorMessage = groupLoadError.value;
    // The error message is "Retrieving accessible devices is disabled."
    if (errorMessage.toLowerCase().contains('disabled')) {
      users.clear();
      peers.clear();
      deviceGroups.clear();
    }
  }
}
