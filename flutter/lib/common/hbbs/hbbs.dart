import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/consts.dart';

import 'package:flutter_hbb/models/peer_model.dart';

import '../../models/platform_model.dart';

enum UserStatus { kDisabled, kNormal, kUnverified }

// to-do: The UserPayload does not contain all the fields of the user.
// Is all the fields of the user needed?
class UserPayload {
  String name = '';
  String displayName = '';
  String avatar = '';
  String email = '';
  String note = '';
  String? verifier;
  UserStatus status;
  bool isAdmin = false;

  UserPayload.fromJson(Map<String, dynamic> json)
      : name = json['name'] ?? '',
        displayName = json['display_name'] ?? '',
        avatar = json['avatar'] ?? '',
        email = json['email'] ?? '',
        note = json['note'] ?? '',
        verifier = json['verifier'],
        status = json['status'] == 0
            ? UserStatus.kDisabled
            : json['status'] == -1
                ? UserStatus.kUnverified
                : UserStatus.kNormal,
        isAdmin = json['is_admin'] == true;

  Map<String, dynamic> toJson() {
    final Map<String, dynamic> map = {
      'name': name,
      'display_name': displayName,
      'avatar': avatar,
      'status': status == UserStatus.kDisabled
          ? 0
          : status == UserStatus.kUnverified
              ? -1
              : 1,
    };
    return map;
  }

  Map<String, dynamic> toGroupCacheJson() {
    final Map<String, dynamic> map = {
      'name': name,
      'display_name': displayName,
    };
    return map;
  }

  String get displayNameOrName {
    return displayName.trim().isEmpty ? name : displayName;
  }
}

class PeerPayload {
  String id = '';
  Map<String, dynamic> info = {};
  int? status;
  String user = '';
  String user_name = '';
  String? device_group_name;
  String note = '';

  PeerPayload.fromJson(Map<String, dynamic> json)
      : id = json['id'] ?? '',
        info = (json['info'] is Map<String, dynamic>) ? json['info'] : {},
        status = json['status'],
        user = json['user'] ?? '',
        user_name = json['user_name'] ?? '',
        device_group_name = json['device_group_name'] ?? '',
        note = json['note'] ?? '';

  static Peer toPeer(PeerPayload p) {
    return Peer.fromJson({
      "id": p.id,
      'loginName': p.user_name,
      "username": p.info['username'] ?? '',
      "platform": _platform(p.info['os']),
      "hostname": p.info['device_name'],
      "device_group_name": p.device_group_name,
      "note": p.note,
    });
  }

  static String? _platform(dynamic field) {
    if (field == null) {
      return null;
    }
    final fieldStr = field.toString();
    List<String> list = fieldStr.split(' / ');
    if (list.isEmpty) return null;
    final os = list[0];
    switch (os.toLowerCase()) {
      case 'windows':
        return kPeerPlatformWindows;
      case 'linux':
        return kPeerPlatformLinux;
      case 'macos':
        return kPeerPlatformMacOS;
      case 'android':
        return kPeerPlatformAndroid;
      default:
        if (fieldStr.toLowerCase().contains('linux')) {
          return kPeerPlatformLinux;
        }
        return null;
    }
  }
}

enum ShareRule {
  read(1),
  readWrite(2),
  fullControl(3);

  const ShareRule(this.value);
  final int value;

  static String desc(int v) {
    if (v == ShareRule.read.value) {
      return translate('Read-only');
    }
    if (v == ShareRule.readWrite.value) {
      return translate('Read/Write');
    }
    if (v == ShareRule.fullControl.value) {
      return translate('Full Control');
    }
    return v.toString();
  }

  static String shortDesc(int v) {
    if (v == ShareRule.read.value) {
      return 'R';
    }
    if (v == ShareRule.readWrite.value) {
      return 'RW';
    }
    if (v == ShareRule.fullControl.value) {
      return 'F';
    }
    return v.toString();
  }

  static ShareRule? fromValue(int v) {
    if (v == ShareRule.read.value) {
      return ShareRule.read;
    }
    if (v == ShareRule.readWrite.value) {
      return ShareRule.readWrite;
    }
    if (v == ShareRule.fullControl.value) {
      return ShareRule.fullControl;
    }
    return null;
  }
}

class AbProfile {
  String guid;
  String name;
  String owner;
  String? note;
  dynamic info;
  int rule;

  AbProfile(this.guid, this.name, this.owner, this.note, this.rule, this.info);

  AbProfile.fromJson(Map<String, dynamic> json)
      : guid = json['guid'] ?? '',
        name = json['name'] ?? '',
        owner = json['owner'] ?? '',
        note = json['note'] ?? '',
        info = json['info'],
        rule = json['rule'] ?? 0;
}

class AbTag {
  String name;
  int color;

  AbTag(this.name, this.color);

  AbTag.fromJson(Map<String, dynamic> json)
      : name = json['name'] ?? '',
        color = json['color'] ?? '';
}

class DeviceGroupPayload {
  String name;

  DeviceGroupPayload(this.name);

  DeviceGroupPayload.fromJson(Map<String, dynamic> json)
      : name = json['name'] ?? '';

  Map<String, dynamic> toGroupCacheJson() {
    final Map<String, dynamic> map = {
      'name': name,
    };
    return map;
  }
}
