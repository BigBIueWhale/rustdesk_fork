import 'package:flutter/material.dart';
import '../../models/incoming_recording_status.dart';

class IncomingRecordingStatusView extends StatelessWidget {
  const IncomingRecordingStatusView({
    super.key,
    required this.status,
    required this.translate,
  });

  final IncomingRecordingStatus? status;
  final String Function(String) translate;

  @override
  Widget build(BuildContext context) {
    final current = status;
    final lines = <Widget>[];
    if (current == null) {
      lines.add(Text(translate('Recording status unavailable')));
    } else {
      for (final entry in {
        'Starting': current.starting,
        'Recording': current.active,
        'Finishing': current.finishing,
      }.entries) {
        if (entry.value != 0) {
          lines.add(Text('${translate(entry.key)}: ${entry.value}'));
        }
      }
      if (lines.isEmpty) lines.add(Text(translate('Not recording')));
      final failure = current.lastFailure;
      if (failure != null) {
        final stage = switch (failure.stage) {
          'start' => 'Starting',
          'write' => 'Writing',
          _ => 'Finishing',
        };
        lines.add(Text(
          '${translate('Last recording failure')}: '
          '${translate(failure.camera ? 'View camera' : 'Display')} '
          '${failure.display + 1} (${translate(stage)})',
          style: TextStyle(color: Theme.of(context).colorScheme.error),
        ));
      }
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [Text(translate('Incoming recordings')), ...lines],
    );
  }
}
