import 'package:flutter/material.dart';
import '../../models/incoming_recording_setting.dart';

class IncomingRecordingSettingView extends StatelessWidget {
  const IncomingRecordingSettingView({super.key, required this.model,
    required this.translate, required this.fixed});
  final IncomingRecordingSettingModel model;
  final String Function(String) translate;
  final bool fixed;

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: model,
    builder: (context, _) {
      final enabled = model.enabled;
      return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        CheckboxListTile(
          contentPadding: EdgeInsets.zero,
          controlAffinity: ListTileControlAffinity.leading,
          dense: true,
          title: Text(translate('Automatically record incoming sessions')),
          tristate: true,
          value: enabled,
          onChanged: fixed || model.pending || enabled == null ? null
              : (_) => model.change(!enabled),
        ),
        if (model.pending) const LinearProgressIndicator(minHeight: 2),
        if (fixed) Text(translate('Set by policy')),
        if (model.enabled == null && !model.pending)
          Text(translate('Recording setting unavailable')),
        if (model.outcome != null && model.outcome != IncomingRecordingChangeOutcome.applied)
          Text(translate(switch (model.outcome!) {
            IncomingRecordingChangeOutcome.denied => 'Denied',
            IncomingRecordingChangeOutcome.failed => 'Failed',
            _ => 'Recording change is unconfirmed',
          }), style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ],
      );
    },
  );
}
