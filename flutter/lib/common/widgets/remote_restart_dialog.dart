import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';

class RemoteRestartDialog extends StatefulWidget {
  const RemoteRestartDialog({
    super.key,
    required this.target,
    required this.requestRestart,
    required this.close,
    required this.translateText,
  });

  final String target;
  final Future<void> Function() requestRestart;
  final DialogClose close;
  final String Function(String) translateText;

  @override
  State<RemoteRestartDialog> createState() => _RemoteRestartDialogState();
}

class _RemoteRestartDialogState extends State<RemoteRestartDialog> {
  bool _submitting = false;
  bool _failed = false;

  bool get _current => mounted && widget.close.isCurrent;

  void _cancel() {
    if (_current && !_submitting) widget.close();
  }

  Future<void> _submit() async {
    if (!_current || _submitting) return;
    setState(() {
      _submitting = true;
      _failed = false;
    });
    try {
      await widget.requestRestart();
      if (_current) widget.close();
    } catch (error) {
      debugPrint('Failed to submit remote restart: $error');
      if (_current) {
        setState(() {
          _submitting = false;
          _failed = true;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final text = widget.translateText;
    return CustomAlertDialog(
      title: Row(children: [
        const Icon(Icons.warning_rounded, color: Colors.redAccent, size: 28),
        Flexible(
          child: Padding(
            padding: const EdgeInsets.only(left: 10),
            child: Text(text('Restart remote device')),
          ),
        ),
      ]),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('${text('Are you sure you want to restart')} \n${widget.target} ?'),
          if (_submitting) const LinearProgressIndicator(),
          if (_failed)
            Text(text('Failed'),
                style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ],
      ),
      actions: [
        dialogButton('Cancel',
            icon: const Icon(Icons.close_rounded),
            onPressed: _submitting ? null : _cancel,
            isOutline: true,
            translateText: text),
        dialogButton(_failed ? 'Retry' : 'OK',
            icon: const Icon(Icons.done_rounded),
            onPressed: _submitting ? null : _submit,
            translateText: text),
      ],
      onCancel: _cancel,
      onSubmit: _submit,
    );
  }
}
