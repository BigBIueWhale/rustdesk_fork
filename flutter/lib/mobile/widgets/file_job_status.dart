import 'package:flutter/material.dart';
import 'package:get/get.dart';

import '../../common.dart';
import '../../models/file_model.dart';

class FileJobStatus extends StatelessWidget {
  FileJobStatus({super.key, required this.controller, required this.sessionId,
      String Function(String)? translateText})
      : _translate = translateText ?? translate;

  final JobController controller;
  final SessionID sessionId;
  final String Function(String) _translate;

  @override
  Widget build(BuildContext context) => Obx(() {
      final jobTable = controller.jobTable;
      if (jobTable.isEmpty) {
        return Offstage();
      }

      // Find the first job that is in progress (the one actually transferring data)
      // Rust backend processes jobs sequentially, so the first inProgress job is the active one
      final activeJob = jobTable
              .firstWhereOrNull((job) => job.state == JobState.inProgress) ??
          jobTable.last;

      switch (activeJob.state) {
        case JobState.inProgress:
          return BottomSheetBody(
            leading: CircularProgressIndicator(),
            title: _translate("Waiting"),
            text:
                "${_translate("Speed")}:  ${readableFileSize(activeJob.speed)}/s",
            onCanceled: () async {
              final expectedSessionId = sessionId;
              final canceled = await controller.cancelJob(
                  activeJob.id,
                  expectedSessionId: expectedSessionId);
              if (canceled) {
                controller.clearForSession(expectedSessionId);
              }
            },
          );
        case JobState.done:
          return BottomSheetBody(
            leading: Icon(Icons.check),
            title: "${_translate("Successful")}!",
            text: activeJob.display(),
            onCanceled: () =>
                controller.clearForSession(sessionId),
          );
        case JobState.error:
          return BottomSheetBody(
            leading: Icon(Icons.error),
            title: "${_translate("Error")}!",
            text: "",
            onCanceled: () =>
                controller.clearForSession(sessionId),
          );
        case JobState.none:
          break;
        case JobState.paused:
          // TODO: Handle this case.
          break;
      }
      return Offstage();
    });
}

class BottomSheetBody extends StatelessWidget {
  BottomSheetBody(
      {required this.leading,
      required this.title,
      required this.text,
      this.onCanceled,
      this.actions});

  final Widget leading;
  final String title;
  final String text;
  final VoidCallback? onCanceled;
  final List<IconButton>? actions;

  @override
  BottomSheet build(BuildContext context) {
    // ignore: no_leading_underscores_for_local_identifiers
    final _actions = actions ?? [];
    return BottomSheet(
      builder: (BuildContext context) {
        return Container(
            height: 65,
            alignment: Alignment.centerLeft,
            decoration: BoxDecoration(
                color: MyTheme.accent50,
                borderRadius: BorderRadius.vertical(top: Radius.circular(10))),
            child: Padding(
              padding: EdgeInsets.symmetric(horizontal: 15),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      leading,
                      SizedBox(width: 16),
                      Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(title, style: TextStyle(fontSize: 18)),
                          Text(text,
                              style: TextStyle(fontSize: 14)) // TODO color
                        ],
                      )
                    ],
                  ),
                  Row(children: () {
                    _actions.add(IconButton(
                      icon: Icon(Icons.cancel_outlined),
                      onPressed: onCanceled,
                    ));
                    return _actions;
                  }())
                ],
              ),
            ));
      },
      onClosing: () {},
      // backgroundColor: MyTheme.grayBg,
      enableDrag: false,
    );
  }
}
