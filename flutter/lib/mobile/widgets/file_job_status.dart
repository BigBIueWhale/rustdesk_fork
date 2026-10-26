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

      // Show the first active job, otherwise the newest recorded outcome.
      final activeJob = jobTable
              .firstWhereOrNull((job) => job.state == JobState.inProgress) ??
          jobTable.last;
      final jobId = activeJob.id;

      bool ownsJob() {
        if (!controller.isCurrentSession(sessionId)) return false;
        final index = controller.getJob(jobId);
        return index >= 0 && identical(jobTable[index], activeJob);
      }

      void dismiss() {
        if (ownsJob()) controller.removeJob(sessionId, jobId);
      }

      switch (activeJob.state) {
        case JobState.inProgress:
          return BottomSheetBody(
            leading: CircularProgressIndicator(),
            title: _translate("Waiting"),
            text:
                "${_translate("Speed")}:  ${readableFileSize(activeJob.speed)}/s",
            onCanceled: () async {
              if (!ownsJob()) return;
              final canceled = await controller.cancelJob(
                  jobId, expectedSessionId: sessionId);
              if (canceled) dismiss();
            },
          );
        case JobState.done:
          return BottomSheetBody(
            leading: Icon(Icons.check),
            title: "${_translate("Successful")}!",
            text: activeJob.display(),
            onCanceled: dismiss,
          );
        case JobState.error:
          return BottomSheetBody(
            leading: Icon(Icons.error),
            title: "${_translate("Error")}!",
            text: "",
            onCanceled: dismiss,
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
                  Row(children: [
                    ...?actions,
                    IconButton(
                      icon: Icon(Icons.cancel_outlined),
                      onPressed: onCanceled,
                    ),
                  ])
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
