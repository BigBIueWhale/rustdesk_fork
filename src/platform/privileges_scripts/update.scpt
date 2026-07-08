on run {daemon_file, agent_file, user, user_home, cur_pid, source_dir}

  set agent_plist to "/Library/LaunchAgents/com.carriez.RustDesk_server.plist"
  set daemon_plist to "/Library/LaunchDaemons/com.carriez.RustDesk_service.plist"
  set app_bundle to "/Applications/RustDesk.app"
  set service_exec to "/Applications/RustDesk.app/Contents/MacOS/service"
  set log_dir to "/Library/Logs/RustDesk"
  set log_stderr to "/Library/Logs/RustDesk/rustdesk_service.err"
  set log_stdout to "/Library/Logs/RustDesk/rustdesk_service.out"
  set support_dir to "/Library/Application Support/RustDesk"
  set root_prefs_dir to "/var/root/Library/Preferences/com.carriez.RustDesk"
  set root_prefs_file to "/var/root/Library/Preferences/com.carriez.RustDesk/RustDesk.toml"
  set root_prefs2_file to "/var/root/Library/Preferences/com.carriez.RustDesk/RustDesk2.toml"

  set check_source to "test -d " & quoted form of source_dir & " || exit 1;"
  set reject_symlinks to "if [ -L " & quoted form of daemon_plist & " ] || [ -L " & quoted form of agent_plist & " ] || [ -L " & quoted form of app_bundle & " ] || [ -L " & quoted form of service_exec & " ] || [ -L " & quoted form of log_dir & " ] || [ -L " & quoted form of log_stderr & " ] || [ -L " & quoted form of log_stdout & " ] || [ -L " & quoted form of support_dir & " ] || [ -L " & quoted form of root_prefs_dir & " ]; then exit 1; fi;"
  set create_dirs to "/usr/bin/install -d -o root -g wheel -m 0755 " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & ";"
  set secure_dirs to "/bin/chmod -N " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & " && /usr/sbin/chown root:wheel " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & " && /bin/chmod 0755 " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & ";"
  set verify_app_bundle_tree to "if [ ! -d " & quoted form of app_bundle & " ]; then exit 1; fi; for service_component in " & quoted form of app_bundle & " " & quoted form of app_bundle & "/Contents " & quoted form of app_bundle & "/Contents/MacOS " & quoted form of service_exec & "; do if [ -L \"$service_component\" ]; then exit 1; fi; done; if [ ! -f " & quoted form of service_exec & " ] || [ ! -x " & quoted form of service_exec & " ]; then exit 1; fi; /usr/bin/find " & quoted form of app_bundle & " -type l -print | while IFS= read -r app_link; do app_target=$(/bin/readlink \"$app_link\") || exit 1; case \"$app_target\" in *../*|../*|*/..|..) exit 1 ;; esac; case \"$app_target\" in /*) case \"$app_target\" in " & quoted form of app_bundle & "/*) ;; *) exit 1 ;; esac ;; esac; done || exit 1;"
  set reject_root_pref_symlinks to "if [ -L " & quoted form of root_prefs_file & " ] || [ -L " & quoted form of root_prefs2_file & " ]; then exit 1; fi;"
  set prepare_logs to "/bin/rm -f " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /usr/bin/touch " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /bin/chmod -N " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /usr/sbin/chown root:wheel " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /bin/chmod 0644 " & quoted form of log_stderr & " " & quoted form of log_stdout & ";"
  set resolve_uid to "uid=$(/usr/bin/id -u " & quoted form of user & " 2>/dev/null || true);"
  set unload_agent to "if [ -n \"$uid\" ]; then /bin/launchctl bootout gui/$uid " & quoted form of agent_plist & " 2>/dev/null || /bin/launchctl bootout user/$uid " & quoted form of agent_plist & " 2>/dev/null || /bin/launchctl unload -w " & quoted form of agent_plist & " || true; else /bin/launchctl unload -w " & quoted form of agent_plist & " || true; fi;"
  set unload_service to "/bin/launchctl unload -w " & quoted form of daemon_plist & " || true;"
  set kill_others to "pids=$(/usr/bin/pgrep -x 'RustDesk' | /usr/bin/grep -Fxv -- " & quoted form of cur_pid & " || true); if [ -n \"$pids\" ]; then /bin/kill -9 $pids || true; fi;"

  set copy_files to "(/bin/rm -rf " & quoted form of app_bundle & " && /usr/bin/ditto " & quoted form of source_dir & " " & quoted form of app_bundle & " && { " & verify_app_bundle_tree & " } && /usr/sbin/chown -R root:wheel " & quoted form of app_bundle & " && /bin/chmod -RN " & quoted form of app_bundle & " && /bin/chmod -R u+rwX,go+rX,go-w " & quoted form of app_bundle & " && (/usr/bin/xattr -r -d com.apple.quarantine " & quoted form of app_bundle & " || true)) || exit 1;"

  set write_daemon_plist to "/usr/bin/printf %s " & quoted form of daemon_file & " > " & quoted form of daemon_plist & " && /bin/chmod -N " & quoted form of daemon_plist & " && /usr/sbin/chown root:wheel " & quoted form of daemon_plist & " && /bin/chmod 0644 " & quoted form of daemon_plist & ";"
  set write_agent_plist to "/usr/bin/printf %s " & quoted form of agent_file & " > " & quoted form of agent_plist & " && /bin/chmod -N " & quoted form of agent_plist & " && /usr/sbin/chown root:wheel " & quoted form of agent_plist & " && /bin/chmod 0644 " & quoted form of agent_plist & ";"
  set copy_user_prefs to "if [ -n " & quoted form of user_home & " ]; then user_prefs=" & quoted form of user_home & "/Library/Preferences/com.carriez.RustDesk; if [ -L \"$user_prefs\" ] || [ -L \"$user_prefs/RustDesk.toml\" ] || [ -L \"$user_prefs/RustDesk2.toml\" ]; then exit 1; fi; if [ -f \"$user_prefs/RustDesk.toml\" ]; then /bin/rm -f " & quoted form of root_prefs_file & " && /bin/cp -f \"$user_prefs/RustDesk.toml\" " & quoted form of root_prefs_file & "; fi; if [ -f \"$user_prefs/RustDesk2.toml\" ]; then /bin/rm -f " & quoted form of root_prefs2_file & " && /bin/cp -f \"$user_prefs/RustDesk2.toml\" " & quoted form of root_prefs2_file & "; fi; fi; for prefs_file in " & quoted form of root_prefs_file & " " & quoted form of root_prefs2_file & "; do if [ -L \"$prefs_file\" ]; then exit 1; fi; if [ -e \"$prefs_file\" ]; then /bin/chmod -N \"$prefs_file\" && /usr/sbin/chown root:wheel \"$prefs_file\" && /bin/chmod 0600 \"$prefs_file\"; fi; done;"
  set load_service to "/bin/launchctl load -w " & quoted form of daemon_plist & ";"
  set agent_label_cmd to "agent_label=$(/usr/bin/basename " & quoted form of agent_plist & " .plist);"
  set bootstrap_agent to "if [ -n \"$uid\" ]; then /bin/launchctl bootstrap gui/$uid " & quoted form of agent_plist & " 2>/dev/null || /bin/launchctl bootstrap user/$uid " & quoted form of agent_plist & " 2>/dev/null || /bin/launchctl load -w " & quoted form of agent_plist & " || true; else /bin/launchctl load -w " & quoted form of agent_plist & " || true; fi;"
  set kickstart_agent to "if [ -n \"$uid\" ]; then /bin/launchctl kickstart -k gui/$uid/$agent_label 2>/dev/null || /bin/launchctl kickstart -k user/$uid/$agent_label 2>/dev/null || true; fi;"
  set load_agent to agent_label_cmd & bootstrap_agent & kickstart_agent

  set sh to "set -e;" & check_source & reject_symlinks & create_dirs & secure_dirs & reject_root_pref_symlinks & prepare_logs & resolve_uid & unload_agent & unload_service & kill_others & copy_files & write_daemon_plist & write_agent_plist & copy_user_prefs & load_service & load_agent

  do shell script sh with prompt "RustDesk wants to update itself" with administrator privileges
end run
