on run {daemon_file, agent_file, bundled_service_exec}

  set daemon_plist to "/Library/LaunchDaemons/com.carriez.RustDesk_service.plist"
  set agent_plist to "/Library/LaunchAgents/com.carriez.RustDesk_server.plist"
  set helper_dir to "/Library/PrivilegedHelperTools"
  set service_exec to "/Library/PrivilegedHelperTools/com.carriez.rustdesk_service"
  set temp_service_exec to "/Library/PrivilegedHelperTools/.com.carriez.rustdesk_service.installing"
  set helper_requirement to "=anchor apple generic and certificate leaf[subject.OU] = \"HZF9JMC8YN\" and (identifier \"service\" or identifier \"com.carriez.rustdesk_service\")"
  set log_dir to "/Library/Logs/RustDesk"
  set log_stderr to "/Library/Logs/RustDesk/rustdesk_service.err"
  set log_stdout to "/Library/Logs/RustDesk/rustdesk_service.out"
  set support_dir to "/Library/Application Support/RustDesk"
  set root_prefs_dir to "/var/root/Library/Preferences/com.carriez.RustDesk"
  set service_label to "com.carriez.RustDesk_service"

  set reject_symlinks to "if [ -L " & quoted form of daemon_plist & " ] || [ -L " & quoted form of agent_plist & " ] || [ -L " & quoted form of helper_dir & " ] || [ -L " & quoted form of service_exec & " ] || [ -L " & quoted form of temp_service_exec & " ] || [ -L " & quoted form of bundled_service_exec & " ] || [ -L " & quoted form of log_dir & " ] || [ -L " & quoted form of log_stderr & " ] || [ -L " & quoted form of log_stdout & " ] || [ -L " & quoted form of support_dir & " ] || [ -L " & quoted form of root_prefs_dir & " ]; then exit 1; fi;"

  set cleanup_temp to "trap \"/bin/rm -f " & quoted form of temp_service_exec & "\" EXIT;"

  set create_helper_dir to "/usr/bin/install -d -o root -g wheel -m 0755 " & quoted form of helper_dir & ";"

  set secure_helper_dir to "/bin/chmod -N " & quoted form of helper_dir & " && /usr/sbin/chown root:wheel " & quoted form of helper_dir & " && /bin/chmod 0755 " & quoted form of helper_dir & ";"

  set create_dirs to "/usr/bin/install -d -o root -g wheel -m 0755 " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & ";"

  set secure_dirs to "/bin/chmod -N " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & " && /usr/sbin/chown root:wheel " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & " && /bin/chmod 0755 " & quoted form of log_dir & " " & quoted form of support_dir & " " & quoted form of root_prefs_dir & ";"

  set verify_bundled_service_exec to "if [ ! -f " & quoted form of bundled_service_exec & " ] || [ ! -x " & quoted form of bundled_service_exec & " ]; then exit 1; fi; if [ -n \"$(/usr/bin/find " & quoted form of bundled_service_exec & " -prune \\( -perm +022 \\) -print)\" ]; then exit 1; fi; /bin/ls -lde " & quoted form of bundled_service_exec & " | /usr/bin/awk 'NR > 1 {exit 1}' || exit 1; /usr/bin/codesign --verify --strict -R " & quoted form of helper_requirement & " " & quoted form of bundled_service_exec & " >/dev/null 2>&1;"

  set install_service_exec to "/bin/rm -f " & quoted form of temp_service_exec & " && /usr/bin/install -o root -g wheel -m 0755 " & quoted form of bundled_service_exec & " " & quoted form of temp_service_exec & " && /bin/chmod -N " & quoted form of temp_service_exec & " && /usr/bin/codesign --verify --strict -R " & quoted form of helper_requirement & " " & quoted form of temp_service_exec & " >/dev/null 2>&1 && /bin/mv -f " & quoted form of temp_service_exec & " " & quoted form of service_exec & " && /bin/chmod -N " & quoted form of service_exec & " && /usr/sbin/chown root:wheel " & quoted form of service_exec & " && /bin/chmod 0755 " & quoted form of service_exec & " && /usr/bin/cmp -s " & quoted form of bundled_service_exec & " " & quoted form of service_exec & ";"

  set verify_service_exec to "for service_component in " & quoted form of helper_dir & " " & quoted form of service_exec & "; do if [ -L \"$service_component\" ]; then exit 1; fi; if [ ! -e \"$service_component\" ]; then exit 1; fi; if [ \"$(/usr/bin/stat -f '%Su:%Sg' \"$service_component\")\" != \"root:wheel\" ]; then exit 1; fi; if [ -n \"$(/usr/bin/find \"$service_component\" -prune \\( ! -user root -o ! -group wheel -o -perm +022 \\) -print)\" ]; then exit 1; fi; /bin/ls -lde \"$service_component\" | /usr/bin/awk 'NR > 1 {exit 1}' || exit 1; done; if [ ! -f " & quoted form of service_exec & " ] || [ ! -x " & quoted form of service_exec & " ]; then exit 1; fi; /usr/bin/codesign --verify --strict -R " & quoted form of helper_requirement & " " & quoted form of service_exec & " >/dev/null 2>&1;"

  set prepare_logs to "/bin/rm -f " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /usr/bin/touch " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /bin/chmod -N " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /usr/sbin/chown root:wheel " & quoted form of log_stderr & " " & quoted form of log_stdout & " && /bin/chmod 0644 " & quoted form of log_stderr & " " & quoted form of log_stdout & ";"

  set write_daemon_plist to "/usr/bin/printf %s " & quoted form of daemon_file & " > " & quoted form of daemon_plist & " && /bin/chmod -N " & quoted form of daemon_plist & " && /usr/sbin/chown root:wheel " & quoted form of daemon_plist & " && /bin/chmod 0644 " & quoted form of daemon_plist & ";"

  set write_agent_plist to "/usr/bin/printf %s " & quoted form of agent_file & " > " & quoted form of agent_plist & " && /bin/chmod -N " & quoted form of agent_plist & " && /usr/sbin/chown root:wheel " & quoted form of agent_plist & " && /bin/chmod 0644 " & quoted form of agent_plist & ";"

  set unload_existing_service to "if /bin/launchctl list " & quoted form of service_label & " >/dev/null 2>&1; then /bin/launchctl unload -w " & quoted form of daemon_plist & "; fi;"

  set load_service to "/bin/launchctl load -w " & quoted form of daemon_plist & " && /bin/launchctl list " & quoted form of service_label & " >/dev/null 2>&1;"

  set sh to "set -e;" & cleanup_temp & reject_symlinks & verify_bundled_service_exec & create_helper_dir & secure_helper_dir & install_service_exec & verify_service_exec & create_dirs & secure_dirs & prepare_logs & write_daemon_plist & write_agent_plist & verify_service_exec & unload_existing_service & load_service

  do shell script sh with prompt "RustDesk wants to install daemon and agent" with administrator privileges
end run
