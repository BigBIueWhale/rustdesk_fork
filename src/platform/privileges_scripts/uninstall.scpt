set daemon_plist to "/Library/LaunchDaemons/com.carriez.RustDesk_service.plist"
set agent_plist to "/Library/LaunchAgents/com.carriez.RustDesk_server.plist"
set helper_dir to "/Library/PrivilegedHelperTools"
set service_exec to "/Library/PrivilegedHelperTools/com.carriez.rustdesk_service"
set temp_service_exec to "/Library/PrivilegedHelperTools/.com.carriez.rustdesk_service.installing"
set service_label to "com.carriez.RustDesk_service"
set service_target to "system/" & service_label

set reject_helper_dir_symlink to "if [ -L " & quoted form of helper_dir & " ]; then exit 1; fi;"
set unload_service to "/bin/launchctl print system >/dev/null 2>&1; if /bin/launchctl print " & quoted form of service_target & " >/dev/null 2>&1; then /bin/launchctl bootout " & quoted form of service_target & "; fi;"
set verify_unloaded to "/bin/launchctl print system >/dev/null 2>&1; if /bin/launchctl print " & quoted form of service_target & " >/dev/null 2>&1; then exit 1; fi;"
set remove_daemon_plist to "/bin/rm -f " & quoted form of daemon_plist & ";"
set remove_agent_plist to "/bin/rm -f " & quoted form of agent_plist & ";"
set remove_service_exec to "/bin/rm -f " & quoted form of service_exec & " " & quoted form of temp_service_exec & ";"
set verify_removed to "if [ -e " & quoted form of daemon_plist & " ] || [ -L " & quoted form of daemon_plist & " ] || [ -e " & quoted form of agent_plist & " ] || [ -L " & quoted form of agent_plist & " ] || [ -e " & quoted form of service_exec & " ] || [ -L " & quoted form of service_exec & " ] || [ -e " & quoted form of temp_service_exec & " ] || [ -L " & quoted form of temp_service_exec & " ]; then exit 1; fi;"

set sh to "set -e;" & reject_helper_dir_symlink & unload_service & verify_unloaded & remove_daemon_plist & remove_agent_plist & remove_service_exec & verify_removed
do shell script sh with prompt "RustDesk wants to unload daemon" with administrator privileges
