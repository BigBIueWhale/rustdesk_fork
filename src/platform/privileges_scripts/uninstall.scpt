set daemon_plist to "/Library/LaunchDaemons/com.carriez.RustDesk_service.plist"
set agent_plist to "/Library/LaunchAgents/com.carriez.RustDesk_server.plist"
set service_label to "com.carriez.RustDesk_service"

set unload_service to "if /bin/launchctl list " & quoted form of service_label & " >/dev/null 2>&1; then /bin/launchctl unload -w " & quoted form of daemon_plist & "; fi;"
set verify_unloaded to "if /bin/launchctl list " & quoted form of service_label & " >/dev/null 2>&1; then exit 1; fi;"
set remove_daemon_plist to "/bin/rm -f " & quoted form of daemon_plist & ";"
set remove_agent_plist to "/bin/rm -f " & quoted form of agent_plist & ";"
set verify_removed to "if [ -e " & quoted form of daemon_plist & " ] || [ -e " & quoted form of agent_plist & " ]; then exit 1; fi;"

set sh to "set -e;" & unload_service & verify_unloaded & remove_daemon_plist & remove_agent_plist & verify_removed
do shell script sh with prompt "RustDesk wants to unload daemon" with administrator privileges
