set daemon_plist to "/Library/LaunchDaemons/com.carriez.RustDesk_service.plist"
set agent_plist to "/Library/LaunchAgents/com.carriez.RustDesk_server.plist"

set sh1 to "/bin/launchctl unload -w " & quoted form of daemon_plist & " || true;"
set sh2 to "/bin/rm -f " & quoted form of daemon_plist & ";"
set sh3 to "/bin/rm -f " & quoted form of agent_plist & ";"

set sh to sh1 & sh2 & sh3
do shell script sh with prompt "RustDesk wants to unload daemon" with administrator privileges
