# WireGuard-handshake-detect
This is a WireGuard Handshake Detection python script that checks for a new handshake happens and when the handshake has expired/disconnected.
You must make a folder on your Linux machine in /opt/ and call the folder /opt/wireguard. Move these 2 files from the repo in there.

Next, you need to make a service to run these files. I made my service in /etc/systemd/system/ and made another service folder called /etc/systemd/system/wireguard-monitor.service. The code for this service will be in the repo. You will also need to make sure the python script can be executable.

In the JSON File, you will need to put your clients key in the first quote marks, and the client name in the second quote marks. When a client connects, both the key and client name will get displayed. If you don't want the client key to show, you can modify the code as needed. For my personal use, I left it in. Also, the detect rate is delayed on purpose because since different people will have their persistent key rates set at various times, the code has a longer "time out" notification period. Again any code line of code can be adjusted to suit the situation needed. Otherwise, this is should work well. 
