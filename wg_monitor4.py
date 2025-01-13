import subprocess
import time
import requests
from datetime import datetime, timedelta
import json
import os

# Configuration
WG_INTERFACE = "wg0"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1265881891928539197/r0wJHOEHLqms7KXpUo9WdSRhIK_J0L10OE12A_BDo7Lzs9m4O0IocAy1BFUhsN1RrUAO"
CHECK_INTERVAL = 30
INACTIVE_THRESHOLD = 210  # Consider inactive after 3 and a half minutes without handshake. 3.5 seconds.
NOTIFICATION_TIMEOUT = 300  # Stop sending inactive notifications after 5 minutes

# Define base directory and config file path
BASE_DIR = "/opt/wireguard-monitor"  # Changed to match your service directory
PEER_NAMES_FILE = os.path.join(BASE_DIR, "wireguard_peer_names.json")  # Changed back to original filename

class PeerNameManager:
    def __init__(self):
        self.filename = PEER_NAMES_FILE
        self.peer_names = self.load_peer_names()
        print(f"Loaded peer names from: {self.filename}")
        print(f"Current peer names: {self.peer_names}")  # Debug line

    def load_peer_names(self):
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    print(f"Successfully loaded peer names: {data}")  # Debug line
                    return data
        except Exception as e:
            print(f"Error loading peer names file {self.filename}: {e}")
        return {}

    def get_name(self, public_key):
        name = self.peer_names.get(public_key)
        if name:
            return name
        return "Unknown Client"

class WireGuardPeer:
    def __init__(self, public_key, last_handshake, friendly_name=None):
        self.public_key = public_key
        self.last_handshake = last_handshake
        self.friendly_name = friendly_name
        self.last_known_handshake = None
        self.notified_inactive = False
        self.first_inactive_time = None
    
    def check_status(self, current_handshake, current_time):
        # First time seeing this peer
        if self.last_known_handshake is None:
            self.last_known_handshake = current_handshake
            # Only report active if we see a valid handshake (not 0)
            if current_handshake > 0:
                return "active"
            return None
            
        # New handshake detected (timestamp increased)
        if current_handshake > self.last_known_handshake:
            self.last_known_handshake = current_handshake
            self.notified_inactive = False
            self.first_inactive_time = None
            # Don't notify if previous handshake was 0 (first real handshake)
            if self.last_known_handshake > 0:
                return "handshake"
            return None
            
        # Check for inactivity
        if current_handshake > 0:  # Only check inactivity if we've ever had a handshake
            time_since_handshake = current_time - current_handshake
            if time_since_handshake >= INACTIVE_THRESHOLD:
                if not self.notified_inactive:
                    self.notified_inactive = True
                    self.first_inactive_time = current_time
                    return "inactive"
                elif self.first_inactive_time is not None:
                    if current_time - self.first_inactive_time >= NOTIFICATION_TIMEOUT:
                        return "timeout"
        return None

def get_wg_peers(peer_manager):
    try:
        result = subprocess.run(
            ["sudo", "wg", "show", WG_INTERFACE, "dump"],
            stdout=subprocess.PIPE,
            text=True,
            check=True
        )
        
        peers = {}
        lines = result.stdout.strip().split("\n")
        if not lines or lines[0] == '':
            return peers
            
        peer_lines = lines[1:] if len(lines) > 1 and not lines[0].startswith('peer') else lines
        
        for line in peer_lines:
            fields = line.split("\t")
            if len(fields) >= 5:
                public_key = fields[0]
                try:
                    last_handshake = int(fields[4])
                    friendly_name = peer_manager.get_name(public_key)
                    peers[public_key] = WireGuardPeer(public_key, last_handshake, friendly_name)
                except ValueError:
                    print(f"Invalid handshake time for peer {public_key}")
                    continue
        return peers
    except subprocess.CalledProcessError as e:
        print(f"Error running 'wg show': {e}")
        return {}
    except Exception as e:
        print(f"Unexpected error while getting peers: {e}")
        return {}

def send_discord_notification(message):
    payload = {
        "content": message,
        "allowed_mentions": {"parse": []}
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code == 204:
            print(f"Notification sent: {message}")
        else:
            print(f"Failed to send notification: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord notification: {e}")

def format_time(timestamp):
    if timestamp == 0:
        return "never"
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def format_peer_info(peer):
    name_info = f"Name: {peer.friendly_name}" if peer.friendly_name != "Unknown Client" else "Unnamed Client"
    return f"{name_info}\nPublic Key: `{peer.public_key}`"

def monitor_connections():
    peer_manager = PeerNameManager()  # Removed the filename parameter
    known_peers = {}
    print(f"Monitoring WireGuard interface '{WG_INTERFACE}' for handshake activity...")
    
    while True:
        try:
            current_time = time.time()
            current_peers = get_wg_peers(peer_manager)
            
            # Check existing peers for handshake changes
            for public_key, peer in current_peers.items():
                old_peer = known_peers.get(public_key)
                
                if old_peer is None:
                    # New peer detected
                    last_handshake_str = "never" if peer.last_handshake == 0 else format_time(peer.last_handshake)
                    send_discord_notification(
                        f"✨ New peer detected on '{WG_INTERFACE}'\n"
                        f"{format_peer_info(peer)}\n"
                        f"Last handshake: {last_handshake_str}"
                    )
                else:
                    # Copy over the state from old peer
                    peer.last_known_handshake = old_peer.last_known_handshake
                    peer.notified_inactive = old_peer.notified_inactive
                    peer.first_inactive_time = old_peer.first_inactive_time
                    
                    # Check for status changes
                    status = peer.check_status(peer.last_handshake, current_time)
                    if status == "inactive":
                        send_discord_notification(
                            f"🔴 No recent handshakes on '{WG_INTERFACE}'\n"
                            f"{format_peer_info(peer)}\n"
                            f"Last handshake: {format_time(peer.last_handshake)}"
                        )
                    elif status == "handshake":
                        send_discord_notification(
                            f"🟢 New handshake on '{WG_INTERFACE}'\n"
                            f"{format_peer_info(peer)}\n"
                            f"Handshake time: {format_time(peer.last_handshake)}"
                        )
            
            # Check for removed peers
            removed_peers = set(known_peers.keys()) - set(current_peers.keys())
            for public_key in removed_peers:
                peer = known_peers[public_key]
                send_discord_notification(
                    f"❌ Peer removed from '{WG_INTERFACE}'\n"
                    f"{format_peer_info(peer)}"
                )
            
            known_peers = current_peers.copy()
            time.sleep(CHECK_INTERVAL)
            
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            break
        except Exception as e:
            print(f"Error during monitoring: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    monitor_connections()
