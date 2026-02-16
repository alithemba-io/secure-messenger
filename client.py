"""
client.py — SecureMsg terminal client (BitchX/IRC-style UI).

Layout:
  ┌─[SecureMsg]────────────────────────────────────────[🔒 E2E]─┐
  │ Channels        │ #ops                    │ Online           │
  │ ─────────────── │ ─────────────────────── │ ──────────────── │
  │ #general        │ [09:41] <ghost> hey     │ * ghost          │
  │ #ops ◄          │ [09:41] <you> yo        │   nighthawk      │
  │                 │                         │                  │
  ├─────────────────┴─────────────────────────┴──────────────────┤
  │ > type a message or /command                                 │
  ├──────────────────────────────────────────────────────────────┤
  │ /create #name  /invite <user>  /join <token>  /leave  /quit  │
  └──────────────────────────────────────────────────────────────┘

Commands:
  /create #name      Create a new invite-only channel
  /invite <user>     Invite a registered user to current channel
  /join <token>      Accept an invite token
  /leave             Leave the current channel
  /quit              Disconnect and exit

Usage:
  python client.py [SERVER_URL]
  e.g.  python client.py http://localhost:5000
        python client.py https://abc123.ngrok.io
"""

import asyncio
import sys
import os
import getpass
from datetime import datetime
from typing import Optional

import socketio as sio_lib
from dotenv import load_dotenv
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Input, Label, ListItem, ListView, RichLog, Static,
)
from textual.reactive import reactive

import crypto

load_dotenv()

SERVER_URL = (
    sys.argv[1] if len(sys.argv) > 1
    else os.environ.get("SERVER_URL", "http://localhost:5000")
)



# ---------------------------------------------------------------------------
# Textual custom messages (used to push socket events into the UI)
# ---------------------------------------------------------------------------

from textual.message import Message as TxMessage


class ServerMessage(TxMessage):
    """A chat message arrived from the server."""
    def __init__(self, channel_id: str, sender: str, text: str, ts: str) -> None:
        super().__init__()
        self.channel_id = channel_id
        self.sender     = text and sender
        self.text       = text
        self.ts         = ts


class StatusLine(TxMessage):
    """Update the bottom status bar."""
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class ChannelListUpdate(TxMessage):
    """Channel list changed."""
    def __init__(self, channels: list[dict]) -> None:
        super().__init__()
        self.channels = channels


class OnlineListUpdate(TxMessage):
    """Online user list for current channel changed."""
    def __init__(self, users: list[str]) -> None:
        super().__init__()
        self.users = users


class InviteReady(TxMessage):
    """Invite token generated — display it to the user."""
    def __init__(self, token: str, invitee: str) -> None:
        super().__init__()
        self.token   = token
        self.invitee = invitee


class PeerPublicKey(TxMessage):
    """Server returned a peer's public key — complete the invite."""
    def __init__(self, username: str, user_id: str, public_key: str) -> None:
        super().__init__()
        self.username   = username
        self.user_id    = user_id
        self.public_key = public_key


# ---------------------------------------------------------------------------
# Login / Register screen
# ---------------------------------------------------------------------------

class LoginScreen(App):
    """
    Blocking prompts in the terminal before launching the Textual UI.
    We keep this dead-simple (plain input) so we don't need nested Textual apps.
    """

    CSS = ""  # not used — this runs before the TUI

    @staticmethod
    def run_login() -> tuple[str, str, str, str]:
        """
        Returns (token, user_id, username, password).
        password is kept in memory only — needed to unlock local key store.
        """
        print("\n╔══════════════════════════════════╗")
        print("║       SecureMsg  •  E2E Chat      ║")
        print("╚══════════════════════════════════╝\n")
        print(f"Server: {SERVER_URL}\n")

        while True:
            choice = input("  [1] Login    [2] Register  > ").strip()
            if choice in ("1", "2"):
                break

        username = input("  Username : ").strip()
        password = getpass.getpass("  Password : ")

        if choice == "2":
            password2 = getpass.getpass("  Confirm  : ")
            if password != password2:
                print("Passwords do not match.")
                sys.exit(1)

        # Generate or load identity keypair
        if choice == "2" or not crypto.identity_exists():
            print("  Generating identity keypair…", end=" ", flush=True)
            public_key = crypto.generate_and_save_identity(password)
            print("done.")
        else:
            try:
                priv = crypto.load_identity(password)
                public_key = crypto.get_public_key_b64(priv)
            except ValueError as exc:
                print(f"  Error: {exc}")
                sys.exit(1)

        endpoint = "/register" if choice == "2" else "/login"

        import requests  # sync is fine here (pre-UI)
        try:
            resp = requests.post(
                SERVER_URL + endpoint,
                json={"username": username, "password": password, "public_key": public_key},
                timeout=10,
            )
        except requests.exceptions.ConnectionError:
            print(f"\n[ERROR] Cannot connect to {SERVER_URL}")
            sys.exit(1)

        data = resp.json()
        if "error" in data:
            print(f"\n[ERROR] {data['error']}")
            sys.exit(1)

        print(f"\n  Logged in as: {data['username']}\n")
        return data["token"], data["user_id"], data["username"], password


# ---------------------------------------------------------------------------
# Main TUI  (ChatApp)
# ---------------------------------------------------------------------------

class ChatApp(App):
    """IRC/BitchX-style terminal chat client."""

    TITLE = "SecureMsg"
    CSS = """
    Screen {
        layout: vertical;
    }

    #main-row {
        height: 1fr;
        layout: horizontal;
    }

    #channel-panel {
        width: 18;
        border-right: solid $primary-darken-2;
        padding: 0 1;
        overflow-y: auto;
    }

    #channel-panel Label {
        color: $text-muted;
        text-style: bold;
    }

    #channel-panel ListView {
        border: none;
        height: auto;
    }

    #message-area {
        width: 1fr;
        border-right: solid $primary-darken-2;
        padding: 0 1;
        overflow-y: auto;
    }

    #user-panel {
        width: 16;
        padding: 0 1;
        overflow-y: auto;
    }

    #user-panel Label {
        color: $text-muted;
        text-style: bold;
    }

    #channel-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
    }

    #input-row {
        height: 3;
        border-top: solid $primary-darken-2;
        layout: horizontal;
    }

    #prompt {
        width: 3;
        padding: 1 0 0 1;
        color: $accent;
    }

    #msg-input {
        width: 1fr;
        border: none;
    }

    #status-bar {
        height: 1;
        background: $primary-darken-3;
        color: $text-muted;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("escape", "blur_input", "Blur input", show=False),
    ]

    current_channel_id: reactive[Optional[str]] = reactive(None)
    current_channel_name: reactive[str] = reactive("")

    def __init__(
        self,
        token: str,
        user_id: str,
        username: str,
        password: str,
    ) -> None:
        super().__init__()
        self._token    = token
        self._user_id  = user_id
        self._username = username
        self._password = password

        self._private_key = crypto.load_identity(password)

        # channel_id → channel_name
        self._channels: dict[str, str] = {}
        # channel_id → [online usernames]
        self._online: dict[str, list[str]] = {}
        # pending invite: waiting for peer public key
        self._pending_invite: Optional[dict] = None

        self.sio = sio_lib.Client(logger=False, engineio_logger=False)
        self._register_socket_events()

    # ------------------------------------------------------------------
    # Compose UI
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-row"):
            with Vertical(id="channel-panel"):
                yield Label("CHANNELS")
                yield ListView(id="channel-list")
            with Vertical(id="message-area"):
                yield Static(id="channel-title", markup=False)
                yield RichLog(id="messages", highlight=True, markup=True,
                              auto_scroll=True, wrap=True)
            with Vertical(id="user-panel"):
                yield Label("ONLINE")
                yield RichLog(id="user-list", highlight=False, markup=False,
                              auto_scroll=False)
        with Horizontal(id="input-row"):
            yield Static("> ", id="prompt")
            yield Input(placeholder="type a message or /command…", id="msg-input")
        yield Static(
            "/create #name  /invite <user>  /join <token>  /leave  /quit",
            id="status-bar",
        )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.run_worker(self._connect_socket(), exclusive=True, thread=False)

    async def _connect_socket(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sync_connect)

    def _sync_connect(self) -> None:
        try:
            self.sio.connect(
                SERVER_URL,
                auth={"token": self._token},
                transports=["websocket", "polling"],
                wait_timeout=10,
            )
        except Exception as exc:
            self.call_from_thread(
                self._sys_msg,
                f"[red]Connection failed: {exc}[/red]\n"
                "  Check that the server is running and reachable.",
            )
            return
        self.sio.emit("list_my_channels")

    # ------------------------------------------------------------------
    # Socket event registration (called in __init__, before UI)
    # ------------------------------------------------------------------

    def _register_socket_events(self) -> None:
        sio = self.sio

        @sio.on("connected")
        def _on_connected(data):
            self.call_from_thread(
                self._sys_msg, f"Connected to {SERVER_URL} as {data['username']}"
            )

        @sio.on("my_channels")
        def _on_my_channels(data):
            channels = data.get("channels", [])
            self.call_from_thread(self._update_channel_list, channels)

        @sio.on("channel_created")
        def _on_channel_created(data):
            cid  = data["channel_id"]
            name = data["name"]
            # Store the pending channel key now that we have the real channel_id
            if hasattr(self, "_pending_channel_key") and self._pending_channel_key:
                crypto.store_channel_key(cid, self._pending_channel_key, self._password)
                self._pending_channel_key = None
            self._channels[cid] = name
            self.call_from_thread(self._update_channel_list,
                                  [{"id": k, "name": v} for k, v in self._channels.items()])
            self.call_from_thread(self._sys_msg, f"Channel #{name} created.")
            # Auto-join the new channel
            self.sio.emit("join_channel", {"channel_id": cid})

        @sio.on("channel_joined")
        def _on_channel_joined(data):
            cid  = data["channel_id"]
            name = data["channel_name"]
            enc_key = data.get("encrypted_key")
            history = data.get("history", [])
            online  = data.get("online_users", [])

            # Decrypt and store channel key locally
            if enc_key:
                try:
                    raw_key = crypto.decrypt_from_peer(
                        enc_key, self._private_key,
                        crypto.get_public_key_b64(self._private_key),
                    )
                    crypto.store_channel_key(cid, raw_key, self._password)
                except Exception:
                    # Key already stored locally
                    pass

            self._channels[cid] = name
            self._online[cid]   = online

            self.call_from_thread(self._switch_to_channel, cid, name, history, online)

        @sio.on("invite_accepted")
        def _on_invite_accepted(data):
            cid            = data["channel_id"]
            cname          = data["channel_name"]
            enc_key        = data["encrypted_key"]
            inviter_pubkey = data["inviter_pubkey"]
            try:
                raw_key = crypto.decrypt_from_peer(
                    enc_key, self._private_key, inviter_pubkey,
                )
                crypto.store_channel_key(cid, raw_key, self._password)
                self.call_from_thread(
                    self._sys_msg,
                    f"Joined #{cname}! Channel key decrypted. Use /join to enter."
                )
                # Auto-join the room
                self.sio.emit("join_channel", {"channel_id": cid})
            except Exception as exc:
                self.call_from_thread(
                    self._sys_msg, f"[red]Failed to decrypt channel key: {exc}[/red]"
                )

        @sio.on("new_message")
        def _on_new_message(data):
            cid  = data["channel_id"]
            enc  = data["encrypted_content"]
            ts   = data["created_at"]
            sender = data["sender_name"]
            key = crypto.get_channel_key(cid, self._password)
            if key:
                try:
                    plaintext = crypto.decrypt_message(enc, key)
                except Exception:
                    plaintext = "[unable to decrypt]"
            else:
                plaintext = "[no key — not in channel]"
            self.call_from_thread(self.post_message,
                                  ServerMessage(cid, sender, plaintext, ts))

        @sio.on("user_joined")
        def _on_user_joined(data):
            uname = data["username"]
            # Add to online list for all channels this user might be in
            for cid in self._online:
                if uname not in self._online[cid]:
                    self._online[cid].append(uname)
            self.call_from_thread(self._refresh_online)
            self.call_from_thread(self._sys_msg, f"→ {uname} joined")

        @sio.on("user_left")
        def _on_user_left(data):
            uname = data["username"]
            for cid in self._online:
                self._online[cid] = [u for u in self._online[cid] if u != uname]
            self.call_from_thread(self._refresh_online)
            self.call_from_thread(self._sys_msg, f"← {uname} left")

        @sio.on("peer_public_key")
        def _on_peer_public_key(data):
            self.call_from_thread(self.post_message,
                                  PeerPublicKey(data["username"], data["user_id"],
                                                data["public_key"]))

        @sio.on("invite_ready")
        def _on_invite_ready(data):
            self.call_from_thread(self.post_message,
                                  InviteReady(data["token"], data["invitee"]))

        @sio.on("error")
        def _on_error(data):
            self.call_from_thread(self._sys_msg,
                                  f"[red]Server: {data.get('message', '?')}[/red]")

        @sio.on("disconnect")
        def _on_disconnect():
            self.call_from_thread(self._sys_msg,
                                  "[yellow]Disconnected from server.[/yellow]")

    # ------------------------------------------------------------------
    # Message handlers (run in UI thread via post_message)
    # ------------------------------------------------------------------

    def on_server_message(self, event: ServerMessage) -> None:
        if event.channel_id != self.current_channel_id:
            return
        log = self.query_one("#messages", RichLog)
        ts  = _fmt_time(event.ts)
        me  = self._username
        col = "bold cyan" if event.sender == me else "bold green"
        log.write(f"[dim]{ts}[/dim] [{col}]<{event.sender}>[/{col}] {event.text}")

    def on_invite_ready(self, event: InviteReady) -> None:
        self._sys_msg(
            f"[green]Invite token for {event.invitee}:[/green]\n"
            f"  [bold yellow]{event.token}[/bold yellow]\n"
            f"  Send this token to {event.invitee}. It expires in 48 hours."
        )

    def on_peer_public_key(self, event: PeerPublicKey) -> None:
        """Got the invitee's public key — now encrypt the channel key for them."""
        if not self._pending_invite:
            return
        p = self._pending_invite
        if p["username"] != event.username:
            return

        cid = p["channel_id"]
        channel_key = crypto.get_channel_key(cid, self._password)
        if not channel_key:
            self._sys_msg("[red]Cannot find channel key locally. Try rejoining the channel.[/red]")
            self._pending_invite = None
            return

        try:
            encrypted_key = crypto.encrypt_for_peer(
                channel_key, self._private_key, event.public_key,
            )
        except Exception as exc:
            self._sys_msg(f"[red]Encryption error: {exc}[/red]")
            self._pending_invite = None
            return

        self.sio.emit("send_invite", {
            "channel_id":   cid,
            "invitee_id":   event.user_id,
            "encrypted_key": encrypted_key,
        })
        self._pending_invite = None

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.clear()
        if not raw:
            return

        if raw.startswith("/"):
            self._handle_command(raw)
        else:
            self._send_chat(raw)

    def _handle_command(self, raw: str) -> None:
        parts = raw.split(None, 1)
        cmd   = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "/quit":
            self.action_quit_app()

        elif cmd == "/create":
            name = arg.lstrip("#").strip()
            if not name:
                self._sys_msg("Usage: /create #channelname")
                return
            self._create_channel(name)

        elif cmd == "/invite":
            if not self.current_channel_id:
                self._sys_msg("Join a channel first.")
                return
            if not arg:
                self._sys_msg("Usage: /invite <username>")
                return
            self._invite_user(arg)

        elif cmd == "/join":
            if not arg:
                self._sys_msg("Usage: /join <invite-token>")
                return
            self.sio.emit("accept_invite", {"token": arg})

        elif cmd == "/leave":
            if not self.current_channel_id:
                self._sys_msg("Not in a channel.")
                return
            self.sio.emit("leave_channel", {"channel_id": self.current_channel_id})
            self.current_channel_id   = None
            self.current_channel_name = ""
            self.query_one("#channel-title", Static).update("")
            self.query_one("#messages", RichLog).clear()
            self.query_one("#user-list", RichLog).clear()

        else:
            self._sys_msg(f"Unknown command: {cmd}")

    def _send_chat(self, text: str) -> None:
        cid = self.current_channel_id
        if not cid:
            self._sys_msg("Join a channel first (/join <token> or click a channel).")
            return
        key = crypto.get_channel_key(cid, self._password)
        if not key:
            self._sys_msg("[red]No channel key — cannot encrypt message.[/red]")
            return
        enc = crypto.encrypt_message(text, key)
        self.sio.emit("send_message", {
            "channel_id":        cid,
            "encrypted_content": enc,
        })

    def _create_channel(self, name: str) -> None:
        channel_key = crypto.generate_channel_key()
        my_pub      = crypto.get_public_key_b64(self._private_key)

        # Self-encrypt: ECDH(my_priv, my_pub) — deterministic from own key
        try:
            enc_key = crypto.encrypt_for_peer(channel_key, self._private_key, my_pub)
        except Exception as exc:
            self._sys_msg(f"[red]Key encryption error: {exc}[/red]")
            return

        # Store locally before sending (so we have it when channel_joined arrives)
        # We'll get the channel_id from the server response and store then.
        # For now, store with a placeholder — overwrite on channel_joined.
        self._pending_channel_key = channel_key

        self.sio.emit("create_channel", {"name": name, "encrypted_key": enc_key})

    def _invite_user(self, username: str) -> None:
        self._pending_invite = {
            "channel_id": self.current_channel_id,
            "username":   username,
        }
        self.sio.emit("get_public_key", {"username": username})

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def _sys_msg(self, text: str) -> None:
        """Print a system message in the current message log."""
        log = self.query_one("#messages", RichLog)
        log.write(f"[dim]──[/dim] {text}")

    def _update_channel_list(self, channels: list[dict]) -> None:
        for c in channels:
            self._channels[c["id"]] = c["name"]
        lv = self.query_one("#channel-list", ListView)
        lv.clear()
        for c in channels:
            active = "◄ " if c["id"] == self.current_channel_id else "  "
            lv.append(ListItem(Label(f"{active}#{c['name']}"), id=f"ch-{c['id']}"))

    def _switch_to_channel(
        self,
        channel_id: str,
        channel_name: str,
        history: list[dict],
        online_users: list[str],
    ) -> None:
        self.current_channel_id   = channel_id
        self.current_channel_name = channel_name
        self._online[channel_id]  = online_users

        title = self.query_one("#channel-title", Static)
        title.update(f"#{channel_name}")

        log = self.query_one("#messages", RichLog)
        log.clear()

        key = crypto.get_channel_key(channel_id, self._password)
        for msg in history:
            ts   = _fmt_time(msg["created_at"])
            sndr = msg["sender_name"]
            enc  = msg["encrypted_content"]
            if key:
                try:
                    text = crypto.decrypt_message(enc, key)
                except Exception:
                    text = "[unable to decrypt]"
            else:
                text = "[encrypted]"
            col = "bold cyan" if sndr == self._username else "bold green"
            log.write(f"[dim]{ts}[/dim] [{col}]<{sndr}>[/{col}] {text}")

        self._refresh_online()
        self._update_channel_list(
            [{"id": k, "name": v} for k, v in self._channels.items()]
        )

    def _refresh_online(self) -> None:
        ul = self.query_one("#user-list", RichLog)
        ul.clear()
        users = self._online.get(self.current_channel_id or "", [])
        for u in users:
            prefix = "* " if u == self._username else "  "
            ul.write(f"{prefix}{u}")

    # ------------------------------------------------------------------
    # ListView click → join channel
    # ------------------------------------------------------------------

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("ch-"):
            channel_id = item_id[3:]
            self.sio.emit("join_channel", {"channel_id": channel_id})

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_quit_app(self) -> None:
        try:
            self.sio.disconnect()
        except Exception:
            pass
        self.exit()

    def action_blur_input(self) -> None:
        self.query_one("#msg-input", Input).blur()

    # ------------------------------------------------------------------
    # Watch reactive
    # ------------------------------------------------------------------

    def watch_current_channel_id(self) -> None:
        # Refresh channel list to update the ◄ marker
        self._update_channel_list(
            [{"id": k, "name": v} for k, v in self._channels.items()]
        )

    # ------------------------------------------------------------------
    # Store channel key when channel_created fires
    # ------------------------------------------------------------------

    def on_channel_created(self, _event) -> None:
        pass  # handled in socket callback directly


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_time(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%H:%M")
    except Exception:
        return "??:??"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Step 1: auth (blocking, plain terminal)
    token, user_id, username, password = LoginScreen.run_login()

    # Step 2: launch TUI
    app = ChatApp(token=token, user_id=user_id, username=username, password=password)
    app.run()
