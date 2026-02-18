# PRD: Desktop Application - Main Entry Point
# Reference: docs/PRD.md v0.2.3, Section: Technical Architecture
#
# IMPORTANT: Citadel Archer is a DESKTOP APPLICATION, NOT a web app.
# This manages the entire application lifecycle:
# - Start FastAPI backend internally
# - Launch Guardian agents
# - Open Edge in app mode (looks like native window)
# - Handle shutdown and cleanup (kill all processes, no ghosts)

import webbrowser
import subprocess
import threading
import time
import sys
import signal
import atexit
import socket
import os
from pathlib import Path

from .api.main import app, file_monitor, process_monitor
import uvicorn
from .core import get_audit_logger, EventType, EventSeverity


class CitadelDesktopApp:
    """
    Desktop application using Edge in app mode.

    PRD: Desktop application with embedded backend and process management.
    Opens Edge in kiosk/app mode - looks like native window, no browser UI.
    """

    def __init__(self):
        self.backend_thread = None
        self.backend_server = None
        self.backend_started = False
        self.is_shutting_down = False
        self.edge_process = None  # Track Edge subprocess for window-close detection

        # Register cleanup handlers
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C and other termination signals."""
        print("\n⚠️  Shutdown signal received...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """
        Clean up all resources on shutdown.

        PRD: "Kill all processes before shutting down to avoid ghost processes"

        Stops:
        - Guardian file monitor
        - Guardian process monitor
        - FastAPI backend server
        - Any background threads
        """
        if self.is_shutting_down:
            return  # Already cleaning up

        self.is_shutting_down = True

        print("\n🧹 Cleaning up Citadel Archer...")

        # Stop Guardian agents
        if file_monitor and file_monitor.is_running:
            print("  ⏹️  Stopping file monitor...")
            file_monitor.stop()

        if process_monitor and process_monitor.is_running:
            print("  ⏹️  Stopping process monitor...")
            process_monitor.stop()

        # Stop backend server
        if self.backend_server:
            print("  ⏹️  Stopping backend server...")
            self.backend_server.should_exit = True

        # Log shutdown
        get_audit_logger().log_event(
            event_type=EventType.SYSTEM_STOP,
            severity=EventSeverity.INFO,
            message="Citadel Archer desktop application shutdown (clean exit)"
        )

        print("✅ Cleanup complete. All processes stopped.")

    @staticmethod
    def _is_port_in_use(port):
        """Check if a TCP port is already bound."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return False
            except OSError:
                return True

    @staticmethod
    def _kill_stale_server(port):
        """Find and kill a stale process holding the given port (Windows)."""
        try:
            # netstat to find the PID owning the port
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if f"127.0.0.1:{port}" in line and "LISTENING" in line:
                    pid = int(line.strip().split()[-1])
                    if pid == os.getpid():
                        continue  # Don't kill ourselves
                    print(f"  Found stale process PID {pid} on port {port}, terminating...")
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True, timeout=5
                    )
                    time.sleep(0.5)  # Give OS time to release the port
                    return True
        except Exception as e:
            print(f"  Warning: Could not clean stale process on port {port}: {e}")
        return False

    def start_backend(self):
        """Start FastAPI backend in background thread."""
        # Bind to 0.0.0.0 so remote agents can reach us over Tailscale/VPN.
        # Session-token auth + CORS origin allowlist protect against unauthorized access.
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="error",  # Reduce console noise
            access_log=False
        )
        self.backend_server = uvicorn.Server(config)

        # Mark backend as started
        self.backend_started = True

        # Run server (blocks until shutdown)
        self.backend_server.run()

    def wait_for_backend(self, max_wait=10):
        """Wait for backend to be ready."""
        import httpx

        start_time = time.time()
        while time.time() - start_time < max_wait:
            try:
                response = httpx.get("http://127.0.0.1:8000/api")
                if response.status_code == 200:
                    print("✅ Backend ready!")
                    return True
            except:
                time.sleep(0.5)

        print("❌ Backend failed to start within timeout")
        return False

    def _start_heartbeat_watchdog(self):
        """
        Monitor frontend heartbeat to detect window close.

        The frontend POSTs to /api/heartbeat every 5 seconds.
        If no heartbeat is received for 15 seconds after the first one,
        assume the user closed the window and trigger shutdown.
        """
        from .api.main import get_last_heartbeat

        def watchdog():
            # Wait for first heartbeat (window opened and loaded)
            while not self.is_shutting_down:
                if get_last_heartbeat() is not None:
                    break
                time.sleep(1)

            print("  Heartbeat watchdog active")

            # Monitor for heartbeat timeout
            grace_period = 15  # seconds

            while not self.is_shutting_down:
                last = get_last_heartbeat()
                if last is not None:
                    from datetime import datetime, timezone
                    elapsed = (datetime.now(timezone.utc) - last).total_seconds()
                    if elapsed > grace_period:
                        print(f"\n  No heartbeat for {elapsed:.0f}s — window closed.")
                        self.cleanup()
                        sys.exit(0)
                time.sleep(3)

        t = threading.Thread(target=watchdog, daemon=True)
        t.start()

    def open_app_window(self):
        """
        Open Edge in app mode (looks like native window).

        Windows 10/11 guaranteed to have Edge.
        App mode = no address bar, no tabs, looks like desktop app.
        Stores the process handle so we can detect when the user closes the window.
        """
        url = "http://127.0.0.1:8000"

        # Edge app mode command (Windows)
        edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

        # Try to launch Edge in app mode
        try:
            self.edge_process = subprocess.Popen([
                edge_path,
                f"--app={url}",
                "--window-size=1280,800",
                "--disable-features=TranslateUI",
                "--no-first-run",
                "--disk-cache-size=0",
                "--aggressive-cache-discard",
            ])
            print("✅ Desktop window opened!")
            return True
        except FileNotFoundError:
            # Edge not in default location, try webbrowser module
            print("⚠️  Edge not found at default location, using webbrowser...")
            webbrowser.open(url)
            return True

    def run(self):
        """
        Run Citadel Archer desktop application.

        PRD: Desktop application with embedded backend and process management.

        Lifecycle:
        1. Kill any stale backend on our port
        2. Start FastAPI backend in background thread (internal)
        3. Start Guardian agents (file & process monitoring)
        4. Wait for backend to be ready
        5. Open Edge in app mode (looks like native window)
        6. Monitor Edge process — auto-shutdown when window closes
        7. On close: cleanup ALL processes (no ghosts)
        """
        print("=" * 60)
        print("  🛡️  Citadel Archer Desktop v0.2.3")
        print("  Windows Desktop Application")
        print("=" * 60)
        print("  Philosophy: Proactive protection. Acts first, informs after.")
        print("=" * 60)
        print()

        # Kill stale backend if port is occupied
        if self._is_port_in_use(8000):
            print("⚠️  Port 8000 already in use — cleaning up stale server...")
            if not self._kill_stale_server(8000):
                print("❌ Could not free port 8000. Is another instance running?")
                sys.exit(1)
            if self._is_port_in_use(8000):
                print("❌ Port 8000 still in use after cleanup. Exiting.")
                sys.exit(1)
            print("✅ Port 8000 freed.")

        # Start backend in background thread
        print("🔧 Starting backend server...")
        self.backend_thread = threading.Thread(
            target=self.start_backend,
            daemon=True
        )
        self.backend_thread.start()

        # Wait for backend to be ready
        print("⏳ Waiting for backend to start...")
        if not self.wait_for_backend():
            print("❌ Failed to start backend. Exiting.")
            sys.exit(1)

        # Open app window
        print("🪟 Opening desktop window...")
        self.open_app_window()

        print("✅ Desktop application ready!")
        print("=" * 60)
        print()
        print("ℹ️  Close the window to stop Citadel Archer")
        print("   Or press Ctrl+C in this terminal")
        print()

        # Wait for shutdown signal.
        # Edge --app= exits immediately (hands off to main Edge process),
        # so we cannot use subprocess.poll() to detect window close.
        # Instead, we rely on:
        #   - Ctrl+C / SIGINT (signal handler triggers cleanup)
        #   - WebSocket disconnect watchdog (all clients gone for 30s)
        #   - Port cleanup on next startup (catches any ghost)
        self._start_heartbeat_watchdog()

        try:
            while not self.is_shutting_down:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        print("\n🛑 Desktop application closing...")


def main():
    """Entry point for desktop application."""
    app = CitadelDesktopApp()
    app.run()


if __name__ == "__main__":
    main()
