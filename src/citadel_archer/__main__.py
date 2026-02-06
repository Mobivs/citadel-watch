# PRD: Main Entry Point - Desktop Application
# Reference: docs/PRD.md v0.2.3
#
# IMPORTANT: Citadel Archer is a DESKTOP APPLICATION, NOT a web app.
# Uses Edge in app mode (native-looking window) with embedded FastAPI backend.
#
# This is the main entry point. By default, launches the desktop app.
# Use --backend-only for development/testing (backend without GUI).

import sys
import argparse

from .core import get_audit_logger, EventType, EventSeverity


def main():
    """
    Main entry point for Citadel Archer.

    PRD: "pywebview (native wrapper)" - Desktop application, not web app.
    """
    parser = argparse.ArgumentParser(
        description="Citadel Archer - AI-centric defensive security DESKTOP application (Windows)",
        epilog="For more information, see docs/PRD.md"
    )

    parser.add_argument(
        "--backend-only",
        action="store_true",
        help="Run backend API server only (for development/testing, no GUI)"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Backend host (only with --backend-only, default: 127.0.0.1)"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Backend port (only with --backend-only, default: 8000)"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Citadel Archer v0.2.3 (Phase 1 - Foundation)"
    )

    args = parser.parse_args()

    # Log startup
    get_audit_logger().log_event(
        event_type=EventType.SYSTEM_START,
        severity=EventSeverity.INFO,
        message="Citadel Archer starting",
        details={
            "version": "0.2.3",
            "mode": "backend-only" if args.backend_only else "desktop"
        }
    )

    if args.backend_only:
        # Development mode: Backend only (no GUI)
        print("=" * 60)
        print("  ⚠️  DEVELOPMENT MODE: Backend Only (No GUI)")
        print("=" * 60)
        print()
        print("  This mode is for development/testing.")
        print("  For normal use, run without --backend-only to launch desktop app.")
        print()
        print(f"  Starting API server on {args.host}:{args.port}...")
        print("  Press Ctrl+C to stop")
        print("=" * 60)
        print()

        from .api.main import start_api_server

        try:
            start_api_server(host=args.host, port=args.port)
        except KeyboardInterrupt:
            print("\n\nShutting down backend...")
            get_audit_logger().log_event(
                event_type=EventType.SYSTEM_STOP,
                severity=EventSeverity.INFO,
                message="Citadel Archer backend stopped (user interrupt)"
            )
        except Exception as e:
            print(f"\n\nError: {str(e)}")
            get_audit_logger().log_event(
                event_type=EventType.SYSTEM_STOP,
                severity=EventSeverity.CRITICAL,
                message=f"Citadel Archer backend crashed: {str(e)}"
            )
            sys.exit(1)
    else:
        # Normal mode: Desktop application with embedded backend
        # No external GUI framework needed - uses subprocess + Edge app mode
        from .desktop import CitadelDesktopApp

        try:
            app = CitadelDesktopApp()
            app.run()
        except KeyboardInterrupt:
            print("\n\nShutdown signal received...")
        except Exception as e:
            print(f"\n\n❌ Error: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
