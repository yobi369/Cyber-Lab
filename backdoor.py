"""Compatibility entry point for the safe Authorized Administration Lab.

The historical filename is retained to avoid a broken entry point. No
backdoor, remote shell, network connection, or command-execution capability
is implemented here.
"""
from admin_lab import main


if __name__ == "__main__":
    raise SystemExit(main())
