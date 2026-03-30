from __future__ import annotations

from ingestion.detectors.ssh_bruteforce import SSHBruteForceDetector


def build_detector(args):
    if args.detect_command == "ssh-bruteforce":
        return SSHBruteForceDetector(
            log_path=args.log_file,
            threshold=args.threshold,
            window_seconds=args.window,
            cooldown_seconds=args.cooldown,
            poll_interval=args.poll_interval,
            hostname=args.hostname,
            start_at_end=not args.from_start,
        )
    raise ValueError(f"Unsupported detector: {args.detect_command!r}")
