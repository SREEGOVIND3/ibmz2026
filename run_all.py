"""
ConsentShield notebook runner with live terminal output.

Put this file in the ConsentShield project root:
    consentshield/
      run_all.py
      data/
      notebooks/
        01_ai4privacy_exploration.ipynb
        02_synthetic_payload_generation.ipynb
        03_train_field_classifier.ipynb
        04_evaluate_gliner.ipynb
        05_ablation_study.ipynb

Run:
    python -u run_all.py
    python -u run_all.py --list
    python -u run_all.py --workers 2
    python -u run_all.py --only 03_train_field_classifier

Install in the SAME Python environment used to run this script:
    python -m pip install papermill ipykernel
"""

from __future__ import annotations

import argparse
import concurrent.futures
import subprocess
import sys
import threading
import time
from pathlib import Path

NOTEBOOKS = [
    "01_ai4privacy_exploration.ipynb",
    "02_synthetic_payload_generation.ipynb",
    "03_train_field_classifier.ipynb",
    "04_evaluate_gliner.ipynb",
    "05_ablation_study.ipynb",
]
PRINT_LOCK = threading.Lock()


def log(message: str = "") -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def find_project_root() -> Path:
    """Prefer the script's location; fall back to current directory/parents."""
    starts = [Path(__file__).resolve().parent, Path.cwd().resolve()]
    seen = set()
    for start in starts:
        for candidate in (start, *start.parents):
            if candidate in seen:
                continue
            seen.add(candidate)
            if (candidate / "notebooks").is_dir() and (candidate / "data").is_dir():
                return candidate
    # Allow an early diagnostic if the expected project folders are absent.
    return Path(__file__).resolve().parent


def run_one(root: Path, notebook: Path, output_dir: Path) -> tuple[str, bool, float, str]:
    started = time.perf_counter()
    output_path = output_dir / f"completed_{notebook.stem}.ipynb"
    log_path = output_dir / f"{notebook.stem}.log"
    command = [
        sys.executable, "-u", "-m", "papermill",
        str(notebook.resolve()),
        str(output_path.resolve()),
        "--kernel", "python3",
        "--log-output",
    ]

    log(f"[START] {notebook.name}")
    with log_path.open("w", encoding="utf-8", errors="replace") as logfile:
        logfile.write(f"Project root: {root}\nNotebook: {notebook}\nCommand: {' '.join(command)}\n\n")
        logfile.flush()
        try:
            process = subprocess.Popen(
                command,
                cwd=str(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                logfile.write(line)
                logfile.flush()
                # Prefix notebook messages so simultaneous runs remain readable.
                with PRINT_LOCK:
                    print(f"[{notebook.stem}] {line}", end="", flush=True)
            return_code = process.wait()
            elapsed = time.perf_counter() - started
            if return_code == 0:
                message = f"Saved: {output_path}"
                log(f"[SUCCESS] {notebook.name} ({elapsed:.1f}s) — {message}")
                return notebook.name, True, elapsed, message
            message = f"Exit code {return_code}; inspect {log_path}"
            log(f"[FAILED] {notebook.name} ({elapsed:.1f}s) — {message}")
            return notebook.name, False, elapsed, message
        except Exception as exc:
            logfile.write(f"\nRunner exception: {type(exc).__name__}: {exc}\n")
            logfile.flush()
            elapsed = time.perf_counter() - started
            message = f"{type(exc).__name__}: {exc}; inspect {log_path}"
            log(f"[FAILED] {notebook.name} — {message}")
            return notebook.name, False, elapsed, message


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ConsentShield notebooks concurrently.")
    parser.add_argument(
        "--workers", type=int, default=2,
        help="Maximum notebooks to run simultaneously (default: 2).",
    )
    parser.add_argument(
        "--only", nargs="+", metavar="NOTEBOOK_STEM",
        help="Run selected notebook stems, e.g. --only 03_train_field_classifier 05_ablation_study.",
    )
    parser.add_argument("--list", action="store_true", help="List notebook paths and exit.")
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    root = find_project_root()
    notebook_dir = root / "notebooks"
    configured = [notebook_dir / name for name in NOTEBOOKS]

    log(f"ConsentShield notebook runner | Python: {sys.executable}")
    log(f"Project root: {root}")
    log(f"Notebook folder: {notebook_dir}")

    if args.list:
        for path in configured:
            log(f"{'[FOUND]  ' if path.is_file() else '[MISSING]'} {path}")
        return 0

    if args.only:
        requested = {name.removesuffix(".ipynb") for name in args.only}
        known = {Path(name).stem for name in NOTEBOOKS}
        unknown = requested - known
        if unknown:
            parser.error("Unknown notebook stem(s): " + ", ".join(sorted(unknown)))
        configured = [path for path in configured if path.stem in requested]

    if not configured:
        log("ERROR: No notebooks selected.")
        return 2

    missing = [path for path in configured if not path.is_file()]
    if missing:
        log("\nERROR: These expected notebooks are missing:")
        for path in missing:
            log(f"  - {path}")
        log("\nCheck that the notebooks are inside the project's notebooks/ folder")
        log("and that the filenames match NOTEBOOKS at the top of run_all.py.")
        log("Run `python -u run_all.py --list` to see which files were found.")
        return 2

    try:
        import papermill  # noqa: F401
    except ImportError:
        log("\nERROR: Papermill is not installed in this Python environment.")
        log(f"Install it using this interpreter:\n  \"{sys.executable}\" -m pip install papermill ipykernel")
        return 2

    output_dir = root / "parallel_outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    log(f"Selected notebooks: {len(configured)}")
    log(f"Workers: {min(args.workers, len(configured))}")
    log(f"Output/log folder: {output_dir}")
    log("Notebook output will appear below as execution progresses.")
    log("Note: notebooks share data/models/results folders; don't run duplicate copies concurrently.\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, len(configured))) as pool:
        futures = {
            pool.submit(run_one, root, notebook, output_dir): notebook
            for notebook in configured
        }
        for future in concurrent.futures.as_completed(futures):
            notebook = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                log(f"[FAILED] Unexpected runner error for {notebook.name}: {exc}")
                results.append((notebook.name, False, 0.0, str(exc)))

    succeeded = sum(ok for _, ok, _, _ in results)
    failed = len(results) - succeeded
    log(f"\nFinished: {succeeded} succeeded, {failed} failed.")
    log(f"Executed notebooks and logs: {output_dir}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
