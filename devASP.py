import os
import shutil
import subprocess
import sys
from pathlib import Path

# Enable ANSI colors on Windows terminals
if os.name == "nt":
    os.system("")


class Color:
    """ANSI color codes for terminal output formatting."""

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_status(message: str, color: str = Color.OKBLUE):
    print(f"\n{color}{Color.BOLD}[*] {message}{Color.ENDC}")


def run_check(
    command: list[str], step_name: str, timeout_seconds: int = 600
) -> bool:
    """Executes a terminal security scanner command and returns success status."""
    print_status(f"Starting Step: {step_name}...")

    tool = command[0]
    if not shutil.which(tool):
        print_status(
            f"Error: Tool '{tool}' for '{step_name}' not found. Please install it.",
            Color.FAIL,
        )
        return False

    try:
        result = subprocess.run(
            command, check=False, text=True, timeout=timeout_seconds
        )
        if result.returncode == 0:
            print_status(f"✓ Passed: {step_name}", Color.OKGREEN)
            return True
        else:
            print_status(
                f"✗ Failed: {step_name} (Exit code {result.returncode})",
                Color.FAIL,
            )
            return False
    except subprocess.TimeoutExpired:
        print_status(f"✗ Failed: {step_name} timed out.", Color.FAIL)
        return False
    except Exception as e:
        print_status(f"✗ Error running '{step_name}': {e}", Color.FAIL)
        return False


def main():
    target_dir = str(Path(".").resolve())
    docker_image = "my-app:latest"

    print_status(
        "=== DevSecOps Automated Pipeline Runner (Python) ===", Color.HEADER
    )

    results = []

    # 1. Secret Scanning
    results.append(
        run_check(
            [
                "trivy",
                "fs",
                "--quiet",
                "--scanners",
                "secret",
                "--exit-code",
                "1",
                "--skip-dirs",
                ".venv",
                "--skip-dirs",
                "venv",
                target_dir,
            ],
            "1. Secret Leakage Scan (Trivy Secrets)",
        )
    )

    # 2. SAST (Semgrep)
    results.append(
        run_check(
            ["semgrep", "--config", "p/owasp-top-ten", "--error", target_dir],
            "2. SAST Code Analysis (Semgrep - OWASP Top 10)",
        )
    )

    # 3. SCA (Trivy Dependency Scan)
    results.append(
        run_check(
            [
                "trivy",
                "fs",
                "--quiet",
                "--scanners",
                "vuln",
                "--severity",
                "HIGH,CRITICAL",
                "--exit-code",
                "1",
                "--skip-dirs",
                ".venv",
                "--skip-dirs",
                "venv",
                target_dir,
            ],
            "3. Dependency Vulnerability Scan (Trivy)",
        )
    )

    # 4. Container Security (Optional)
    if Path("Dockerfile").exists():
        build_status = run_check(
            ["docker", "build", "-t", docker_image, "."], "Docker Image Build"
        )
        if build_status:
            results.append(
                run_check(
                    [
                        "trivy",
                        "image",
                        "--quiet",
                        "--severity",
                        "HIGH,CRITICAL",
                        "--exit-code",
                        "1",
                        docker_image,
                    ],
                    "4. Container Image Scan (Trivy)",
                )
            )
        else:
            results.append(False)

    # Pipeline Summary
    print("\n" + "=" * 50)
    if all(results):
        print_status(
            "ALL SECURITY CHECKS PASSED — READY FOR DEPLOYMENT", Color.OKGREEN
        )
        sys.exit(0)
    else:
        print_status(
            "PIPELINE BLOCKED — HIGH/CRITICAL ISSUES FOUND", Color.FAIL
        )
        sys.exit(1)


if __name__ == "__main__":
    main()