import shutil
import subprocess
from pathlib import Path


def find_bash() -> str | None:
    """Find a functional bash binary, skipping non-functional Windows WSL stubs."""
    candidates = []
    which_bash = shutil.which("bash")
    if which_bash:
        if "system32" in which_bash.lower():
            for git_p in [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"]:
                if Path(git_p).is_file():
                    candidates.append(git_p)
            candidates.append(which_bash)
        else:
            candidates.append(which_bash)
    else:
        for git_p in [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"]:
            if Path(git_p).is_file():
                candidates.append(git_p)

    for cmd in candidates:
        try:
            res = subprocess.run([cmd, "-c", "exit 0"], capture_output=True, check=False)  # noqa: S603
            if res.returncode == 0:
                return cmd
        except (OSError, subprocess.SubprocessError):
            pass
    return None
