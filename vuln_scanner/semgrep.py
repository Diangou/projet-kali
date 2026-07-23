import subprocess

def run_semgrep(target_url):
    result = subprocess.run(
        ["semgrep", "--config=p/ci", target_url],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("Semgrep a réussi.")
        print(result.stdout)
        return True
    else:
        print("Semgrep a échoué.")
        print(result.stderr)
        return False