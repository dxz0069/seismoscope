import subprocess


def run_user_command(command):
    return subprocess.run(command, shell=True, check=False)
