#!/usr/bin/python3

import sys
import os
import time
import subprocess
import argparse

#Launcher for Kyogre

def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Kyogre Launcher - Pokemon Go Bot for Discord")
    parser.add_argument(
        "--auto-restart", "-r",
        help="Auto-Restarts Kyogre in case of a crash.", action="store_true")
    parser.add_argument(
        "--debug", "-d",
        help=("Prevents output being sent to Discord DM, "
              "as restarting could occur often."),
        action="store_true")
    return parser.parse_args()

def run_kyogre(autorestart):
    interpreter = sys.executable
    if interpreter is None:
        raise RuntimeError("Python could not be found")

    cmd = [interpreter, "-m", "meowth", "launcher"]

    retries = 0

    while True:
        if args.debug:
            cmd.append("debug")
        try:
            code = subprocess.call(cmd)
        except KeyboardInterrupt:
            code = 0
            break
        else:
            if code == 0:
                break
            elif code == 26:
                #standard restart
                retries = 0
                print("")
                print("Restarting Kyogre")
                print("")
                continue
            else:
                if not autorestart:
                    break
                retries += 1
                wait_time = min([retries^2, 60])
                print("")
                print("Kyogre experienced a crash.")
                print("")
                for i in range(wait_time, 0, -1):
                    sys.stdout.write("\r")
                    sys.stdout.write(
                        "Restarting Kyogre from crash in {:0d}".format(i))
                    sys.stdout.flush()
                    time.sleep(1)

    print("Kyogre has closed. Exit code: {exit_code}".format(exit_code=code))

args = parse_cli_args()

if __name__ == '__main__':
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)
    print("Launching Kyogre...")
    run_kyogre(autorestart=args.auto_restart)
