"""Generate user-level autostart definitions; never embeds an API key."""

from pathlib import Path
import plistlib
import subprocess
import sys
from xml.sax.saxutils import escape


def definition(system, config, executable=None):
    config = str(Path(config).resolve())
    executable = executable or sys.executable
    args = ["-m", "kauliki_network_scanner", "--config", config, "run"]
    if system == "windows":
        arguments = subprocess.list2cmdline(args)
        return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="Author"><Exec><Command>{escape(executable)}</Command><Arguments>{escape(arguments)}</Arguments></Exec></Actions>
</Task>"""
    if system == "darwin":
        return plistlib.dumps(
            dict(
                Label="ru.kauliki.network-scanner",
                ProgramArguments=[executable, *args],
                RunAtLoad=True,
                KeepAlive=True,
                ThrottleInterval=30,
            )
        ).decode()

    def quote(value):
        return (
            '"'
            + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
            + '"'
        )

    return "\n".join(
        [
            "[Unit]",
            "Description=Kauliki Network Scanner",
            "After=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=" + " ".join(quote(value) for value in [executable, *args]),
            "Restart=on-failure",
            "RestartSec=30",
            "TimeoutStopSec=210",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )
