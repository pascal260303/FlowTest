import logging
import os
import time
from .interface import HostStats
from lbr_testsuite.executable import (
    Executor,
    Daemon,
    Rsync,
    RsyncException,
    Tool,
    ExecutableProcessError,
)


class PidStat(HostStats):
    cpus: int = 0
    total_ram: int = 0

    def __init__(self, executor: Executor, watch_cmd: str, sudo: bool = False):
        self._sudo = sudo
        self._executor = executor
        self._rsync = Rsync(executor)
        self._work_dir = self._rsync._data_dir
        self._outfile = os.path.join(self._work_dir, "pidstat.csv")
        self.cpus = int(
            Tool(
                "bash -c 'cat /proc/cpuinfo | grep \"cpu cores\" | head -n1'",
                executor=self._executor,
                sudo=self._sudo,
            )
            .run()[0]
            .split(":")[1]
            .strip()
        )
        self.total_ram = int(
            Tool(
                "bash -c 'cat /proc/meminfo | grep \"MemTotal\"'",
                executor=self._executor,
                sudo=self._sudo,
            )
            .run()[0]
            .split(":")[1]
            .strip()
            .split(" ")[0]
        )  # in kB

        self._cmd = f"""
        pidstat -rushHv -C {watch_cmd} | sed 's/^# //g' | sed -E 's/[ ]+/;/g' | tail -n2 > {self._outfile}
        sleep 1
        stdbuf -oL pidstat -rushHv -C {watch_cmd} 1 | stdbuf -oL sed -E -e 's/[ ]+/;/g' -e '/^([^0-9].*)?$/d' >> {self._outfile}
        """
        """command that writes every second one line in `self._outfile` in csv format (; separated with header)
        see `man pidstat` for the meaning of the metrics selected by `-rus`
        """

    def start(self):
        self._process = Daemon(
            self._cmd,
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        )
        self._process.start()
        time.sleep(1)

        if not self._process.is_running():
            res = self._process.stop()
            return_code = self._process.returncode()
            self._process = None

            # stderr is redirected to stdout
            err = res[0]
            logging.getLogger().error(
                "Unable to start pidstat: return code: %d, error: %s",
                self._ifc_names,
                return_code,
                err,
            )
            raise Exception("pidstat startup error")

    def stop(self):
        try:
            self._process.stop()
        except ExecutableProcessError:
            pass

    def get_csv(self, output_dir) -> os.PathLike:
        try:
            self._rsync.pull_path(self._outfile, output_dir)
        except RsyncException as err:
            logging.getLogger().warning("%s", err)

        return os.path.join(output_dir, os.path.basename(self._outfile))

    def cleanup(self):
        self._rsync.wipe_data_directory()
        Tool(f"rmdir {self._work_dir}", executor=self._executor).run()
