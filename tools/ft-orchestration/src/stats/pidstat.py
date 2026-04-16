import logging
import os
import shutil
import time
from src.stats.interface import HostStats
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
    local_file: os.PathLike = None

    def __init__(
        self,
        executor: Executor,
        watch_cmd: str,
        sudo: bool = False,
        cpus=None,
        total_ram=None,
    ):
        self._sudo = sudo
        self._executor = executor
        self._rsync = Rsync(executor)
        self._work_dir = self._rsync._data_dir
        Tool(
            f"mkdir -p {self._work_dir}",
            executor=self._executor,
            sudo=self._sudo,
            failure_verbosity="silent",
        ).run()  # make sure dir exists
        self._outfile = os.path.join(self._work_dir, "pidstat.csv")
        if cpus is not None:
            self.cpus = cpus
        else:
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

        if total_ram is not None:
            self.total_ram = total_ram
        else:
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

        self._process = None
        self._watch_cmd = watch_cmd

    def _get_cmd(self):
        pidstat_args = "-ruhHv"
        pids, _ = Tool(f"pgrep {self._watch_cmd}", executor=self._executor).run()
        pids = pids.replace("\n", ",").strip(",")
        header = "Time;UID;PID;percent_usr;percent_system;percent_guest;percent_wait;percent_CPU;CPU;minflt/s;majflt/s;VSZ;RSS;percent_MEM;threads;fd-nr;Command"
        cmd = f"""
        echo '{header}' > {self._outfile}
        sleep 1
        stdbuf -oL pidstat {pidstat_args} -p {pids} 1 | stdbuf -oL sed -E -e 's/[ ]+/;/g' -e '/^([^0-9].*)?$/d' >> {self._outfile}
        """
        """command that writes every second one line in `self._outfile` in csv format (; separated,  with header)
        see `man pidstat` for the meaning of the metrics selected by `-rus`
        """

        return cmd

    def start(self):
        """
        Start collecting pidstat statistics.
        """
        self._process = Daemon(
            self._get_cmd(),
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
        """
        Stop collecting pidstat statistics.
        """
        if self._process is None:
            return
        try:
            self._process.stop()
        except ExecutableProcessError:
            pass

    def get_csv(self, output_dir) -> os.PathLike:
        """
        Download the CSV file containing pidstat statistics to the output directory.

        Args:
            output_dir (os.PathLike): Path where to copy CSV to.

        Returns:
            os.PathLike: Path to the CSV file.
        """
        if self.local_file:
            if os.path.dirname(self.local_file) == output_dir:
                return self.local_file
            return shutil.copy(self.local_file, output_dir)
        try:
            self.local_file = self._rsync.pull_path(self._outfile, output_dir)
            return self.local_file
        except RsyncException as err:
            logging.getLogger().warning("%s", err)
        return ""

    def cleanup(self):
        """
        Remove temporary files and clean up resources.
        """
        self._rsync.wipe_data_directory()
        Tool(
            f"rmdir {self._work_dir}",
            executor=self._executor,
            failure_verbosity="silent",
        ).run()
