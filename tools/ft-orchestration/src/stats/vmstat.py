import logging
import os
import shutil
import time

from src.common.tool_is_installed import assert_tool_is_installed
from src.stats.interface import HostStats
from lbr_testsuite.executable import (
    Executor,
    Daemon,
    Rsync,
    RsyncException,
    Tool,
    ExecutableProcessError,
)


class VmStat(HostStats):
    cpus: int = 0
    total_ram: int = 0
    local_file: os.PathLike = None

    def __init__(
        self, executor: Executor, sudo: bool = False, cpus=None, total_ram=None
    ):
        assert_tool_is_installed("vmstat", executor)
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
        self._outfile = os.path.join(self._work_dir, "vmstat.csv")
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

        header = (
            "r;b;swpd;free;buff;cache;si;so;bi;bo;in;cs;us;sy;id;wa;st;gu;date;time"
        )
        self._cmd = f"""
        echo '{header}' > {self._outfile}
        stdbuf -oL vmstat -nytS K 1 | stdbuf -oL sed -E -e 's/^ //g' -e 's/[ ]+/;/g' -e '/^([^0-9].*)?$/d' >> {self._outfile}
        """
        """command that writes every second one line in `self._outfile` in csv format (; separated,  with header)
        see `man vmstat` for the meaning of the metrics`
        """

    def start(self):
        """
        Start collecting vmstat statistics.
        """
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
                "Unable to start vmstat: return code: %d, error: %s",
                self._ifc_names,
                return_code,
                err,
            )
            raise Exception("vmstat startup error")

    def stop(self):
        """
        Stop collecting vmstat statistics.
        """
        if self._process is None:
            return
        try:
            self._process.stop()
        except ExecutableProcessError:
            pass

    def get_csv(self, output_dir: os.PathLike) -> os.PathLike:
        """
        Download the CSV file containing vmstat statistics to the output directory.

        Args:
            output_dir (os.PathLike): Path where to copy CSV to.

        Returns:
            os.PathLike: Path to the CSV file.
        """
        if self.local_file:
            local_dir = os.path.dirname(self.local_file)
            if local_dir == output_dir:
                return self.local_file
            for item in os.listdir(local_dir):
                shutil.copy(os.path.join(local_dir, item), output_dir)
            self.local_file = os.path.join(
                output_dir, os.path.basename(self.local_file)
            )
            return self.local_file

        try:
            self.local_file = self._rsync.pull_path(self._outfile, output_dir)
        except RsyncException as err:
            logging.getLogger().warning("%s", err)
            return ""

        return self.local_file

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
