import logging
import os
import shutil
import time
from typing import List

import pandas as pd
from src.common.tool_is_installed import assert_tool_is_installed
from src.probe.interface import HostStats
from lbr_testsuite.executable import (
    Executor,
    Daemon,
    Rsync,
    RsyncException,
    Tool,
    ExecutableProcessError,
    RemoteExecutor,
    LocalExecutor,
)
from fabric import Connection
from src.probe.pidstat import PidStat


class MpStat(HostStats):
    cpus: int = 0
    total_ram: int = 0
    local_file: os.PathLike = None

    def __init__(self, executor: Executor, watch_cmd: str, sudo: bool = False):
        assert_tool_is_installed("mpstat", executor)
        self.pidstat = PidStat(self._duplicate_executor(executor)[0], watch_cmd, sudo)
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
        self._outfile = os.path.join(self._work_dir, "mpstat.csv")
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

        self._process = None

        header = "Time;CPU;percent_usr;percent_nice;percent_sys;percent_iowait;percent_irq;percent_soft;percent_steal;percent_guest;percent_gnice;percent_idle"
        self._cmd = f"""
        echo '{header}' > {self._outfile}
        stdbuf -oL mpstat -U 1 | stdbuf -oL sed -E -e 's/[ ]+/;/g' -e '/^([^0-9].*)?$/d' | stdbuf -oL tail -n +2 >> {self._outfile}
        """
        """command that writes every second one line in `self._outfile` in csv format (; separated,  with header)
        see `man mpstat` for the meaning of the metrics`
        """

    def _duplicate_executor(self, executor: Executor, num: int = 1) -> List[Executor]:
        executors = []
        for i in range(num):
            if isinstance(executor, RemoteExecutor):
                connection: Connection = executor.get_connection()
                executors.append(
                    RemoteExecutor(executor.get_host(), **connection.connect_kwargs)
                )
            else:
                executors.append(LocalExecutor())

        return executors

    def start(self):
        """
        Start collecting mpstat statistics.
        """
        self.pidstat.start()
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
                "Unable to start mpstat: return code: %d, error: %s",
                self._ifc_names,
                return_code,
                err,
            )
            raise Exception("mpstat startup error")

    def stop(self):
        """
        Stop collecting mpstat statistics.
        """
        if self._process is None:
            return
        try:
            self._process.stop()
        except ExecutableProcessError:
            pass
        self.pidstat.stop()

    def get_csv(self, output_dir: os.PathLike) -> os.PathLike:
        """
        Download the CSV file containing mpstat and pidstat statistics to the output directory.

        Args:
            output_dir (os.PathLike): Path where to copy CSV to.

        Returns:
            os.PathLike: Path to the merged CSV file.
        """
        if self.local_file:
            if os.path.dirname(self.local_file) == output_dir:
                return self.local_file
            return shutil.copy(self.local_file, output_dir)

        try:
            self.local_file = self._rsync.pull_path(self._outfile, output_dir)
        except RsyncException as err:
            logging.getLogger().warning("%s", err)
            return ""

        # merge pidstat and mpstat in one file
        df = pd.read_csv(self.local_file, sep=";", engine="pyarrow")
        pidstat_df = pd.read_csv(
            self.pidstat.get_csv(output_dir), sep=";", engine="pyarrow"
        )

        agg_dict = {col: "sum" for col in pidstat_df.columns if col != "Time"}
        pidstat_df = pidstat_df.groupby(["Time"], as_index=False).agg(agg_dict)
        df = pd.merge(df, pidstat_df, on="Time", how="left")

        # calculate CPU usage by mpstat output
        df.rename(columns={"percent_CPU": f"percent_CPU_{self.pidstat._watch_cmd}"})
        df["percent_CPU"] = (
            (100 - df["percent_idle"]) * self.cpus
        )  # multiply with cpu core count to get better understanding of core usage

        self.local_file = os.path.join(output_dir, "mpstat_and_pidstat.csv")
        df.to_csv(self.local_file, index=False, sep=";")
        return self.local_file

    def cleanup(self):
        """
        Remove temporary files and clean up resources.
        """
        self.pidstat.cleanup()
        self._rsync.wipe_data_directory()
        Tool(
            f"rmdir {self._work_dir}",
            executor=self._executor,
            failure_verbosity="silent",
        ).run()
