from datetime import datetime
import os

import pandas as pd
from src.common.utils import duplicate_executor
from src.stats.interface import HostStats
from lbr_testsuite.executable import (
    Executor,
    Rsync,
    Tool,
)
from src.stats.pidstat import PidStat
from src.stats.vmstat import VmStat
from src.stats.mpstat import MpStat
import functools as ft


class MergedStats(HostStats):
    cpus: int = 0
    total_ram: int = 0
    local_file: os.PathLike = None

    def __init__(self, executor: Executor, watch_cmd: str, sudo: bool = False):
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

        self.tz = (
            Tool("date +%z", executor=self._executor, sudo=self._sudo).run()[0].strip()
        )

        self.vmstat = VmStat(
            duplicate_executor(executor)[0], sudo, self.cpus, self.total_ram
        )
        self.mpstat = MpStat(
            duplicate_executor(executor)[0], sudo, self.cpus, self.total_ram
        )
        self.pidstat = PidStat(
            duplicate_executor(executor)[0], watch_cmd, sudo, self.cpus, self.total_ram
        )

    def start(self):
        """
        Start collecting mpstat statistics.
        """
        self.vmstat.start()
        self.mpstat.start()
        self.pidstat.start()

    def stop(self):
        """
        Stop collecting mpstat statistics.
        """
        self.vmstat.stop()
        self.mpstat.stop()
        self.pidstat.stop()

    def get_csv(self, output_dir: os.PathLike) -> os.PathLike:
        """
        Download the CSV file containing mpstat and vmstat statistics to the output directory.

        Args:
            output_dir (os.PathLike): Path where to copy CSV to.

        Returns:
            os.PathLike: Path to the merged CSV file.
        """
        # merge vmstat and mpstat in one file
        mpstat_df = pd.read_csv(
            self.mpstat.get_csv(output_dir), sep=";", engine="pyarrow"
        )
        mpstat_df = mpstat_df[mpstat_df["CPU"] == "all"]
        mpstat_df["Time"] = mpstat_df["Time"].astype("int64")

        vmstat_df = pd.read_csv(
            self.vmstat.get_csv(output_dir),
            sep=";",
            engine="pyarrow",
            dtype={"date": str, "time": str},
        )

        # convert "date" and "time" to unix timestamp
        vmstat_df["Time"] = pd.to_datetime(
            vmstat_df["date"] + ";" + vmstat_df["time"],
            format="%Y-%m-%d;%H:%M:%S",
        )
        tzinfo = datetime.strptime(self.tz, "%z").tzinfo
        vmstat_df["Time"] = vmstat_df["Time"].dt.tz_localize(tzinfo)
        vmstat_df["Time"] = (
            vmstat_df["Time"].dt.tz_convert("UTC").astype("int64") // 10**9
        )

        pidstat_df = pd.read_csv(
            self.pidstat.get_csv(output_dir), sep=";", engine="pyarrow"
        )
        agg_dict = {col: "sum" for col in pidstat_df.columns if col != "Time"}
        pidstat_df = pidstat_df.groupby(["Time"], as_index=False).agg(agg_dict)
        pidstat_df["Time"] = pidstat_df["Time"].astype("int64")

        mpstat_df = mpstat_df.add_prefix("mpstat_")
        vmstat_df = vmstat_df.add_prefix("vmstat_")
        pidstat_df = pidstat_df.add_prefix("pidstat_")
        mpstat_df.rename(columns={"mpstat_Time": "Time"}, inplace=True)
        vmstat_df.rename(columns={"vmstat_Time": "Time"}, inplace=True)
        pidstat_df.rename(columns={"pidstat_Time": "Time"}, inplace=True)

        df: pd.DataFrame = ft.reduce(
            lambda left, right: pd.merge(left, right, on="Time", how="outer"),
            (mpstat_df, vmstat_df, pidstat_df),
        )

        # calculate CPU usage by mpstat output
        df["percent_CPU"] = (
            (100 - df["mpstat_percent_idle"]) * self.cpus
        )  # multiply with cpu core count to get better understanding of core usage

        df["total_MEM"] = (
            self.total_ram - df["vmstat_free"] - df["vmstat_buff"] - df["vmstat_cache"]
        )  # in KiB

        df.rename(
            columns={"vmstat_cache": "cache", "vmstat_buff": "buff"}, inplace=True
        )

        df = df.sort_values("Time").reset_index(drop=True)
        df.ffill(inplace=True)

        self.local_file = os.path.join(output_dir, "merged_stats.csv")
        df.to_csv(self.local_file, index=False, sep=";")
        return self.local_file

    def cleanup(self):
        """
        Remove temporary files and clean up resources.
        """
        self.vmstat.cleanup()
        self._rsync.wipe_data_directory()
        Tool(
            f"rmdir {self._work_dir}",
            executor=self._executor,
            failure_verbosity="silent",
        ).run()
