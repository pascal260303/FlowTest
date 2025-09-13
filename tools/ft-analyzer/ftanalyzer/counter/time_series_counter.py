from os import PathLike
import os
from typing import List
import numpy as np
import pandas as pd
from .discrete_counter import DiscreteCounter
from ..statistic_object import SimState
import matplotlib.pyplot as plt


class TimeSeriesCounter(DiscreteCounter):
    """
    Counter that records the time series of a variable and exports to CSV/plot.
    """

    def __init__(
        self,
        variable: str,
        sim: SimState,
        start_time: np.uint64,
        end_time: np.uint64,
        factor: float = 1.0,
        target_sample_count: int = 10000,
        measure_start_time: np.uint64 = None,
        measure_end_time: np.uint64 = None,
    ) -> None:
        """
        Initialize a time series counter.
        Args:
            variable: Name of the observed variable.
            sim: Simulation state object.
            start_time: Start time in ms.
            end_time: End time in ms.
            factor: Scaling factor for values.
            target_sample_count: Target number of samples in time series.
            measure_start_time: Optional measurement window start.
            measure_end_time: Optional measurement window end.
        """
        super().__init__(variable, "counter type: time-series counter")
        self._sim = sim
        self._factor = factor
        self._samples_list: List[tuple[np.uint64, np.float64]] = []

        total_time_ms = end_time - start_time + 1

        self._agg_window_ms = max(1, total_time_ms // target_sample_count)
        self._agg_start_time: np.uint64 | None = None
        self._agg_sum = 0.0
        self._agg_count = 0
        self._measure_start_time = (
            self._sim.convert_to_seconds(measure_start_time)
            if measure_start_time
            else None
        )
        self._measure_end_time = (
            self._sim.convert_to_seconds(measure_end_time) if measure_end_time else None
        )

    def count(self, x: np.float64) -> None:
        """
        Count a new sample and update the time series aggregation.
        Args:
            x: Value to count.
        """
        x = x * self._factor
        super().count(x)

        if self._agg_start_time is None:
            self._agg_start_time = self._sim.get_time()

        self._agg_sum += x
        self._agg_count += 1

        # If aggregation window is over, compute average and store
        if self._sim.get_time() - self._agg_start_time >= self._agg_window_ms:
            avg_value = self._agg_sum / self._agg_count
            self._samples_list.append((self._agg_start_time, avg_value))

            # Reset aggregation state
            self._agg_start_time = self._sim.get_time()
            self._agg_sum = 0.0
            self._agg_count = 0

    def _finalize_aggregation(self) -> None:
        """
        Finalize the aggregation window and store the last average value.
        """
        if self._agg_count > 0:
            avg_value = self._agg_sum / self._agg_count
            self._samples_list.append((self._agg_start_time, avg_value))
            self._agg_sum = 0.0
            self._agg_count = 0

    def reset(self) -> None:
        """
        Reset all statistics and clear the time series.
        """
        super().reset()
        self._samples_list.clear()

    def report(self) -> None:
        """
        Finalize aggregation and print report.
        """
        super().report()
        self._finalize_aggregation()

    def csv_report(self, outputdir: PathLike, is_ref: bool = False) -> None:
        """
        Export the time series data to a CSV file and create a plot.
        Args:
            outputdir: Output directory for CSV and plot files.
            is_ref: If True, write to expected-counters/expected-plots folders.
        """
        self._finalize_aggregation()
        plot_path = os.path.join(outputdir, "expected-plots" if is_ref else "plots")
        self._plot(plot_path)

        samples_df = pd.DataFrame(
            self._samples_list,
            columns=["time", "value"],
        ).astype(
            {
                "time": np.uint64,
                "value": np.float64,
            }
        )

        outputdir = os.path.join(
            outputdir, "expected-counters" if is_ref else "counters"
        )
        os.makedirs(outputdir, exist_ok=True)
        file_name = f"{self._observed_variable}_timeseries.csv".replace(
            " ", "_"
        ).replace("/", "p")
        path = os.path.join(outputdir, file_name)

        samples_df.to_csv(path, sep=";", index=False, float_format="%.6f", decimal=",")

    def _plot(self, outputdir: str) -> None:
        """
        Plot the time series data and save as PNG file in the output directory.
        Args:
            outputdir: Path to the output folder.
        """
        if not self._samples_list:
            return

        os.makedirs(outputdir, exist_ok=True)

        # convert times from ms to seconds for the plot
        time_unit = "seconds"
        df = pd.DataFrame(
            self._samples_list,
            columns=["time", "value"],
        ).astype(
            {
                "time": np.uint64,
                "value": np.float64,
            }
        )
        df["time_sec"] = df["time"].apply(self._sim.convert_to_seconds)
        df["time_sec_zero"] = df["time_sec"] - df["time_sec"].iloc[0]

        plt.figure(figsize=(10, 6))
        plt.plot(
            df["time_sec_zero"],
            df["value"],
            color="orange",
            linewidth=1.5,
            label=self._observed_variable,
        )
        if self._measure_start_time:
            plt.axvline(
                self._measure_start_time - df["time_sec"].iloc[0], color="green"
            )
        if self._measure_end_time:
            plt.axvline(self._measure_end_time - df["time_sec"].iloc[0], color="red")
        plt.xlabel(time_unit)
        plt.ylabel(self._observed_variable)
        plt.title(f"Time Series of {self._observed_variable}")
        plt.legend()
        plt.grid(True)

        file_name = f"{self._observed_variable}_timeseries.png".replace(
            " ", "_"
        ).replace("/", "p")
        file_path = os.path.join(outputdir, file_name)
        plt.savefig(file_path, dpi=300)
        plt.close()
