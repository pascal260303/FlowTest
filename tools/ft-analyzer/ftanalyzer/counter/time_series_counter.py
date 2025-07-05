from os import PathLike
import numpy as np
from .counter import Counter
from ..statistic_object import SimState


class TimeSeriesCounter(Counter):
    """
    Counter that records the time series of a variable
    """

    def __init__(self, variable: str, sim: SimState, factor=1.0):
        """
        Args:
            variable (str): name of the observed variable
            sim (SimState): the simulation state for current time
            factor (float, optional): scaling factor. Defaults to 1.0.
        """
        super().__init__(variable, "counter type: time-series counter")
        self._sim = sim
        self._factor = factor
        self.samples: list[tuple[np.uint64, np.float64]] = []

    def count(self, x: np.float64) -> None:
        x = x * self._factor
        super().count(x)

        current_time = self._sim.get_time()
        self.samples.append((current_time, x))

    def reset(self) -> None:
        super().reset()
        self.samples.clear()

    def csv_report(self, outputdir: PathLike) -> None:
        """
        Exports the time series data to a CSV file.
        """
        import os

        os.makedirs(outputdir, exist_ok=True)
        path = os.path.join(outputdir, f"{self.variable}_timeseries.csv")

        with open(path, "w") as f:
            f.write("#time;value\n")
            for timestamp, value in self.samples:
                # change dot to comma if needed (like your Histogram)
                line = f"{timestamp};{value}\n"
                f.write(line.replace(".", ","))

