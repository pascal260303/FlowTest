from abc import ABC, abstractmethod
from pathlib import Path
from ..statistic_object import StatisticObject
import os


class Histogram(StatisticObject, ABC):
    def __init__(
        self,
        variable: str,
        num_intervals: int,
        lower_bound: float,
        upper_bound: float,
        histogram_type: str = "histogram type: base histogram",
    ) -> None:
        """
        Initialize a histogram for a given variable.
        Args:
            variable: Name of the observed variable.
            num_intervals: Number of bins in the histogram.
            lower_bound: Lower bound of the histogram.
            upper_bound: Upper bound of the histogram.
            histogram_type: Description of the histogram type.
        """
        self.observed_variable = variable
        self.histogram_type = histogram_type
        self.num_intervals = num_intervals
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.bins = [0.0 for _ in range(num_intervals)]
        self.delta = (upper_bound - lower_bound) / num_intervals

    @abstractmethod
    def count(self, x: float) -> None:
        """
        Count a new observation in the histogram.
        Args:
            x: Value to count.
        """
        pass

    @abstractmethod
    def get_normalizing_factor(self) -> float:
        """
        Return the normalizing factor for histogram output.
        Returns:
            Normalizing factor as float.
        """
        pass

    def get_num_intervals(self) -> int:
        """Return the number of intervals (bins) in the histogram."""
        return self.num_intervals

    def get_bin_number(self, x: float) -> int:
        """
        Get the bin index for a given value.
        Args:
            x: Value to bin.
        Returns:
            Bin index as int.
        """
        if x >= self.upper_bound:
            return self.num_intervals - 1
        if x < self.lower_bound:
            return 0
        return int((x - self.lower_bound) // self.delta)

    def increment_bin(self, bin_number: int, x: float) -> None:
        """Increment the value of a bin by x."""
        self.bins[bin_number] += x

    def get_bin_value(self, bin_number: int) -> float:
        """Get the value of a bin."""
        return self.bins[bin_number]

    def get_lower_bound(self) -> float:
        """Return the lower bound of the histogram."""
        return self.lower_bound

    def get_upper_bound(self) -> float:
        """Return the upper bound of the histogram."""
        return self.upper_bound

    def get_delta(self) -> float:
        """Return the bin width (delta) of the histogram."""
        return self.delta

    def reset(self) -> None:
        """Reset all bins to zero."""
        self.bins = [0.0 for _ in range(self.num_intervals)]

    def report(self) -> str:
        """Return a string report of the histogram (default: empty)."""
        return ""

    def csv_report(self, output_dir: os.PathLike, is_ref: bool = False) -> None:
        """
        Write histogram data to CSV files (histogram, PDF, distribution).
        Args:
            output_dir: Output directory for CSV files.
            is_ref: If True, write to expected-histograms folder.
        """
        os.makedirs(os.path.join(output_dir, "histograms"), exist_ok=True)
        dest = Path(output_dir) / "expected-histograms" if is_ref else "histograms"
        hist_path = dest / f"{self.observed_variable}_hist.csv"
        pdf_path = dest / f"{self.observed_variable}_pdf.csv"
        dist_path = dest / f"{self.observed_variable}_dist.csv"

        try:
            with (
                hist_path.open("w", encoding="utf-8") as hist_writer,
                pdf_path.open("w", encoding="utf-8") as pdf_writer,
                dist_path.open("w", encoding="utf-8") as dist_writer,
            ):
                header = f"#{self.histogram_type}\n#{self.observed_variable}\n"
                hist_writer.write(header)
                pdf_writer.write(header)
                dist_writer.write(header)

                hist_writer.write("#lowerBound ; upperBound ; relative frequency\n")
                pdf_writer.write("#lowerBound ; upperBound ; probability density\n")
                dist_writer.write("#(lowerBound+upperBound)/2 ; probability\n")

                for i in range(self.get_num_intervals()):
                    lb = self.lower_bound + i * self.delta
                    ub = lb + self.delta
                    bin_value = self.get_bin_value(i)
                    norm_factor = self.get_normalizing_factor()
                    rel_freq = bin_value / norm_factor if norm_factor != 0 else 0
                    prob_density = rel_freq / self.delta if self.delta != 0 else 0
                    center = lb + 0.5 * self.delta

                    hist_writer.write(
                        f"{lb:.6f};{ub:.6f};{rel_freq:.6f}\n".replace(".", ",")
                    )
                    pdf_writer.write(
                        f"{lb:.6f};{ub:.6f};{prob_density:.6f}\n".replace(".", ",")
                    )
                    dist_writer.write(
                        f"{center:.6f};{rel_freq:.6f}\n".replace(".", ",")
                    )

        except IOError as e:
            print(f"Error writing histogram files: {e}")
