"""
Author(s): Tomas Jansky <Tomas.Jansky@progress.com>

Copyright: (C) 2023 Flowmon Networks a.s.
SPDX-License-Identifier: BSD-3-Clause

File contains data structures which are used for statistical model tests.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

from dataclass_wizard import YAMLWizard


class SMException(Exception):
    """General exception used in statistical model."""


class SMMetricType(Enum):
    """Enum containing possible metrics which can be evaluated in a statistical model."""

    PACKETS = "PACKETS"
    BYTES = "BYTES"
    FLOWS = "FLOWS"
    PPS = "PACKETS / S"
    MBPS = "MB / S"
    DURATION = "DURATION"


@dataclass
class SMSubnetSegment(YAMLWizard):
    """Describe subnets which will be used to filter flows before computing metrics in a statistical model.

    Attributes
    ----------
    source : str, None
        Source IPv4 or IPv6 subnet (e.g., 192.168.0.0/16). Any IP address if None is set.
    dest : str, None
        Destination IPv4 or IPv6 subnet (e.g., 192.168.0.0/16). Any IP address if None is set.
    bidir : bool
        Indicate whether the IP addresses should also include flows in the opposite direction.
    """

    source: Optional[str] = None
    dest: Optional[str] = None
    bidir: bool = False

    def __eq__(self, other: "SMSubnetSegment") -> bool:
        """Compare all attributes of the dataclass.

        Parameters
        ----------
        other : SMSubnetSegment
            The other segment to be compared with.

        Returns
        ------
        bool
            True if equal, False otherwise.
        """

        return (
            isinstance(self, type(other))
            and self.source == other.source
            and self.dest == other.dest
            and self.bidir == other.bidir
        )

    def __str__(self) -> str:
        src_str = self.source or "ANY"
        dest_str = self.dest or "ANY"
        sign = "<->" if self.bidir else "->"
        return f"{src_str} {sign} {dest_str}"


@dataclass
class SMTimeSegment(YAMLWizard):
    """Describe time interval which will be used to filter flows before computing metrics in a statistical model.
    Both start and end times are expected to be in the UTC time zone.

    Flow start time = time of the first observed packet in the flow.
    Flow end time = time of the last observed packet in the flow.
    Start time <= start time of the flow <= end time of the flow <= end time.

    Attributes
    ----------
    start : datetime, None
        Start time in milliseconds.
        Start time is not considered if None is set.
    end : datetime, None
        End time in milliseconds.
        End time is not considered if None is set.
    """

    start: Optional[datetime] = None
    end: Optional[datetime] = None

    def __eq__(self, other: "SMTimeSegment") -> bool:
        """Compare start and end times of both segments.

        Parameters
        ----------
        other : SMTimeSegment
            The other segment to be compared with.

        Returns
        ------
        bool
            True if equal, False otherwise.
        """

        return isinstance(self, type(other)) and self.start == other.start and self.end == other.end

    def __str__(self) -> str:
        src_str = self.start or "ANY"
        dest_str = self.end or "ANY"

        return f"{src_str} -> {dest_str}"


@dataclass
class SMMetric(YAMLWizard):
    """Describe metric and its acceptable relative difference to evaluate data in the statistical model.

    Attributes
    ----------
    key : SMMetricType
        Metric to be used in the statistical model test.
    diff : float
        Acceptable relative difference of the metric from the reference for the test to be marked as passed (0.0 - 1.0).
    """

    key: SMMetricType
    diff: float

    @property
    def diff(self) -> float:
        """Getter"""
        return self._diff

    @diff.setter
    def diff(self, value: float) -> None:
        if 0 <= value <= 1:
            self._diff = value
        else:
            raise ValueError("Relative difference must be in range 0 - 1 (included)")


@dataclass
class SMRule(YAMLWizard):
    """Rule to be applied to a statistical model to evaluate it. Consists of metrics and an optional segment to filter
    desirable data before applying the metrics.

    Attributes
    ----------
    metrics : list
        List of metrics for evaluation.
    segment : SMSubnetSegment, SMTimeSegment, None
        Segment of data to which the metrics should be applied. Either subnet or time segment can be specified.
        If None is set, metrics are applied to all data.
    """

    metrics: List[SMMetric]
    segment: Optional[Union[SMSubnetSegment, SMTimeSegment]] = None


@dataclass
class SMTestOutcome:
    """An outcome of a single test performed in the statistical model.

    Attributes
    ----------
    metrics : SMMetric
        Evaluation metric.
    segment : SMSubnetSegment, SMTimeSegment, None, str
        Segment used to filter data before applying the evaluation metric.
    value : int
        The value of the metric acquired from the probe data.
    reference : int
        The value of the metric acquired from the reference data.
    diff : float
        Relative difference of the value from the reference (0.0 - 1.0).
        Formula: abs(value - reference) / reference
    """

    metric: SMMetric
    segment: Optional[Union[SMSubnetSegment, SMTimeSegment, str]]
    value: int
    reference: int
    diff: float

    def is_passing(self) -> bool:
        """Is the computed relative difference of the metric <= acceptable relative difference?

        Returns
        ------
        bool
            True - test passed, False - test failed
        """
        return bool(self.diff <= self.metric.diff)
