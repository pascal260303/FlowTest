from pathlib import Path
import logging
from src.probe.interface import ProbeInterface, HostStats
import time


class EmptyHostStats(HostStats):
    def __init__(self, executor, watch_cmd):
        pass

    local_file = None
    cpus = 0
    total_ram = 0

    def start(self):
        pass

    def stop(self):
        pass

    def cleanup(self):
        pass

    def get_csv(self, output_dir):
        pass


class Manual(ProbeInterface):
    """
    Empty implementation of ProbeInterface to allow manual setup or hardware flow exporter.
    """

    host_statistics = None

    def __init__(
        self,
        executor,
        target,
        protocols,
        interfaces,
        *,
        verbose=False,
        mtu,
        active_timeout,
        inactive_timeout,
        **kwargs,
    ):
        self._timeouts = (active_timeout, inactive_timeout)
        self.host_statistics = EmptyHostStats(executor, "")
        self.running = False

    def start(self):
        """
        Start the probe manually. Waits for user to start the probe.
        """
        logging.warning("start probe now")
        for i in range(10, -1, -1):
            logging.info(i)
            time.sleep(1)
        self.running = True

    def supported_fields(self):
        pass

    def get_special_fields(self):
        pass

    def stop(self):
        """
        Stop the probe manually. Waits for user to stop the probe.
        """
        if not self.running:
            return

        logging.warning("you can stop the probe now")
        wait_time = self._timeouts[1]  # inactive timeout is enough
        for i in range(wait_time, -1, -1):
            logging.info(i)
            time.sleep(1)
        self.running = False

    def cleanup(self):
        pass

    def download_logs(self, directory):
        """
        Download logs to the given directory.

        Args:
            directory (str): Path to a local directory where logs should be stored.
        """
        log_file = Path(directory, "manual.log")
        open(log_file, "w").close()

    def get_timeouts(self):
        return self._timeouts

    def set_prefilter(self, ip_ranges):
        pass
