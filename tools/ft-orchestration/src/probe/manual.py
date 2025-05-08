from pathlib import Path
import logging
from src.probe.interface import ProbeInterface
import time

class Manual(ProbeInterface):
    """Empty implementation of ProbeInterface to allow manual setup or hardware flow exporter"""

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
    
    def start(self):
        logging.warning("start probe now")
        for i in range(10,-1,-1):
            logging.info(i)
            time.sleep(1)
            
    
    def supported_fields(self):
        pass
    
    def get_special_fields(self):
        pass
    
    def stop(self):
        logging.warning("you can stop the probe now")
        for i in range(10,-1,-1):
            logging.info(i)
            time.sleep(1)
        
    def cleanup(self):
        pass
    
    def download_logs(self, directory):
        log_file = Path(directory, "manual.log")
        open(log_file, "w").close()
    
    def get_timeouts(self):
        return self._timeouts
    
    def set_prefilter(self, ip_ranges):
        pass
