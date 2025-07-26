import json
import logging
from os import path
from pathlib import Path
import tempfile
import time
import xml.etree.ElementTree as ET

import pandas as pd
from src.collector.interface import (
    CollectorOutputReaderException,
    CollectorOutputReaderInterface,
)
from lbr_testsuite.executable import (
    AsyncTool,
    ExecutableProcessError,
    Executor,
    Rsync,
    Tool,
)

from src.common.tool_is_installed import assert_tool_is_installed

CSV_HEADER_TO_ANALYZER_HEADER = {
    "iana:octetDeltaCount": "BYTES",
    "iana:packetDeltaCount": "PACKETS",
    "iana:protocolIdentifier": "PROTOCOL",
    "iana:sourceTransportPort": "SRC_PORT",
    "iana:sourceIPAddress": "SRC_IP",
    "iana:destinationTransportPort": "DST_PORT",
    "iana:destinationIPAddress": "DST_IP",
    "iana:flowStartMilliseconds": "START_TIME",
    "iana:flowEndMilliseconds": "END_TIME",
    "ipfix:exportTime": "EXPORT_TIME",
    "ipfix:msgLength": "MSG_LENGTH",
}


class JQ(CollectorOutputReaderInterface):
    CONFIG_FILE = "config.xml"

    """Read FDS file again with ipfixcol2 and use json output wich is converted using jq to csv
    This has the advantage that in the json output of ipfixcol2 more information can be included 
    especially the export time, which is currently not accessible when using `fdsdump`

    Args:
        CollectorOutputReaderInterface (_type_): _description_
    """

    def __init__(self, executor: Executor, file: str):
        assert_tool_is_installed("ipfixcol2", executor)
        assert_tool_is_installed("jq", executor)

        command = Tool(f"ls {file} -1", executor=executor, failure_verbosity="silent")
        stdout, _ = command.run()
        if command.returncode() != 0:
            raise CollectorOutputReaderException(f"Cannot access file '{file}'")
        if stdout.count("\n") != 1:
            raise CollectorOutputReaderException("More than one file found.")

        self._conf_file = tempfile.NamedTemporaryFile(
            prefix="ipfixcol2", suffix=".conf"
        )

        self._rsync = Rsync(executor)
        self._work_dir = Path(tempfile.mkdtemp())
        self._conf_dir = Path(self._rsync.get_data_directory())

        self._executor = executor
        self._file = stdout.strip()
        tmp_file = path.join(self._rsync.get_data_directory(), "flows.json")
        self._cmd_json = f"ipfixcol2 -c {Path(self._conf_dir, self.CONFIG_FILE)}"
        self._cmd_csv = f"""(ipfixcol2 -c {Path(self._conf_dir, self.CONFIG_FILE)} > {tmp_file}
HEADER=$(head -n 1 {tmp_file} | jq -r '
  .["iana:sourceIPAddress"] = (.["iana:sourceIPv4Address"] // .["iana:sourceIPv6Address"]) |
  .["iana:destinationIPAddress"] = (.["iana:destinationIPv4Address"] // .["iana:destinationIPv6Address"]) |
  del(
    .["iana:sourceIPv4Address"],
    .["iana:sourceIPv6Address"],
    .["iana:destinationIPv4Address"],
    .["iana:destinationIPv6Address"]
  ) |
  keys_unsorted | @csv
')
echo ${{HEADER}}
cat {tmp_file} | jq -r "
  .[\\"iana:sourceIPAddress\\"] = (.\\"iana:sourceIPv4Address\\" // .\\"iana:sourceIPv6Address\\") |
  .[\\"iana:destinationIPAddress\\"] = (.\\"iana:destinationIPv4Address\\" // .\\"iana:destinationIPv6Address\\") |
  del(
    .\\"iana:sourceIPv4Address\\",
    .\\"iana:sourceIPv6Address\\",
    .\\"iana:destinationIPv4Address\\",
    .\\"iana:destinationIPv6Address\\"
  ) |
  [.$(echo ${{HEADER}} | sed 's/,/, ./g')] | @csv
"
rm {tmp_file})"""
        """Reads fds file and output as json with ipfixcol2, then converts json with `jq` to csv\\
        In the csv output the columns `iana:sourceIPv4Address` and `iana:sourceIPv6Address` are merged to `iana:sourceIPAddress`\\
        The same is done for `iana:destinationIPAddress`
        """
        self._process = None
        self._buf = None
        self._idx = 0

        self._create_xml_config()

    def _create_xml_config(self):
        """Create XML configuration file for Ipfixcol2 based on startup arguments.

        Raises
        ------
        CollectorException
            Cannot create base directory.
        """

        # For XML structure see:
        # https://github.com/CESNET/ipfixcol2/blob/master/doc/sphinx/configuration.rst

        # pylint: disable=too-many-locals
        root = ET.Element("ipfixcol2")
        input_plugins = ET.SubElement(root, "inputPlugins")
        output_plugins = ET.SubElement(root, "outputPlugins")

        inpt = ET.SubElement(input_plugins, "input")
        inpt_name = ET.SubElement(inpt, "name")
        inpt_plugin = ET.SubElement(inpt, "plugin")
        inpt_params = ET.SubElement(inpt, "params")
        inpt_params_path = ET.SubElement(inpt_params, "path")

        outpt = ET.SubElement(output_plugins, "output")
        outpt_name = ET.SubElement(outpt, "name")
        outpt_plugin = ET.SubElement(outpt, "plugin")
        outpt_params = ET.SubElement(outpt, "params")
        outpt_params_detailed_info = ET.SubElement(outpt_params, "detailedInfo")
        output_params_timestamp = ET.SubElement(outpt_params, "timestamp")
        output_params_protocol = ET.SubElement(outpt_params, "protocol")
        outpt_params_outputs = ET.SubElement(outpt_params, "outputs")
        outpt_params_outputs_print = ET.SubElement(outpt_params_outputs, "print")
        outpt_params_outputs_print_name = ET.SubElement(
            outpt_params_outputs_print, "name"
        )

        inpt_name.text = "FDS input plugin"
        inpt_plugin.text = "fds"

        inpt_params_path.text = str(self._file)

        outpt_name.text = "JSON output plugin"
        outpt_plugin.text = "json"

        outpt_params_detailed_info.text = "true"
        output_params_timestamp.text = "unix"
        output_params_protocol.text = "raw"
        outpt_params_outputs_print_name.text = "Printer to stdout"

        tree = ET.ElementTree(root)
        # with open(Path(self._work_dir, self.CONFIG_FILE), "wb", encoding="ascii") as config_file:
        config_file = str(Path(self._work_dir, self.CONFIG_FILE))
        tree.write(config_file)

        self._rsync.push_path(Path(self._work_dir, self.CONFIG_FILE))

    def __iter__(self):
        """Basic iterator. Start ipfixcol2 + jq process.

        Returns
        -------
        ipfixcol2 + jq
            Iterable object instance.

        Raises
        ------
        CollectorOutputReaderException
            ipfixcol2 / jq process exited unexpectedly with an error.
        """

        if self._process is not None:
            self._stop()

        self._start()
        self._buf = iter(self._process.stdout)

        return self

    def _start(self):
        """Starts the ipfixcol2 + jq process.

        Raises
        ------
        CollectorOutputReaderException
            ipfixcol2 + jq process exited unexpectedly with an error.
        """

        self._process = AsyncTool(self._cmd_json, executor=self._executor)

        try:
            self._process.run()
        except ExecutableProcessError as err:
            logging.getLogger().error(
                "ipfixcol2 / jq return code: %d, error: %s",
                self._process.returncode(),
                err,
            )
            raise CollectorOutputReaderException(
                "ipfixcol2 / jq startup error"
            ) from err

    def _stop(self):
        """Stop ipfixcol2 + jq process.

        Raises
        ------
        CollectorOutputReaderException
            ipfixcol2 / jq process exited unexpectedly with an error.
        """

        stdout, _ = self._process.wait_or_kill(1)

        if self._process.returncode() > 0:
            # stderr is redirected to stdout
            # Since stdout could be filled with normal output, print only last line
            err = stdout[-1]
            logging.getLogger().error(
                "ipfixcol2 / jq runtime error: %s, error: %s",
                self._process.returncode(),
                err,
            )
            raise CollectorOutputReaderException("ipfixcol2 / jq runtime error")

        self._process = None
        self._buf = None
        self._idx = 0

        return stdout

    def __next__(self):
        """Read next flow entry from FDS file.

        Returns
        -------
        dict
            JSON flow entry in form of dict.

        Raises
        ------
        CollectorOutputReaderException
            ipfixcol2 / jq process not started.
        StopIteration
            No more flow entries for processing.
        """

        if self._process is None and self._buf is None:
            logging.getLogger().error("ipfixcol2 + jq process not started")
            raise CollectorOutputReaderException("ipfixcol2 + jq process not started")

        while self._buf is not None:
            try:
                output = next(self._buf)
                json_output = json.loads(output)
                return json_output
            except json.JSONDecodeError as err:
                logging.getLogger().error(
                    "processing line=%s error=%s", output, str(err)
                )
                output = self._buf.readline()
                continue
            except StopIteration:
                if self._process is not None:
                    # the process is complete, but all output may not have been processed
                    rest_output = self._stop()
                    self._buf = iter(rest_output.splitlines())
                else:
                    # after processing rest of output
                    self._buf = None

        raise StopIteration

    def save_csv(self, csv_file: str):
        """Convert flows from FDS format to CSV file.
        Used for significant amount of flows in performance testing.

        Parameters
        ----------
        csv_file: str
            Path to CSV file. Local file, CSV will be downloaded when collector running on remote.
        """

        rsync = Rsync(self._executor)
        filename = path.basename(csv_file)
        tmp_file = path.join(rsync.get_data_directory(), filename)

        logging.getLogger().info(
            "Preparing CSV output by calling ipfixcol2 + jq command..."
        )
        start = time.time()
        # write csv
        stdout, stderr = Tool(
            f"{self._cmd_csv} >> {tmp_file}", executor=self._executor
        ).run()
        end = time.time()
        logging.getLogger().info("CSV output saved in %.2f seconds.", (end - start))

        start = time.time()
        tmp_dir = tempfile.mkdtemp()
        rsync.pull_path(tmp_file, tmp_dir)
        end = time.time()
        df = pd.read_csv(path.join(tmp_dir, filename))
        # Filter columns
        df = df[list(CSV_HEADER_TO_ANALYZER_HEADER.keys())]
        # rename columns
        df = df.rename(columns=CSV_HEADER_TO_ANALYZER_HEADER)

        df.to_csv(csv_file, index=False)

        logging.getLogger().info(
            "CSV output downloaded in %.2f seconds.", (end - start)
        )
