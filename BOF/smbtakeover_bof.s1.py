from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class SmbTakeoverBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("smbtakeover", base_binary_name="bof.x64")

        self.parser.description = (
            "Interact with the Service Control Manager (SCM) to check, start, or stop "
            "the services responsible for SMB (LanmanServer, srv2, srvnet) in order to "
            "control whether TCP 445 is bound."
        )

        self.parser.add_argument(
            "host",
            help="Target hostname or IP address. Use 'localhost' or '127.0.0.1' for local access.",
        )

        self.parser.add_argument(
            "action",
            choices=["check", "start", "stop"],
            help="Action to perform: check (query service status), start (enable and start SMB services), stop (disable and stop SMB services).",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  smbtakeover localhost check\n"
            "  smbtakeover pc.tart.local stop\n"
            "  smbtakeover 10.0.0.32 start\n\n"
            "Notes:\n"
            "  - 'check' queries service state, start type, and binary path for LanmanServer, srv2, and srvnet\n"
            "  - 'start' sets LanmanServer to AUTO start and starts it (requires SYSTEM or HIGH integrity)\n"
            "  - 'stop' disables LanmanServer and stops all three services (requires SYSTEM or HIGH integrity)\n"
            "  - When targeting remote hosts, RPC over TCP is used as transport, so even after\n"
            "    disabling SMB remotely you can still reconnect via RPC\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        if not parser_arguments.host:
            raise TaskInvalidArgumentsException("Host argument is required.")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # BOF expects: zz (two narrow strings)
        # Matches .cna: bof_pack($1, "zz", $2, $3)
        return [
            (BOFArgumentEncoding.STR, parser_arguments.host),
            (BOFArgumentEncoding.STR, parser_arguments.action),
        ]
