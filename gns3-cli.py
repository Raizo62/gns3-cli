#!/usr/bin/env python3
import argparse  # Standard library CLI parser and help system
import base64  # Base64 decoding for QEMU guest-agent output
import codecs  # Validating user-supplied text encoding names (e.g. --windows_console_encoding)
import contextlib  # Temporary stdout redirection when third-party libs are too verbose
import difflib  # Fuzzy matching for mistyped subcommands
import io  # In-memory text buffer for captured stdout
import inspect  # Introspection for auto-building CLI subcommands
import json  # JSON encoding/decoding for QEMU and GNS3 payloads
import os  # Filesystem checks for config and socket paths
import re  # Regex formatting for usage-line argument styling
import shlex  # Shell-like splitting for Docker command arguments
import shutil  # Terminal width detection for help formatter layout
import socket  # TCP/Unix-socket communication for console and QGA access
import stat  # Reading local file permission bits to mirror them on the remote file
import subprocess  # Running Docker and shell commands
import sys  # Standard output/error handling
import time  # Delays and timeouts in console/QEMU interactions
from functools import partial  # Partial application for reusable command executors
from typing import Any, Callable, Literal, NoReturn, Protocol, Sequence, get_args, get_origin  # Typing helpers for callbacks, protocols, and command sequences
from urllib.parse import urlparse  # Parse GNS3 base URL to extract console hostname
from requests.exceptions import JSONDecodeError  # Error handling for GNS3 HTTP/JSON failures
from pathlib import Path # Object-oriented cross-platform path management

try:
    from gns3fy import Gns3Connector, Link, Node, Project
except ImportError:  # pragma: no cover - optional dependency
    Gns3Connector = None
    Link = None
    Node = None
    Project = None

DEFAULT_USER = "user"
DEFAULT_PASSWORD = "user"
CONFIG_PATH = "/etc/gns3.conf"
#>-----------------------
#GNS3Login=user
#GNS3Password=user
#-----------------------<

GNS3_SERVER_BASE_URL = "http://localhost"
DEFAULT_CONSOLE_HOST = "localhost"
DEFAULT_GNS3_SERVER_PORT = 3080
GNS3_SERVER_PORT = DEFAULT_GNS3_SERVER_PORT

GNS3_SERVER_URL = f"{GNS3_SERVER_BASE_URL}:{GNS3_SERVER_PORT}"
QEMU_PATH_SOCKET = "/usr/lib/qemu/sockets"
QEMU_DEFAULT_HARDDISK_PATH = "/home/user/GNS3/Images"
QEMU_DISK_LETTERS = ("a", "b", "c", "d")
DEFAULT_TIMEOUT = 2.0
QGA_MAX_WAIT_SECONDS = 30.0
QGA_STATUS_POLL_INTERVAL = 0.1
SOCKET_RECV_CHUNK_SIZE = 4096
QGA_FILE_READ_CHUNK_SIZE = 65536  # Bytes requested per guest-file-read call
QGA_FILE_WRITE_CHUNK_SIZE = 65536  # Bytes sent per guest-file-write call
QEMU_DEFAULT_OS_TYPE: Literal["linux", "microsoft"] = "linux"
QEMU_WINDOWS_CONSOLE_ENCODING = "cp437"
	# run `chcp` inside cmd.exe to find the right value
	# "cp437" for US-English
	# "cp852" for Central European
	# "cp850" for a French/Western-European

COLOR_TITLE = "\033[97m" # Bright White
COLOR_OPTION = "\033[95m" # Mauve
COLOR_RESET = "\033[0m"
_ANSI_ESCAPE_RE = re.compile(r"\033\[[0-9;]*m")
HELP_INDENT_INCREMENT = 2
HELP_MAX_POSITION = 30
HELP_MIN_WIDTH = 80
OPTION_COLUMN_WIDTH = 28
COLOR_MODE_ENV = "GNS3_CLI_COLOR"

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # no display needed
_qt_app = None # process-wide QApplication singleton kept alive here
LABEL_STYLE = "font-family: TypeWriter;font-size: 10.0;font-weight: bold;fill: #000000;fill-opacity: 1.0;"
# Linear fallback used only if the Qt-based measurement fails.
# Calibrated on 3 hand-centered reference points (icon_width=65):
#   R4 (2 chars) -> 20, PC1 (3 chars) -> 14, MyComputer123 (13 chars) -> -27
LABEL_X_FALLBACK_SLOPE = -4.2027
LABEL_X_FALLBACK_INTERCEPT = 27.5495

GNS3_CLI_VERSION = "2.0"
GNS3_CLI_URL = "https://github.com/Raizo62/gns3-cli"

def _visible_length(text: str) -> int:
    """Length of text as it will actually appear on screen, ignoring any
    invisible ANSI color escape codes it may contain."""
    return len(_ANSI_ESCAPE_RE.sub("", text))

def load_config() -> tuple[str | None, str | None, str | None]:
    username = DEFAULT_USER
    password = DEFAULT_PASSWORD

    if not os.path.exists(CONFIG_PATH):
        return username, password, None

    if not os.path.isfile(CONFIG_PATH):
        return None, None, (
            f"Error: configuration path "
            f"'{CONFIG_PATH}' is not a regular file."
        )

    if not os.access(CONFIG_PATH, os.R_OK):
        return None, None, (
            f"Error: configuration file "
            f"'{CONFIG_PATH}' is not readable."
        )

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("GNS3Login="):
                    username = line.split("=", 1)[1]
                elif line.startswith("GNS3Password="):
                    password = line.split("=", 1)[1]
    except OSError as exc:
        return None, None, (
            f"Error: unable to read "
            f"configuration file "
            f"'{CONFIG_PATH}': {exc}"
        )

    return username, password, None

class _ConsoleNode(Protocol):
    console: int

# Common signature for functions called by _exec_file:
# (project_name, device_name, command) -> (exit_code: int, message: str | None)
_NodeExecutor = Callable[..., tuple[int, str | None]]

def _resolve_console_host() -> str:
    base_url = GNS3_SERVER_BASE_URL or DEFAULT_CONSOLE_HOST
    normalized_url = base_url if "://" in base_url else f"http://{base_url}"
    parsed = urlparse(normalized_url)
    return parsed.hostname or DEFAULT_CONSOLE_HOST


CONSOLE_HOST = _resolve_console_host()


def _qga_request(sock_path: str, payload: dict, timeout_seconds: float = DEFAULT_TIMEOUT) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_seconds)
        sock.connect(sock_path)
        request_data = (json.dumps(payload) + "\n").encode("utf-8")
        sock.sendall(request_data)

        chunks = []
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                chunk = sock.recv(SOCKET_RECV_CHUNK_SIZE)
            except TimeoutError:
                break

            if not chunk:
                break

            chunks.append(chunk)
            if time.monotonic() >= deadline:
                break

        return b"".join(chunks).decode("utf-8", errors="ignore")


def _to_json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): _to_json_safe(item)
            for key, item in value.items()
            if not str(key).startswith("__")
            if key != "connector"
        }

    if isinstance(value, (list, tuple, set)):
        return [_to_json_safe(item) for item in value]

    if hasattr(value, "__dict__"):
        return {
            key: _to_json_safe(item)
            for key, item in vars(value).items()
            if key != "connector"
            if not key.startswith("__")
        }

    return str(value)


class Gns3CLI:
    def __init__(self):
        if Gns3Connector is None:
            self.server = None
            return

        self.server = Gns3Connector(
            url=GNS3_SERVER_URL,
            user=USERNAME,
            cred=PASSWORD
        )

    def _get_device(
        self,
        project_name: str,
        device_name: str,
        expected_type: str | None = None,
        project_action: str | None = None,
        require_started: bool = False,
    ):
        # Default project_action for typed devices
        if expected_type is not None and project_action is None:
            project_action = "access the project"

        # Default fallback if user forgot project_action in untyped mode
        if project_action is None:
            project_action = "access the project"

        # Load project
        lab, error = self._load_project(project_name, project_action)
        if error is not None:
            return None, error

        # Retrieve device
        try:
            device = lab.get_node(name=device_name)
        except Exception as exc:
            return None, self._format_gns3_error(exc, "access the device")

        if device is None:
            return None, f"Error: Device {device_name} not found."

        # Typed mode
        if expected_type is not None:
            node_type = (getattr(device, "node_type", "") or "").strip().lower()
            if node_type != expected_type:
                return None, (
                    f"Error: Device {device_name} "
                    f"is not a {expected_type} device "
                    f"(node_type: {getattr(device, 'node_type', None) or 'unknown'})."
                )

        # Started requirement
        if require_started and getattr(device, "status", None) != "started":
            return None, (
                f"Error: Device {device_name} is stopped "
                f"(Status: {getattr(device, 'status', 'unknown')})."
            )

        return device, None

    def _format_gns3_error(self, exc: Exception, action: str) -> str:
        message = str(exc).strip()
        lowered = message.lower()

        if "401" in message or "403" in message or "unauthorized" in lowered or "forbidden" in lowered:
            return (
                f"GNS3 authentication error while trying to {action}. "
                f"The username or password is invalid."
            )

        if isinstance(exc, JSONDecodeError) or "expecting value" in lowered or (
            "json" in lowered and any(token in lowered for token in ("decode", "parse"))
        ):
            return (
                f"Unable to {action}: GNS3 returned a non-JSON response. "
                "This can happen with invalid credentials, an invalid attribute/value payload, "
                "or a temporary server-side error."
            )

        return f"Unable to {action}: {message or type(exc).__name__}"

    def _load_project(self, project_name, action: str):
        if self.server is None or Project is None:
            return None, "gns3fy is not installed"

        if not project_name:
            return None, "A project name is required"

        try:
            lab = Project(name=project_name, connector=self.server)
            lab.get()
            return lab, None
        except Exception:
            return None, f"Error: Project {project_name} not found."

    def _resolve_template(
        self, template_name: str, action: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        if self.server is None:
            return None, "gns3fy is not installed"

        if not template_name:
            return None, "A template name is required"

        try:
            template = self.server.get_template(name=template_name)
        except Exception as exc:
            return None, self._format_gns3_error(exc, action)

        if template is None:
            return None, f"Error: Template {template_name} not found."

        return template, None

    def _apply_project_action(
        self,
        project_name: str,
        *,
        action_name: str,
        operation: Callable[[Any], None],
        success_message: str,
    ) -> tuple[int, str | None] :
        lab, error = self._load_project(project_name, action_name)
        if error is not None:
            return 1, error

        try:
            operation(lab)
        except Exception as exc:
            return 2, self._format_gns3_error(exc, action_name)

        print(success_message.format(project_name=project_name))
        return 0, None

    def _load_open_project(self, project_name: str, action_name: str):
        lab, error = self._load_project(project_name, action_name)
        if error is not None:
            return None, error

        if getattr(lab, "status", None) != "opened":
            return None, f"Error: Project {project_name} is closed. Open it before {action_name}."

        return lab, None

    def _get_lab_device(self, lab: Any, device_name: str, action_name: str):
        try:
            device = lab.get_node(name=device_name)
        except Exception as exc:
            return None, self._format_gns3_error(exc, action_name)

        if device is None:
            return None, f"Error: Device {device_name} not found."

        return device, None

    def _get_lab_links(self, lab: Any, action_name: str) -> tuple[list[Any] | None, str | None]:
        if not getattr(lab, "links", None):
            try:
                lab.get_links()
            except Exception as exc:
                return None, self._format_gns3_error(exc, action_name)

        return (getattr(lab, "links", []) or []), None

    def _get_project_id(self, project_name: str) -> str:
        lab, error = self._load_project(project_name, "access the project")
        if error is not None:
            raise RuntimeError(error)

        project_id = None
        for attr_name in ("project_id", "id", "uuid", "_id"):
            value = getattr(lab, attr_name, None)
            if value:
                project_id = value
                break

        if not project_id:
            raise RuntimeError("Unable to determine the GNS3 project ID")

        return project_id

    def _qemu_resolve_socket(
        self, project_name: str, device_name: str
    ) -> tuple[str | None, str | None]:
        """
        Compute the qemu-guest-agent UNIX socket path for a VM and verify
        that it exists.

        This is the single place that performs project/device resolution
        and socket-path computation for QEMU commands. Callers that need
        to do several QEMU operations back to back (e.g. device_exec_cmd,
        which detects the OS type and then executes a command) should call
        this once and pass the resulting sock_path to _qemu_get_os_type /
        qemu_exec_cmd instead of letting each of them resolve it again.

        Returns:
            (sock_path, None) on success.
            (None, error_message) if the project/device can't be resolved.

        Raises:
            RuntimeError: if the project id cannot be determined.
            FileNotFoundError: if the socket file does not exist.
        """
        project_id = self._get_project_id(project_name)

        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error is not None:
            return None, error

        sock_path = os.path.join(
            QEMU_PATH_SOCKET,
            f"GNS3.{device_name}.{project_id}.qga.sock",
        )
        if not os.path.exists(sock_path):
            raise FileNotFoundError(f"Error '{sock_path}' not found")

        return sock_path, None

    @contextlib.contextmanager
    def _patched_gns3fy_node_update(self):
        if Node is None:
            yield
            return
        original_update = getattr(Node, "update", None)
        if original_update is None:
            yield
            return

        def _patched_node_update(node_self, **kwargs):
            allowed_kwargs = {}
            for key in ("name", "x", "y", "label"):
                if key in kwargs:
                    allowed_kwargs[key] = kwargs[key]
            return original_update(node_self, **allowed_kwargs)

        Node.update = _patched_node_update
        try:
            yield
        finally:
            Node.update = original_update

    def _label_payload(self, device_name: str, icon_width: int) -> dict[str, Any]:
        return {
            "text": device_name,
            "x": self._centered_label_x(device_name, icon_width),
            "y": -25,
            "style": LABEL_STYLE,
            "rotation": 0,
        }

    def _apply_position_and_label(
        self,
        refresh_device: Callable[[], Any],
        device_name: str,
        target_x: int,
        target_y: int,
        max_attempts: int = 10,
        poll_interval: float = 0.4,
        stability_checks: int = 3,
    ) -> None:
        """
        Forces x/y and the label of the device until both hold stable across
        several consecutive checks (guards against a connected GUI rewriting
        the node afterwards).

        `refresh_device` must return a fresh node instance (with .x, .y,
        .label, .width, and .update()) on each call.
        """
        device = refresh_device()
        icon_width = getattr(device, "width", 65)
        label_payload = self._label_payload(device_name, icon_width)
        expected_label_x = label_payload["x"]

        consecutive_ok = 0

        with self._patched_gns3fy_node_update():
            for _ in range(max_attempts):
                device.update(x=target_x, y=target_y, label=label_payload)
                time.sleep(poll_interval)
                device = refresh_device()

                position_ok = device.x == target_x and device.y == target_y
                label_ok = (device.label or {}).get("x") == expected_label_x

                if position_ok and label_ok:
                    consecutive_ok += 1
                    if consecutive_ok >= stability_checks:
                        return
                else:
                    consecutive_ok = 0

        print(
            f"Warning: label/position for {device_name} never stabilized "
            f"after {max_attempts} attempts."
        )

    _qt_app = None

    @classmethod
    def _ensure_qt_app(cls) -> None:
        """Lazily creates a headless QApplication, required before using any
        Qt font-metrics API."""
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            from PyQt5.QtWidgets import QApplication
        if QApplication.instance() is None:
            cls._qt_app = QApplication([])

    @staticmethod
    def _font_from_label_style(style: str):
        """Parses a GNS3 label style string ('font-family: ...;font-size: ...;
        font-weight: ...;...') into a QFont, matching what gns3-gui's
        LabelItem applies to the rendered text."""
        try:
            from PyQt6.QtGui import QFont
        except ImportError:
            from PyQt5.QtGui import QFont

        font = QFont()
        if m := re.search(r"font-family:\s*([^;]+)", style):
            font.setFamily(m.group(1).strip())
        if m := re.search(r"font-size:\s*([\d.]+)", style):
            font.setPointSizeF(float(m.group(1)))
        if m := re.search(r"font-weight:\s*(\w+)", style):
            if m.group(1).strip().lower() == "bold":
                font.setBold(True)
        return font

    @classmethod
    def _measured_text_width(cls, text: str, style: str) -> float:
        """Renders the text the same way gns3-gui's LabelItem does and
        returns its actual pixel width, instead of guessing via a
        per-character constant."""
        cls._ensure_qt_app()
        try:
            from PyQt6.QtWidgets import QGraphicsTextItem
        except ImportError:
            from PyQt5.QtWidgets import QGraphicsTextItem

        item = QGraphicsTextItem(text)
        item.setFont(cls._font_from_label_style(style))
        return item.boundingRect().width()

    @classmethod
    def _centered_label_x(cls, text: str, icon_width: int) -> int:
        try:
            text_width = cls._measured_text_width(text, LABEL_STYLE)
            return round((icon_width - text_width) / 2)
        except Exception as exc:
            print(f"Warning: Qt text measurement failed ({exc}), using linear fallback")
            return round(LABEL_X_FALLBACK_INTERCEPT + LABEL_X_FALLBACK_SLOPE * len(text))

    def _device_add(
        self,
        lab: Any,
        device_name: str,
        template_name: str,
        x: int | None = None,
        y: int | None = None,
    ) -> None:

        create_kwargs: dict[str, Any] = {
            "name": device_name,
            "template": template_name,
        }
        if x is not None:
            create_kwargs["x"] = x
        if y is not None:
            create_kwargs["y"] = y

        # --- Case where lab has create_node (GNS3 2.2+ REST API) ---
        if hasattr(lab, "create_node"):
            with self._patched_gns3fy_node_update():
                captured_stdout = io.StringIO()
                with contextlib.redirect_stdout(captured_stdout):
                    lab.create_node(**create_kwargs)

            # Filtered output (keep only non-"Created:" lines)
            for line in captured_stdout.getvalue().splitlines():
                if not line.startswith("Created:"):
                    print(line)

            try:
                # Look up the just-created node by node_id (not name): GNS3
                # may not preserve the requested name verbatim (e.g. names
                # containing several hyphens), so a name-based lookup can
                # silently return None and crash the position/label update.
                created_device = lab.nodes[-1] if getattr(lab, "nodes", None) else None
                if created_device is None or not getattr(created_device, "node_id", None):
                    raise RuntimeError("Unable to locate the newly created device.")

                node_id = created_device.node_id
                target_x = x if x is not None else getattr(created_device, "x", 0)
                target_y = y if y is not None else getattr(created_device, "y", 0)

                self._apply_position_and_label(
                    lambda: lab.get_node(node_id=node_id),
                    device_name,
                    target_x,
                    target_y,
                )

            except Exception as exc:
                print(
                    f"Error: unable to retrieve created device: "
                    f"{type(exc).__name__}: {exc}"
                )

            return

        # --- Fallback: gns3fy.Node ---
        if Node is None:
            raise RuntimeError("gns3fy is not installed")

        device = Node(
            project_id=getattr(lab, "project_id", None),
            connector=self.server,
            name=device_name,
            template=template_name,
            x=x,
            y=y,
        )
        if not device.project_id:
            raise RuntimeError("Unable to determine the project ID.")

        original_update = device.update

        def _rename_device_only(**kwargs: Any) -> None:
            device_name_value = kwargs.get("name", device_name)
            if not device.node_id:
                raise RuntimeError("Node creation did not return a node_id")

            update_kwargs: dict[str, Any] = {"name": device_name_value}
            if "x" in kwargs:
                update_kwargs["x"] = kwargs["x"]
            if "y" in kwargs:
                update_kwargs["y"] = kwargs["y"]

            device.update = original_update
            try:
                original_update(**update_kwargs)
            finally:
                device.update = _rename_device_only

        device.update = _rename_device_only
        device.create()

        try:
            def _refresh() -> Any:
                fresh = Node(
                    project_id=device.project_id,
                    connector=self.server,
                    node_id=device.node_id,
                )
                fresh.get()
                return fresh

            created_device = _refresh()
            target_x = x if x is not None else getattr(created_device, "x", 0)
            target_y = y if y is not None else getattr(created_device, "y", 0)

            self._apply_position_and_label(
                _refresh, device_name, target_x, target_y
            )

        except Exception as exc:
            print(
                f"Error: unable to retrieve created device (fallback): "
                f"{type(exc).__name__}: {exc}"
            )

    def _patch_gns3fy_link_create_once(self) -> None:
        if Link is None or hasattr(Link, "_gns3_cli_dunder_filter_patch"):
            return

        def _patched_link_create(link_self):
            if not link_self.connector:
                raise ValueError("Gns3Connector not assigned under 'connector'")
            if not link_self.project_id:
                raise ValueError("Need to submit project_id")

            _url = f"{link_self.connector.base_url}/projects/{link_self.project_id}/links"
            data = {
                key: value
                for key, value in link_self.__dict__.items()
                if key != "connector"
                if not key.startswith("__")
                if value is not None
            }
            _response = link_self.connector.http_call("post", _url, json_data=data)
            link_self._update(_response.json())

        Link.create = _patched_link_create
        setattr(Link, "_gns3_cli_dunder_filter_patch", True)

    def _resolve_port_binding(self, device_obj: Any, port_name: str) -> dict[str, Any] | None:
        for port in getattr(device_obj, "ports", []) or []:
            if isinstance(port, dict):
                if port.get("name") == port_name:
                    return {
                        "node_id": getattr(device_obj, "node_id", None),
                        "adapter_number": port.get("adapter_number"),
                        "port_number": port.get("port_number"),
                    }
            else:
                if getattr(port, "name", None) == port_name:
                    return {
                        "node_id": getattr(device_obj, "node_id", None),
                        "adapter_number": getattr(port, "adapter_number", None),
                        "port_number": getattr(port, "port_number", None),
                    }
        return None

    def _list_device_port_names(self, device_obj: Any) -> list[str]:
        names: list[str] = []
        for port in getattr(device_obj, "ports", []) or []:
            if isinstance(port, dict):
                name = port.get("name")
            else:
                name = getattr(port, "name", None)
            if name:
                names.append(str(name))
        return names

    def _format_link_endpoints(self, link_obj: Any, devices: list[Any]) -> str:
        endpoints = getattr(link_obj, "nodes", []) or []
        if len(endpoints) < 2:
            return "unknown endpoints"

        def _device_name_from_id(device_id: str | None) -> str:
            if not device_id:
                return "unknown"
            for device in devices:
                if getattr(device, "node_id", None) == device_id:
                    return getattr(device, "name", device_id)
            return device_id

        def _port_name_from_binding(device_id: str | None, adapter: Any, port: Any) -> str:
            if not device_id:
                return "unknown"
            for device in devices:
                if getattr(device, "node_id", None) != device_id:
                    continue
                for device_port in getattr(device, "ports", []) or []:
                    if isinstance(device_port, dict):
                        adapter_number = device_port.get("adapter_number")
                        port_number = device_port.get("port_number")
                        port_name = device_port.get("name")
                    else:
                        adapter_number = getattr(device_port, "adapter_number", None)
                        port_number = getattr(device_port, "port_number", None)
                        port_name = getattr(device_port, "name", None)

                    if adapter_number == adapter and port_number == port:
                        return str(port_name or f"a{adapter}/p{port}")
            return f"a{adapter}/p{port}"

        ep0 = endpoints[0]
        ep1 = endpoints[1]
        device0_id = ep0.get("node_id") if isinstance(ep0, dict) else None
        device1_id = ep1.get("node_id") if isinstance(ep1, dict) else None
        adapter0 = ep0.get("adapter_number") if isinstance(ep0, dict) else None
        adapter1 = ep1.get("adapter_number") if isinstance(ep1, dict) else None
        port0 = ep0.get("port_number") if isinstance(ep0, dict) else None
        port1 = ep1.get("port_number") if isinstance(ep1, dict) else None

        return (
            f"{_device_name_from_id(device0_id)}:{_port_name_from_binding(device0_id, adapter0, port0)}"
            f" <-> "
            f"{_device_name_from_id(device1_id)}:{_port_name_from_binding(device1_id, adapter1, port1)}"
        )

    def _resolve_link_port(self, lab: Any, device_name: str, port_name: str, action_name: str):
        device_obj, device_error = self._get_lab_device(lab, device_name, action_name)
        if device_error is not None:
            return None, device_error

        binding = self._resolve_port_binding(device_obj, port_name)
        if binding is None:
            available = ", ".join(self._list_device_port_names(device_obj)) or "none"
            return None, f"Error: Port {port_name} not found on device {device_name}. Available ports: {available}."

        return device_obj, None

    def _resolve_link_request(
        self,
        project_name: str,
        device_a: str,
        port_a: str,
        device_b: str,
        port_b: str,
        *,
        action_name: str,
    ):
        if not project_name:
            return None, "A project name is required"
        if not device_a or not device_b:
            return None, "Error: Both device names are required."
        if not port_a or not port_b:
            return None, "Error: Both port names are required."

        lab, error = self._load_open_project(project_name, action_name)
        if error is not None:
            return None, error

        _, device_a_error = self._resolve_link_port(lab, device_a, port_a, "read project devices")
        if device_a_error is not None:
            return None, device_a_error

        _, device_b_error = self._resolve_link_port(lab, device_b, port_b, "read project devices")
        if device_b_error is not None:
            return None, device_b_error

        return lab, None

    def _run_gns3fy_bannerless(self, operation: Callable[[], None], *, banner_prefix: str) -> None:
        captured_stdout = io.StringIO()
        with contextlib.redirect_stdout(captured_stdout):
            operation()

        for line in captured_stdout.getvalue().splitlines():
            if not line.startswith(banner_prefix):
                print(line)

    def _build_device_command_executor(
            self,
            device_type: str,
            *,
            cisco_command_settle_seconds: float | None = None,
            cisco_response_timeout_seconds: float | None = None,
            vpcs_command_settle_seconds: float | None = None,
            vpcs_response_timeout_seconds: float | None = None,
            qemu_os_type: Literal["linux", "microsoft"] | None = None,
            qemu_windows_console_encoding: str | None = None,
            qemu_agent_response_timeout_seconds: float | None = None,
            qemu_execution_timeout_seconds: float | None = None,
            qemu_status_poll_interval_seconds: float | None = None,
            qemu_sock_path: str | None = None,
            docker_execution_timeout_seconds: float | None = None,
        ) -> Callable[..., Any] | None:
            normalized_type = (device_type or "").strip().lower()

            kwargs: dict[str, Any] = {}

            if normalized_type in {"dynamips", "iou"}:
                if cisco_command_settle_seconds is not None:
                    kwargs["command_settle_seconds"] = cisco_command_settle_seconds
                if cisco_response_timeout_seconds is not None:
                    kwargs["response_timeout_seconds"] = cisco_response_timeout_seconds
                return partial(self.cisco_exec_cmd, **kwargs)

            if normalized_type == "qemu":
                if qemu_os_type is not None:
                    kwargs["os_type"] = qemu_os_type
                if qemu_windows_console_encoding is not None:
                    kwargs["windows_console_encoding"] = qemu_windows_console_encoding
                if qemu_agent_response_timeout_seconds is not None:
                    kwargs["agent_response_timeout_seconds"] = qemu_agent_response_timeout_seconds
                if qemu_execution_timeout_seconds is not None:
                    kwargs["execution_timeout_seconds"] = qemu_execution_timeout_seconds
                if qemu_status_poll_interval_seconds is not None:
                    kwargs["status_poll_interval_seconds"] = qemu_status_poll_interval_seconds
                if qemu_sock_path is not None:
                    kwargs["sock_path"] = qemu_sock_path
                return partial(self.qemu_exec_cmd, **kwargs)

            if normalized_type == "vpcs":
                if vpcs_command_settle_seconds is not None:
                    kwargs["command_settle_seconds"] = vpcs_command_settle_seconds
                if vpcs_response_timeout_seconds is not None:
                    kwargs["response_timeout_seconds"] = vpcs_response_timeout_seconds
                return partial(self.vpcs_exec_cmd, **kwargs)

            if normalized_type == "docker":
                if docker_execution_timeout_seconds is not None:
                    kwargs["execution_timeout_seconds"] = docker_execution_timeout_seconds
                return partial(self.docker_exec_cmd, **kwargs)

            return None

    def _run_console_command(
        self,
        device: _ConsoleNode,
        command: bytes,
        *,
        initial_delay: float = 1.5,
        read_timeout: float = 2.0,
        followup_commands: Sequence[tuple[bytes, float]] | None = None,
    ) -> tuple[int, str | None] :
        console_host = CONSOLE_HOST
        console_port = device.console

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((console_host, console_port))

                s.sendall(b"\r\n")
                time.sleep(0.3)
                try:
                    while True:
                        if not s.recv(SOCKET_RECV_CHUNK_SIZE):
                            break
                except TimeoutError:
                    pass

                s.settimeout(5.0)
                s.sendall(command)
                time.sleep(initial_delay)

                if followup_commands:
                    for followup_command, followup_delay in followup_commands:
                        s.sendall(followup_command)
                        time.sleep(followup_delay)

                output = ""
                s.settimeout(read_timeout)
                while True:
                    try:
                        chunk = s.recv(SOCKET_RECV_CHUNK_SIZE)
                        if not chunk:
                            break
                        output += chunk.decode("ascii", errors="ignore")
                    except TimeoutError:
                        break

            return 0, output

        except Exception as e:
            return 1, f"Unable to connect to the console ({console_host}:{console_port}): {e}"

    def _cisco_enable_password_followup(self, password: str) -> list[tuple[bytes, float]]:
        return [(f"{password}\r\n".encode("utf-8"), 1.0)]

    def _positive_float_or_default(
        self,
        value: float | None,
        default: float,
        option_name: str,
    ) -> float:
        if value is None:
            return default

        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"Error: '{option_name}' must be a positive number.") from exc

        if numeric <= 0:
            raise SystemExit(f"Error: '{option_name}' must be > 0.")

        return numeric

    def _valid_text_encoding_or_default(
        self,
        value: str | None,
        default: str,
        option_name: str,
    ) -> str:
        encoding = (value if value is not None else default).strip()
        if not encoding:
            raise SystemExit(f"Error: '{option_name}' requires a non-empty value.")

        try:
            codecs.lookup(encoding)
        except LookupError as exc:
            raise SystemExit(f"Error: '{option_name}' is not a known text encoding: '{encoding}'.") from exc

        return encoding

    def _parse_cli_attribute_value(
        self,
        raw_value: str,
        *,
        current_value: Any = None,
    ) -> Any:
        if current_value is not None:
            if isinstance(current_value, bool):
                normalized = raw_value.strip().lower()
                if normalized in {"1", "true", "t", "yes", "y", "on"}:
                    return True
                if normalized in {"0", "false", "f", "no", "n", "off"}:
                    return False
                return raw_value

            if isinstance(current_value, int) and not isinstance(current_value, bool):
                try:
                    return int(raw_value.strip())
                except ValueError:
                    return raw_value

            if isinstance(current_value, float):
                try:
                    return float(raw_value.strip())
                except ValueError:
                    return raw_value

            if isinstance(current_value, str):
                return raw_value

            if isinstance(current_value, (dict, list)):
                try:
                    return json.loads(raw_value)
                except json.JSONDecodeError:
                    return raw_value

        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            # Fall back to a plain string when the payload is not valid JSON.
            return raw_value

    def _select_attribute_or_full(
        self,
        data: Any,
        attribute: str | None,
        *,
        entity_label: str,
        entity_name: str,
    ) -> Any:
        """Return either the full JSON-safe data, or a single attribute's value.

        Shared by commands that expose an optional --attribute flag to
        narrow a JSON object down to one field instead of printing the
        whole thing (see device_attributes, template_attributes).
        """
        if attribute is None:
            return 0, data

        if not attribute.strip():
            return 1, "Error: '--attribute' requires a non-empty value."

        if not isinstance(data, dict) or attribute not in data:
            available = ", ".join(sorted(data)) if isinstance(data, dict) else "none"
            return 2, (
                f"Error: Attribute '{attribute}' not found on {entity_label} {entity_name}. "
                f"Available attributes: {available}."
            )

        return 0, json.dumps(data[attribute], indent=2, ensure_ascii=False)

    def _exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        usage: str,
        comment_prefixes: tuple[str, ...],
        executor: Callable[..., tuple[int, str | None]],
        stream_output: bool = False,
    ) -> tuple[int, str | None]:

        if not project_name or not device_name or not file_name:
            return 1, usage

        if not os.path.isfile(file_name):
            return 2, f"Error: File '{file_name}' not found."

        with open(file_name, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                command = raw_line.strip()
                if not command or command.startswith(comment_prefixes):
                    continue

                print(f"[CMD] {command}")

                code, message = executor(project_name, device_name, command)

                # Display message if requested
                if stream_output and message:
                    sys.stdout.write(message)

                # If error → stop immediately
                if code != 0:
                    return code, message

        return 0, None

    def _qemu_get_os_type(
        self,
        project_name: str,
        device_name: str,
        agent_response_timeout_seconds: float | None = None,
        sock_path: str | None = None,
    ):
        """
        Detect the guest OS type through qemu-guest-agent.

        Args:
            sock_path: Optional pre-resolved socket path (see
                _qemu_resolve_socket). Pass this when the caller already
                resolved/verified the socket, to avoid doing it twice.

        Returns:
            "linux"
            "microsoft"
        """

        if not project_name or not device_name:
            raise SystemExit("Usage: qemu_get_os_type <project_name> <device_name>")

        effective_request_timeout = self._positive_float_or_default(
            agent_response_timeout_seconds,
            DEFAULT_TIMEOUT,
            "agent_response_timeout_seconds",
        )

        try:
            if sock_path is None:
                sock_path, error = self._qemu_resolve_socket(project_name, device_name)
                if error is not None:
                    return error
                assert sock_path is not None  # Informs Mypy that sock_path is a guaranteed str

            request_payload = {
                "execute": "guest-get-osinfo"
            }

            result = _qga_request(
                sock_path,
                request_payload,
                timeout_seconds=effective_request_timeout,
            )

            result_data = json.loads(result or "{}")
            os_info = result_data.get("return", {})

            os_id = str(os_info.get("id", "")).lower()
            os_name = str(os_info.get("name", "")).lower()

            if "windows" in os_id or "windows" in os_name:
                return "microsoft"

            return "linux"

        except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
            print(str(exc))
            raise SystemExit(1)

    def projects(self, status: Literal["opened", "closed"] | None = None) -> tuple[int, str | None]:
        """List project names, optionally filtered by status.

         Usage:
             gns3-cli projects
             gns3-cli projects --status=opened
             gns3-cli projects --status=closed
        """
        if self.server is None:
            return 1, "gns3fy is not installed"

        normalized_status = None
        if status is not None:
            normalized_status = status.strip().lower()
            if normalized_status not in {"opened", "closed"}:
                return 2, "Error: '--status' must be 'opened' or 'closed'."

        try:
            projects = self.server.get_projects()

            if normalized_status is None:
                names = [p["name"] for p in projects]
                return 0, ("\n".join(names) if names else None)

            filtered = [
                p["name"]
                for p in projects
                if (p.get("status") or "").strip().lower() == normalized_status
            ]

            return 0, ("\n".join(filtered) if filtered else None)

        except Exception as exc:
            return 3, self._format_gns3_error(exc, "list the available projects")

    def templates(self) -> tuple[int, str | None]:
        """List the available templates in GNS3."""
        if self.server is None:
            return 1, "gns3fy is not installed"

        try:
            names = [template["name"] for template in self.server.get_templates()]
            return 0, ("\n".join(names) if names else None)

        except Exception as exc:
            return 2, self._format_gns3_error(exc, "list the available templates")

    def project_open(self, project_name: str, startall: bool = False) -> tuple[int, str | None] :
        """Open a project, optionally starting all its devices.

        Usage:
            gns3-cli project_open untitled
            gns3-cli project_open untitled --startall=yes
            gns3-cli project_open untitled --startall=true
        """
        # Reuse of _parse_cli_attribute_value to interpret yes/true/1/no/false/0
        should_start = (
            self._parse_cli_attribute_value(startall, current_value=False)
            if isinstance(startall, str)
            else bool(startall)
        )

        def _open_operation(lab):
            lab.open()
            if should_start:
                lab.start_nodes()

        success_message = (
            "All devices in project '{project_name}' have been started."
            if should_start
            else "Project '{project_name}' has been loaded."
        )

        return self._apply_project_action(
            project_name,
            action_name="load the project",
            operation=_open_operation,
            success_message=success_message,
        )

    def project_close(self, project_name) -> tuple[int, str | None] :
        """Close a project in GNS3.

        Usage:
            gns3-cli project_close untitled
        """
        return self._apply_project_action(
            project_name,
            action_name="close the project",
            operation=lambda lab: lab.close(),
            success_message="Project '{project_name}' has been closed.",
        )

    def _get_projects_path(self) -> str | None:
        """Retrieve the configured projects directory path from GNS3 server settings."""
        try:
            url = f"{self.server.base_url}/settings"
            settings = self.server.http_call("get", url).json()
            if isinstance(settings, dict):
                # GNS3 v2 nests server configuration under the 'Server' key
                projects_path = settings.get("Server", {}).get("projects_path") or settings.get("projects_path")
                if projects_path:
                    return projects_path
        except Exception:
            pass

        # Fallback to standard user directories if settings cannot be fetched
        for fallback in [Path.home() / "projects", Path.home() / "GNS3" / "projects"]:
            if fallback.exists():
                return str(fallback)

        return None

    def _patch_gns3fy_project_create_once(self) -> None:
        """Patch gns3fy Project.create to send valid JSON schema fields."""
        if Project is None or hasattr(Project, "_gns3_cli_project_create_patch"):
            return

        def _patched_project_create(project_self):
            if not project_self.connector:
                raise ValueError("Gns3Connector not assigned under 'connector'")

            url = f"{project_self.connector.base_url}/projects"

            # Force show_interface_labels to be a strict boolean
            show_labels = getattr(project_self, "show_interface_labels", True)
            if show_labels is None:
                show_labels = True

            data = {
                "name": project_self.name,
                "show_interface_labels": bool(show_labels),
            }

            path_attr = getattr(project_self, "path", None)
            if path_attr:
                data["path"] = str(path_attr)

            response = project_self.connector.http_call("post", url, json_data=data)
            project_self._update(response.json())

        Project.create = _patched_project_create
        setattr(Project, "_gns3_cli_project_create_patch", True)

    def project_create(
        self,
        project_name: str,
        custom_path: str | None = None,
        show_interface_labels: bool = True,
    ) -> tuple[int, str | None] :
        """Create an empty project in GNS3 with interface labels enabled by default.

        Usage:
            gns3-cli project_create untitled
            gns3-cli project_create untitled --custom_path=/home/user/my_projects
            gns3-cli project_create untitled --show_interface_labels=false
            gns3-cli project_create untitled --no-show_interface_labels
        """
        if self.server is None:
            return 1, "gns3fy is not installed"

        if not project_name:
            return 2, "A project name is required"

        # Sanitize show_interface_labels if passed as None by the CLI framework
        if show_interface_labels is None:
            show_interface_labels = True

        # Resolve target directory path
        target_path = custom_path
        if not target_path:
            base_path = self._get_projects_path()
            if base_path:
                target_path = str(Path(base_path) / project_name)

        kwargs = {
            "name": project_name,
            "show_interface_labels": show_interface_labels,
        }
        if target_path:
            kwargs["path"] = target_path

        try:
            if Project is None:
                self.server.create_project(**kwargs)
            else:
                self._patch_gns3fy_project_create_once()
                lab = Project(connector=self.server, **kwargs)
                lab.create()
        except Exception as exc:
            return 3, self._format_gns3_error(exc, "create the project")

        return 0, f"Project '{project_name}' created (interface labels: {show_interface_labels})."

    def project_delete(self, project_name: str, confirme: bool = False) -> tuple[int, str | None] :
        """
        Delete a GNS3 project.

        Usage:
            gns3-cli project_delete untitled --confirme=true
        """
        if self.server is None:
            return 1, "gns3fy is not installed"

        if not project_name:
            return 2, "A project name is required"

        # Require confirmation
        if not confirme:
            return 3, (
                "'--confirme=true' is required to delete."
            )

        # Load project (opened or closed)
        lab, error = self._load_project(project_name, "delete the project")
        if error is not None:
            return 4, error

        # Check project status
        status = (getattr(lab, "status", None) or "").strip().lower()
        if status != "closed":
            return 5, f"Error: Project '{project_name}' is opened. Close it before deleting."

        # Perform deletion
        try:
            # gns3fy exposes delete() on the Project object
            lab.delete()
            return 0, f"Project '{project_name}' has been deleted."
        except Exception as exc:
            return 6, self._format_gns3_error(exc, "delete the project")

    def template_clone(
        self,
        source_template_name: str,
        cloned_template_name: str,
    ) -> tuple[int, str | None]:
        """Clone an existing GNS3 template

        Usage:
            gns3-cli template_clone template newtemplate
        """

        if self.server is None:
            return 1, "gns3fy is not installed"

        if not source_template_name or not cloned_template_name:
            return 2, "Usage: template_clone <source_template> <cloned_template>"

        try:
            # Retrieve the source template
            source = self.server.get_template(name=source_template_name)
            if source is None:
                return 3, f"Error: source template '{source_template_name}' not found."

            # Check if the cloned template already exists
            existing = self.server.get_template(name=cloned_template_name)
            if existing is not None:
                return 4, f"Error: template '{cloned_template_name}' already exists."

            # Copy all fields except those that must not be duplicated
            clone_params = {
                key: value
                for key, value in source.items()
                if key not in ("template_id", "name")
            }

            # Set the new template name
            clone_params["name"] = cloned_template_name

            # Create the cloned template
            created = self.server.create_template(**clone_params)
            if created is None:
                return 5, f"Error: unable to create cloned template '{cloned_template_name}'."

            return 0, (
                f"Template '{source_template_name}' successfully cloned as "
                f"'{cloned_template_name}'."
            )

        except Exception as exc:
            return 6, f"Error while cloning template: {exc}"

    def template_delete(
        self, template_name: str, confirme: bool = False
    ) -> tuple[int, str | None]:
        """Delete a GNS3 template.

        Usage:
            gns3-cli template_delete newtemplate --confirme=true
        """

        if self.server is None:
            return 1, "gns3fy is not installed"

        if not template_name:
            return 2, "Usage: template_delete <template_name>"

        if not confirme:
            return 4, "'--confirme=true' is required to delete."

        try:
            # Retrieve the template by name
            template = self.server.get_template(name=template_name)
            if template is None:
                return 3, f"Error: template '{template_name}' not found."

            # Delete the template
            self.server.delete_template(name=template_name)

            return 0, f"Template '{template_name}' has been deleted."

        except Exception as exc:
            return 5, f"Error while deleting template '{template_name}': {exc}"

    def template_attributes(self, template_name: str, attribute: str | None = None) -> tuple[int, str | None] :
        """Display all available JSON information for a template, or only the value of one attribute.

        Usage:
            gns3-cli template_attributes Debian
            gns3-cli template_attributes Debian --attribute=template_type
        """
        template, error = self._resolve_template(template_name, "read the template")
        if error is not None:
            return 1, error

        return self._select_attribute_or_full(
            _to_json_safe(template),
            attribute,
            entity_label="template",
            entity_name=template_name,
        )

    def template_set_attribute(
        self,
        template_name: str,
        attribute_name: str,
        attribute_value: str,
    ) -> tuple[int, str | None] :
        """Update a template attribute in GNS3.

        Usage:
            gns3-cli template_set_attribute Debian name Debian-v2
            gns3-cli template_set_attribute Debian ram 2048
            gns3-cli template_set_attribute Debian symbol :/symbols/qemu_guest.svg
        """
        template, error = self._resolve_template(template_name, "update the template")
        if error is not None:
            return 1, error
        if template is None:
            return 2, f"Error: Template '{template_name}' not found."

        if not attribute_name:
            return 3, "Error: An attribute name is required."

        if attribute_name == "template_id":
            return 4, f"Error: Attribute '{attribute_name}' cannot be updated from this command."

        template_id = template.get("template_id")
        if not template_id:
            return 5, f"Error: Unable to determine the template ID for '{template_name}'."

        # Strip surrounding quotes (single or double) if present
        if (
            len(attribute_value) >= 2
            and attribute_value[0] == attribute_value[-1]
            and attribute_value[0] in ("'", '"')
        ):
            attribute_value = attribute_value[1:-1]

        current_attribute_value = template.get(attribute_name)

        update_value = self._parse_cli_attribute_value(
            attribute_value,
            current_value=current_attribute_value,
        )

        try:
            # Build the full updated template dict and PUT it directly,
            # mirroring what gns3fy's own update_template() does
            # internally. We can't just call update_template(name=...,
            # **kwargs): its 'name' lookup parameter would silently
            # swallow an attempt to update the template's own 'name'
            # attribute (renaming) instead of applying it.
            updated_template = dict(template)
            updated_template[attribute_name] = update_value
            self.server.http_call(
                "put",
                url=f"{self.server.base_url}/templates/{template_id}",
                json_data=updated_template,
            )
        except Exception as exc:
            return 6, self._format_gns3_error(exc, "update the template")

        return 0, f"Template '{template_name}' attribute '{attribute_name}' has been updated."

    def devices(
        self,
        project_name: str,
        status: Literal["started", "stopped"] | None = None,
        device_type: str | None = None,
        name_only: bool = False,
    ) -> tuple[int, str | None]:
        """Display devices in a project, optionally filtered by runtime status.
             gns3-cli devices untitled
             gns3-cli devices untitled --status=started
             gns3-cli devices untitled --status=stopped
             gns3-cli devices untitled --device_type=dynamips
             gns3-cli devices untitled --name_only=true
             gns3-cli devices untitled --status=started --device_type=dynamips --name_only=true
        """

        lab, error = self._load_project(project_name, "read the project")
        if error is not None:
            return 1, error

        normalized_status = None
        if status is not None:
            normalized_status = status.strip().lower()
            if normalized_status not in {"started", "stopped"}:
                return 2, "Error: '--status' must be 'started' or 'stopped'."

        normalized_device_type = None
        if device_type is not None:
            normalized_device_type = device_type.strip().lower()
            if not normalized_device_type:
                return 3, "Error: '--device_type' requires a non-empty value."

        result: list[str] = []

        for device in lab.nodes:
            device_status = (getattr(device, "status", "") or "").strip().lower()
            if normalized_status is not None and device_status != normalized_status:
                continue

            current_device_type = (getattr(device, "node_type", "") or "").strip().lower()
            if normalized_device_type is not None and current_device_type != normalized_device_type:
                continue

            if name_only:
                result.append(str(getattr(device, "name", "")))
            else:
                result.append(
                    f"name={device.name};"
                    f"status={device.status};"
                    f"type={device.node_type};"
                    f"console={device.console_type}"
                )

        # Aucun device → pas de message
        if not result:
            return 0, None

        # Devices → texte multi-ligne
        return 0, "\n".join(result)


    def _apply_open_project_action(
        self,
        project_name: str,
        *,
        action_name: str,
        operation: Callable[[Any], None],
        success_message: str,
    ) -> tuple[int, str | None] :
        lab, error = self._load_open_project(
            project_name,
            action_name,
        )

        if error is not None:
            return 1, error

        try:
            operation(lab)
        except Exception as exc:
            return 2, self._format_gns3_error(
                exc,
                action_name,
            )

        return 0, success_message.format(
            project_name=project_name
        )

    def devices_start(self, project_name) -> tuple[int, str | None] :
        """Start all devices in a project, but only if the project is opened."""
        return self._apply_open_project_action(
            project_name,
            action_name="start the devices",
            operation=lambda lab: lab.start_nodes(),
            success_message=(
                "All devices in project "
                "'{project_name}' have been started."
            ),
        )

    def devices_stop(self, project_name) -> tuple[int, str | None] :
        """Stop all devices in a project, but only if the project is opened."""
        return self._apply_open_project_action(
            project_name,
            action_name="stop the devices",
            operation=lambda lab: lab.stop_nodes(),
            success_message=(
                "All devices in project "
                "'{project_name}' have been stopped."
            ),
        )

    def devices_suspend(self, project_name) -> tuple[int, str | None] :
        """Suspend all devices in a project, but only if the project is opened."""
        return self._apply_open_project_action(
            project_name,
            action_name="suspend the devices",
            operation=lambda lab: lab.suspend_nodes(),
            success_message=(
                "All devices in project "
                "'{project_name}' have been suspended."
            ),
        )

    def devices_connect(
        self,
        project_name: str,
        device_a: str,
        port_a: str,
        device_b: str,
        port_b: str,
    ) -> tuple[int, str | None] :
        """Create a link between 2 devices in a project using their port names.

        Usage:
            gns3-cli devices_connect untitled R1 Gi0/0 R2 Gi0/1
        """
        self._patch_gns3fy_link_create_once()

        lab, error = self._resolve_link_request(
            project_name,
            device_a,
            port_a,
            device_b,
            port_b,
            action_name="creating a link",
        )
        if error is not None:
            return 1, error

        links, links_error = self._get_lab_links(lab, "read project links")
        if links_error is not None:
            return 2, links_error
        if links is None:
            return 3, "Error: Unable to retrieve project links."

        try:
            self._run_gns3fy_bannerless(
                lambda: lab.create_link(
                    node_a=device_a,
                    port_a=port_a,
                    node_b=device_b,
                    port_b=port_b,
                ),
                banner_prefix="Created Link-ID:",
            )
        except Exception as exc:
            message = str(exc).strip()
            if message.startswith("At least one port is used"):
                link_id_match = re.search(r"ID:\s*([0-9a-fA-F-]+)", message)
                blocking_link_id = link_id_match.group(1) if link_id_match else None
                if blocking_link_id:
                    for link in links:
                        if getattr(link, "link_id", None) == blocking_link_id:
                            endpoints = self._format_link_endpoints(link, getattr(lab, "nodes", []) or [])
                            return 4, (
                                f"Error: At least one port is already used by link {blocking_link_id} "
                                f"({endpoints})."
                            )
                return 5, "Error: At least one of the requested ports is already used by another link."

            if "__pydantic_initialised__" in message:
                return 6, (
                    "Error: gns3fy generated an invalid link payload for this environment. "
                    "The local compatibility patch did not apply."
                )

            return 7, self._format_gns3_error(exc, "create the link")

        return 0, (
            f"Link created in project '{project_name}': "
            f"{device_a}:{port_a} <-> {device_b}:{port_b}."
        )

    def devices_disconnect(
        self,
        project_name: str,
        device_a: str,
        port_a: str,
        device_b: str,
        port_b: str,
    ) -> tuple[int, str | None] :
        """Remove the link between 2 devices in a project using their port names.

        Usage:
            gns3-cli devices_disconnect untitled R1 Gi0/0 R2 Gi0/1
        """
        lab, error = self._resolve_link_request(
            project_name,
            device_a,
            port_a,
            device_b,
            port_b,
            action_name="removing a link",
        )
        if error is not None:
            return 1, error

        try:
            self._run_gns3fy_bannerless(
                lambda: lab.delete_link(
                    node_a=device_a,
                    port_a=port_a,
                    node_b=device_b,
                    port_b=port_b,
                ),
                banner_prefix="Deleted Link-ID:",
            )
        except Exception as exc:
            return 2, self._format_gns3_error(exc, "remove the link")

        return 0, (
            f"Link removed in project '{project_name}': "
            f"{device_a}:{port_a} <-> {device_b}:{port_b}."
        )

    def device_add(
        self,
        project_name: str,
        device_name: str,
        template_name: str,
        x: int | None = None,
        y: int | None = None,
    ) -> tuple[int, str | None] :
        """Add a device to a project from an existing template.

        Usage:
            gns3-cli device_add untitled R1 "Debian"
            gns3-cli device_add untitled R1 "Debian" --x=120 --y=-80
        """
        if self.server is None:
            return 1, "gns3fy is not installed"

        if not project_name:
            return 2, "A project name is required"

        if not device_name:
            return 3, "A device name is required"

        if not template_name:
            return 4, "A template name is required"

        lab, error = self._load_open_project(project_name, "adding a device")
        if error is not None:
            return 5, error

        if any(getattr(device, "name", None) == device_name for device in lab.nodes):
            return 6, f"Error: a device named '{device_name}' already exists in project '{project_name}'."

        try:
            template = self.server.get_template(name=template_name)
            if template is None:
                return 7, f"Error: Template {template_name} not found."
            self._device_add(
                lab,
                device_name,
                template_name,
                x=x,
                y=y,
            )
        except Exception as exc:
            return 8, self._format_gns3_error(exc, "add the device")

        return 0, f"Node '{device_name}' has been added to project '{project_name}' from template '{template_name}'."

    def device_del(
        self, project_name: str, device_name: str, confirme: bool = False
    ) -> tuple[int, str | None] :
        """
        Delete a device from a GNS3 project.

        Usage:
            gns3-cli device_del untitled R1 --confirme=true
        """
        if self.server is None:
            return 1, "gns3fy is not installed"

        if not project_name:
            return 2, "A project name is required"

        if not device_name:
            return 3, "A device name is required"

        if not confirme:
            return 4, "'--confirme=true' is required to delete."

        # Load project (must be opened)
        lab, error = self._load_open_project(project_name, "deleting a device")
        if error is not None:
            return 5, error

        try:
            # Find the device
            device = lab.get_node(device_name)
            if device is None:
                return 6, f"Error: Device '{device_name}' not found in project '{project_name}'."

            # Delete the device
            device.delete()

            return 0, f"Device '{device_name}' has been deleted from project '{project_name}'."

        except Exception as exc:
            return 7, self._format_gns3_error(exc, "delete the device")

    def device_interfaces(self, project_name: str, device_name: str) -> tuple[int, str | None]:
        """Return the list of interface names (eth0, eth1, ...) for a device."""

        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action="read the device",
        )
        if error is not None:
            return 1, error

        interfaces = []
        for port in getattr(device, "ports", []):
            name = port.get("name") or port.get("short_name")
            if name:
                interfaces.append(name)

        if not interfaces:
            return 0, None

        return 0, "\n".join(interfaces)

    def device_connections(
        self,
        project_name: str,
        device_name: str,
    ) -> tuple[int, str | None] :
        """
        Return all interfaces of a device and what they are connected to.
        Output format :
            "interface:device:interface"
        or:
            "interface:none:none"
        """

        # Load project
        lab, error = self._load_project(project_name, "read project links")
        if error is not None:
            return 1, error

        # Retrieve device
        device = lab.get_node(name=device_name)
        if device is None:
            return 2, f"Error: Device '{device_name}' not found."

        # List all interfaces of the device
        interfaces = [p.get("name") for p in getattr(device, "ports", [])]

        # Retrieve all links
        links, links_error = self._get_lab_links(lab, "read project links")
        if links_error is not None:
            return 1, links_error
        if links is None:
            return 1, "Error: Unable to retrieve project links."

        results = []

        # For each interface, find its connection
        for iface in interfaces:
            connected = False

            for link in links:
                nodes = getattr(link, "nodes", None)
                if not nodes:
                    continue

                for ep in nodes:
                    ep_node_id = ep.get("node_id")

                    # Extract label text
                    raw_label = ep.get("label")
                    if isinstance(raw_label, dict):
                        ep_label = raw_label.get("text", "")
                    else:
                        ep_label = raw_label or ""

                    node = lab.get_node(node_id=ep_node_id)
                    if node is None:
                        continue

                    # Match our device/interface
                    if node.name == device_name and ep_label == iface:
                        # Find the other endpoint
                        for ep2 in nodes:
                            if ep2 is not ep:
                                other_node = lab.get_node(node_id=ep2.get("node_id"))

                                raw_label2 = ep2.get("label")
                                if isinstance(raw_label2, dict):
                                    other_label = raw_label2.get("text", "")
                                else:
                                    other_label = raw_label2 or ""

                                if other_node:
                                    results.append(f"{iface}:{other_node.name}:{other_label}")
                                    connected = True
                                    break

                        break  # stop scanning this link

                if connected:
                    break  # stop scanning links for this interface

            if not connected:
                results.append(f"{iface}:none:none")

        return 0, "\n".join(results)

    def device_attributes(self, project_name: str, device_name: str, attribute: str | None = None) -> tuple[int, str | None] :
        """Display all available JSON information for a project's device, or only the value of one attribute.

        Usage:
            gns3-cli device_attributes untitled R1
            gns3-cli device_attributes untitled R1 --attribute=node_type
        """
        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action="read the device",
        )
        if error is not None:
            return 1, error

        return self._select_attribute_or_full(
            _to_json_safe(device),
            attribute,
            entity_label="device",
            entity_name=device_name,
        )

    def device_set_attribute(
        self,
        project_name: str,
        device_name: str,
        attribute_name: str,
        attribute_value: str,
    ) -> tuple[int, str | None] :
        """Update a stopped device attribute in a project.

        Usage:
            gns3-cli device_set_attribute untitled R1 name R1-BACKUP
            gns3-cli device_set_attribute untitled R1 x 120
            gns3-cli device_set_attribute untitled R1 properties '{"ram": 1024}'
            gns3-cli device_set_attribute untitled R1 symbol :/symbols/router.svg
        """
        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action="update the device",
        )
        if error is not None:
            return 1, error

        if not attribute_name:
            return 2, "Error: An attribute name is required."

        if attribute_name in {"connector", "node_id", "project_id"}:
            return 3, f"Error: Attribute '{attribute_name}' cannot be updated from this command."

        status = (getattr(device, "status", "") or "").strip().lower()
        if status != "stopped":
            return 4, (
                f"Error: Device {device_name} must be stopped before updating attributes "
                f"(Status: {getattr(device, 'status', 'unknown')})."
            )

        # Strip surrounding quotes (single or double) if present
        if (
            len(attribute_value) >= 2
            and attribute_value[0] == attribute_value[-1]
            and attribute_value[0] in ("'", '"')
        ):
            attribute_value = attribute_value[1:-1]

        current_attribute_value = getattr(device, attribute_name, None)

        update_value = self._parse_cli_attribute_value(
            attribute_value,
            current_value=current_attribute_value,
        )
        update_payload = {attribute_name: update_value}

        try:
            device.update(**update_payload)
        except Exception as exc:
            return 5, self._format_gns3_error(exc, "update the device")

        return 0, (
            f"Node '{device_name}' attribute '{attribute_name}' has been updated "
            f"in project '{project_name}'."
        )

    def _device_action(
        self,
        project_name: str,
        device_name: str,
        *,
        project_action: str,
        device_method: str,
        success_message: str,
    ) -> tuple[int, str | None] :
        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action=project_action,
        )

        if error is not None:
            return 1, error

        try:
            getattr(device, device_method)()
        except Exception as exc:
            return 2, self._format_gns3_error(exc, project_action)

        return 0, success_message.format(device_name=device_name)

    def device_start(self, project_name, device_name) -> tuple[int, str | None] :
        """Start the device passed in parameter.

        Usage:
            gns3-cli device_start untitled R1
        """
        return self._device_action(
            project_name,
            device_name,
            project_action="start the device",
            device_method="start",
            success_message="Node '{device_name}' has been started.",
        )

    def device_stop(self, project_name, device_name) -> tuple[int, str | None] :
        """Stop the device passed in parameter.

        Usage:
            gns3-cli device_stop untitled R1
        """
        return self._device_action(
            project_name,
            device_name,
            project_action="stop the device",
            device_method="stop",
            success_message="Node '{device_name}' has been stopped.",
        )

    def device_suspend(self, project_name, device_name) -> tuple[int, str | None] :
        """Suspend the device passed in parameter.

        Usage:
            gns3-cli device_suspend untitled R1
        """
        return self._device_action(
            project_name,
            device_name,
            project_action="suspend the device",
            device_method="suspend",
            success_message="Node '{device_name}' has been suspended.",
        )

    def device_is_running(self, project_name: str, device_name: str) -> tuple[int, str | None] :
        """Check whether a device in a GNS3 project is currently running.

        Usage:
            gns3-cli device_is_running untitled R1
        """

        if self.server is None:
            return 2, "gns3fy is not installed"

        if not project_name:
            return 3, "A project name is required"

        if not device_name:
            return 4, "A device name is required"

        lab, error = self._load_open_project(project_name, "checking device status")
        if error is not None:
            return 5, error

        try:
            node = lab.get_node(device_name)
            if node is None:
                return 6, f"Device '{device_name}' not found in project '{project_name}'."

            status = (node.status or "").lower()

            if status in {"started", "running"}:
                return 0, "running"

            return 1, "not_running"

        except Exception as exc:
            return 7, (self._format_gns3_error(exc, "check the device status") + "\n")

    def device_exec_cmd(
        self,
        project_name: str,
        device_name: str,
        command: str,
        cisco_command_settle_seconds: float | None = None,
        cisco_response_timeout_seconds: float | None = None,
        vpcs_command_settle_seconds: float | None = None,
        vpcs_response_timeout_seconds: float | None = None,
        qemu_os_type: Literal["linux", "microsoft"] | None = None,
        qemu_windows_console_encoding: str | None = None,
        qemu_agent_response_timeout_seconds: float | None = None,
        qemu_execution_timeout_seconds: float | None = None,
        qemu_status_poll_interval_seconds: float | None = None,
        docker_execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """Execute a command on a device by auto-detecting its GNS3 device type.

        Usage:
            gns3-cli device_exec_cmd untitled R1 "show ip route"
            gns3-cli device_exec_cmd untitled R1 "show running-config" --cisco_response_timeout_seconds=8.0
            gns3-cli device_exec_cmd untitled Debian-1 "apt update" --qemu_execution_timeout_seconds=60.0
            gns3-cli device_exec_cmd untitled Win11-1 "ipconfig"
            gns3-cli device_exec_cmd untitled Win11-1 "ipconfig" --qemu_os_type=microsoft --qemu_windows_console_encoding=cp437
            gns3-cli device_exec_cmd untitled DDebian-1 "apt update" --docker_execution_timeout_seconds=20
        """
        if not project_name or not device_name or not command:
            return 1, "Usage: device_exec_cmd <project_name> <device_name> <command>"

        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action="access the project",
        )
        if error is not None:
            return 2, error

        device_type = (getattr(device, "node_type", "") or "").strip().lower()

        effective_qemu_os_type: Literal["linux", "microsoft"] | None = qemu_os_type
        qemu_sock_path = None
        if device_type == "qemu":
            if effective_qemu_os_type is not None:
                os_str = effective_qemu_os_type.strip().lower()
                if os_str not in {"linux", "microsoft"}:
                    return 3, "Error: '--qemu_os_type' must be 'linux' or 'microsoft'."
                effective_qemu_os_type = "microsoft" if os_str == "microsoft" else "linux"
            else:
                # OS auto-detection needs the socket now (for _qemu_get_os_type)
                # and the command execution right after will need it again, so
                # resolve/verify it once here and reuse it for both instead of
                # letting each call re-resolve it.
                try:
                    qemu_sock_path, sock_error = self._qemu_resolve_socket(project_name, device_name)
                except (FileNotFoundError, RuntimeError) as exc:
                    return 4, str(exc)
                if sock_error is not None:
                    return 5, sock_error

                detected_os_type = self._qemu_get_os_type(
                    project_name,
                    device_name,
                    agent_response_timeout_seconds=qemu_agent_response_timeout_seconds,
                    sock_path=qemu_sock_path,
                )
                if detected_os_type == "microsoft":
                    effective_qemu_os_type = "microsoft"
                elif detected_os_type == "linux":
                    effective_qemu_os_type = "linux"
                else:
                    return 6, detected_os_type

        executor = self._build_device_command_executor(
            device_type,
            cisco_command_settle_seconds=cisco_command_settle_seconds,
            cisco_response_timeout_seconds=cisco_response_timeout_seconds,
            vpcs_command_settle_seconds=vpcs_command_settle_seconds,
            vpcs_response_timeout_seconds=vpcs_response_timeout_seconds,
            qemu_os_type=effective_qemu_os_type,
            qemu_windows_console_encoding=qemu_windows_console_encoding,
            qemu_agent_response_timeout_seconds=qemu_agent_response_timeout_seconds,
            qemu_execution_timeout_seconds=qemu_execution_timeout_seconds,
            qemu_status_poll_interval_seconds=qemu_status_poll_interval_seconds,
            qemu_sock_path=qemu_sock_path,
            docker_execution_timeout_seconds=docker_execution_timeout_seconds,
        )
        if executor is None:
            return 6, f"Error: Unsupported device type '{device_type or 'unknown'}' for device '{device_name}'."

        return executor(project_name, device_name, command)

    def device_exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        cisco_command_settle_seconds: float | None = None,
        cisco_response_timeout_seconds: float | None = None,
        vpcs_command_settle_seconds: float | None = None,
        vpcs_response_timeout_seconds: float | None = None,
        qemu_os_type: Literal["linux", "microsoft"] | None = None,
        qemu_windows_console_encoding: str | None = None,
        qemu_agent_response_timeout_seconds: float | None = None,
        qemu_execution_timeout_seconds: float | None = None,
        qemu_status_poll_interval_seconds: float | None = None,
        docker_execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """Execute commands from a file on a device by auto-detecting its GNS3 device type.

        Usage:
            gns3-cli device_exec_file untitled R1 commands.txt
            gns3-cli device_exec_file untitled R1 commands.txt --cisco_response_timeout_seconds=8.0
            gns3-cli device_exec_file untitled Debian-1 commands.txt --qemu_execution_timeout_seconds=60.0
            gns3-cli device_exec_file untitled Win11-1 commands.txt --qemu_os_type=microsoft --qemu_windows_console_encoding=cp437
            gns3-cli device_exec_file untitled DDebian-1 commands.txt --docker_execution_timeout_seconds=20
        """
        usage = "Usage: device_exec_file <project_name> <device_name> <file_name>"
        if not project_name or not device_name or not file_name:
            return 1, usage

        if not os.path.isfile(file_name):
            return 2, f"Error: File '{file_name}' not found."

        device, error = self._get_device(
            project_name,
            device_name,
            expected_type=None,
            project_action="access the project",
        )
        if error is not None:
            return 3, error

        device_type = (getattr(device, "node_type", "") or "").strip().lower()

        effective_qemu_os_type: Literal["linux", "microsoft"] | None = qemu_os_type
        qemu_sock_path = None
        if device_type == "qemu":
            if effective_qemu_os_type is not None:
                os_str = effective_qemu_os_type.strip().lower()
                if os_str not in {"linux", "microsoft"}:
                    return 4, "Error: '--qemu_os_type' must be 'linux' or 'microsoft'."
                effective_qemu_os_type = "microsoft" if os_str == "microsoft" else "linux"
            else:
                # Resolve/verify the socket once here and reuse it for
                # OS detection and for every command executed from the file,
                # instead of letting each call re-resolve it.
                try:
                    qemu_sock_path, sock_error = self._qemu_resolve_socket(project_name, device_name)
                except (FileNotFoundError, RuntimeError) as exc:
                    return 5, str(exc)
                if sock_error is not None:
                    return 6, sock_error

                detected_os_type = self._qemu_get_os_type(
                    project_name,
                    device_name,
                    agent_response_timeout_seconds=qemu_agent_response_timeout_seconds,
                    sock_path=qemu_sock_path,
                )
                if detected_os_type == "microsoft":
                    effective_qemu_os_type = "microsoft"
                elif detected_os_type == "linux":
                    effective_qemu_os_type = "linux"
                else:
                    return 7, detected_os_type

        executor = self._build_device_command_executor(
            device_type,
            cisco_command_settle_seconds=cisco_command_settle_seconds,
            cisco_response_timeout_seconds=cisco_response_timeout_seconds,
            vpcs_command_settle_seconds=vpcs_command_settle_seconds,
            vpcs_response_timeout_seconds=vpcs_response_timeout_seconds,
            qemu_os_type=effective_qemu_os_type,
            qemu_windows_console_encoding=qemu_windows_console_encoding,
            qemu_agent_response_timeout_seconds=qemu_agent_response_timeout_seconds,
            qemu_execution_timeout_seconds=qemu_execution_timeout_seconds,
            qemu_status_poll_interval_seconds=qemu_status_poll_interval_seconds,
            qemu_sock_path=qemu_sock_path,
            docker_execution_timeout_seconds=docker_execution_timeout_seconds,
        )
        if executor is None:
            return 8, f"Error: Unsupported device type '{device_type or 'unknown'}' for device '{device_name}'."

        normalized_type = device_type or ""
        if normalized_type in {"dynamips", "iou"}:
            comment_prefixes: tuple[str, ...] = ("!",)
            stream_output = True
        elif normalized_type == "vpcs":
            comment_prefixes = ("#", ";")
            stream_output = True
        else:
            comment_prefixes = ("#",)
            stream_output = False

        return self._exec_file(
            project_name,
            device_name,
            file_name,
            usage,
            comment_prefixes,
            executor,
            stream_output=stream_output,
        )

    def switch_interfaces(self, project_name: str, device_name: str) -> tuple[int, str | None]:
        """Display all interfaces of an ethernet_switch with VLAN or trunk mode.

        Usage:
            gns3-cli switch_interfaces untitled Switch1
        """

        # Retrieve the device
        device, error = self._get_device(
            project_name,
            device_name,
            "ethernet_switch",
        )
        if error:
            return 1, error

        ports_mapping = device.properties.get("ports_mapping")
        if not ports_mapping:
            return 2, f"Error: switch '{device_name}' has no ports_mapping."

        lines: list[str] = []

        for entry in ports_mapping:
            name = entry.get("name", "")
            port_type = entry.get("type", "")
            vlan = entry.get("vlan", "")

            # Interpret mode
            if port_type == "dot1q":
                mode = "trunk"
                vlan_str = ""   # trunk has no VLAN number in display
            else:
                mode = "vlan"
                vlan_str = str(vlan)

            lines.append(f"{name};{mode};{vlan_str}")

        return 0, "\n".join(lines)

    def switch_set_vlan(self, project_name: str, device_name: str, port_name: str, vlan) -> tuple[int, str | None] :
        """Set the VLAN or trunk mode of a port on an ethernet_switch.

        Usage:
            gns3-cli switch_set_vlan untitled Switch1 Ethernet0 5
            gns3-cli switch_set_vlan untitled Switch1 Ethernet0 trunk
        """

        device, error = self._get_device(
            project_name,
            device_name,
            "ethernet_switch",
        )
        if error:
            return 1, error

        ports_mapping = device.properties.get("ports_mapping")
        if not ports_mapping:
            return 2, f"Error: switch '{device_name}' has no ports_mapping."

        new_mapping = []
        found = False

        for entry in ports_mapping:
            if entry.get("name") == port_name:
                updated = dict(entry)

                # trunk mode
                if isinstance(vlan, str) and vlan.strip().lower() == "trunk":
                    updated["type"] = "dot1q"
                    updated["vlan"] = 1  # GNS3 requires an integer, never null

                # access mode
                else:
                    try:
                        vlan_int = int(vlan)
                    except ValueError:
                        return 3, f"Error: VLAN must be an integer or 'trunk'. Got: {vlan}"

                    updated["type"] = "access"
                    updated["vlan"] = vlan_int

                new_mapping.append(updated)
                found = True
            else:
                new_mapping.append(entry)

        if not found:
            return 4, f"Error: port '{port_name}' not found on switch '{device_name}'."

        try:
            device.update(properties={"ports_mapping": new_mapping})
            if isinstance(vlan, str) and vlan.strip().lower() == "trunk":
                return 0, f"Port '{port_name}' set to trunk mode."
            else:
                return 0, f"Port '{port_name}' VLAN updated to {vlan}."
        except Exception as exc:
            return 5, self._format_gns3_error(exc, f"update VLAN/trunk on port '{port_name}'")


    def cisco_wake(self, project_name: str, device_name: str) -> tuple[int, str | None] :
        """Wake the Cisco terminal, disable pagination (--More--) and clear the buffer."""
        device, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 1, error

        return self._run_console_command(device, b"\r\nterminal length 0\r\n", initial_delay=1.0)

    def cisco_enable(self, project_name: str, device_name: str) -> tuple[int, str | None] :
        """Put the Cisco device into privileged mode (enable)."""
        device, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 1, error

        return self._run_console_command(device, b"enable\r\n")

    def cisco_enable_password(self, project_name: str, device_name: str, password: str) -> tuple[int, str | None] :
        """Run 'enable' and provide a password when the device asks for it."""
        if password is None or password == "":
            return 1, "Error: A password is required."

        device, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 2, error

        return self._run_console_command(
            device,
            b"enable\r\n",
            initial_delay=0.5,
            read_timeout=2.0,
            followup_commands=self._cisco_enable_password_followup(password),
        )

    def cisco_mode_conf_t(self, project_name: str, device_name: str) -> tuple[int, str | None] :
        """Wake Cisco console, enter enable mode, then run 'conf term'."""
        _, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 1, error

        sequence = [
            ("terminal length 0", lambda: self.cisco_wake(project_name, device_name)),
            ("enable", lambda: self.cisco_enable(project_name, device_name)),
            ("conf term", lambda: self.cisco_exec_cmd(project_name, device_name, "conf term")),
        ]

        outputs: list[str] = []
        for command, runner in sequence:
            print(f"[CMD] {command}")
            result = runner()

            if isinstance(result, str) and (
                result.startswith("Error:") or result.startswith("Unable to connect")
            ):
                return 2, result

            if isinstance(result, str):
                outputs.append(result)
                if result:
                    sys.stdout.write(result)

        return 0, "".join(outputs)

    def cisco_show_running_config(self, project_name: str, device_name: str) -> tuple[int, str | None] :
        """Retrieve the running-config of a router via the TCP console."""
        return self.cisco_exec_cmd(
            project_name,
            device_name,
            "show running-config",
            disable_paging=True,
        )

    def cisco_exec_cmd(
        self,
        project_name: str,
        device_name: str,
        command: str,
        disable_paging: bool = False,
        command_settle_seconds: float | None = None,
        response_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Execute a custom command on a Cisco device via its TCP console.

        Usage:
            gns3-cli cisco_exec_cmd untitled R1 "show ip interface brief"
            gns3-cli cisco_exec_cmd untitled R1 "show ip interface brief | include up"
            gns3-cli cisco_exec_cmd untitled R1 "show running-config" --disable_paging=true
            gns3-cli cisco_exec_cmd untitled R1 "show version" --command_settle_seconds=2.0
            gns3-cli cisco_exec_cmd untitled R1 "show running-config" --disable_paging=true --response_timeout_seconds=8.0
        """
        device, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 1, error

        if disable_paging:
            command_payload = f"\r\nterminal length 0\r\n{command}\r\n"
            effective_initial_delay = self._positive_float_or_default(
                command_settle_seconds,
                1.0,
                "command_settle_seconds",
            )
            effective_read_timeout = self._positive_float_or_default(
                response_timeout_seconds,
                5.0,
                "response_timeout_seconds",
            )
            run_kwargs: dict[str, Any] = {
                "initial_delay": effective_initial_delay,
                "read_timeout": effective_read_timeout,
            }
        else:
            command_payload = f"{command}\r\n"
            effective_initial_delay = self._positive_float_or_default(
                command_settle_seconds,
                1.5,
                "command_settle_seconds",
            )
            run_kwargs = {"initial_delay": effective_initial_delay}
            if response_timeout_seconds is not None:
                run_kwargs["read_timeout"] = self._positive_float_or_default(
                    response_timeout_seconds,
                    2.0,
                    "response_timeout_seconds",
                )

        cmd_bytes = command_payload.encode("ascii")
        return self._run_console_command(
            device,
            cmd_bytes,
            **run_kwargs,
        )

    def cisco_exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        disable_paging: bool = False,
        command_settle_seconds: float | None = None,
        response_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Execute Cisco commands from a file.

        Empty lines, whitespace-only lines, and lines starting with '!' are ignored.
        """
        _, error = self._get_device(project_name, device_name, expected_type=None, project_action="access the project")
        if error is not None:
            return 1, error

        kwargs: dict[str, Any] = {"disable_paging": disable_paging}
        if command_settle_seconds is not None:
            kwargs["command_settle_seconds"] = command_settle_seconds
        if response_timeout_seconds is not None:
            kwargs["response_timeout_seconds"] = response_timeout_seconds

        executor: _NodeExecutor = (
            partial(self.cisco_exec_cmd, **kwargs)
            if kwargs != {"disable_paging": False}
            else self.cisco_exec_cmd
        )

        return self._exec_file(
            project_name,
            device_name,
            file_name,
            "Usage: cisco_exec_file <project_name> <device_name> <file_name>",
            ("!",),
            executor,
            stream_output=True,
        )

    def vpcs_exec_cmd(
        self,
        project_name: str,
        device_name: str,
        command: str,
        command_settle_seconds: float | None = None,
        response_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Execute a custom command on a VPCS device via its TCP console.

        Usage:
            gns3-cli vpcs_exec_cmd untitled R1 "show ip"
            gns3-cli vpcs_exec_cmd untitled R1 "ip 10.0.0.1/24"
            gns3-cli vpcs_exec_cmd untitled PC1 "show ip" --command_settle_seconds=0.2 --response_timeout_seconds=3.0
        """
        device, error = self._get_device(
            project_name,
            device_name,
            "vpcs",
        )
        if error:
            return 1, error

        effective_initial_delay = self._positive_float_or_default(
            command_settle_seconds,
            0.1,
            "command_settle_seconds",
        )
        effective_read_timeout = self._positive_float_or_default(
            response_timeout_seconds,
            2.0,
            "response_timeout_seconds",
        )

        cmd_bytes = f"{command}\r\n".encode("ascii")
        run_kwargs: dict[str, Any] = {"initial_delay": effective_initial_delay}
        if response_timeout_seconds is not None:
            run_kwargs["read_timeout"] = effective_read_timeout

        return self._run_console_command(device, cmd_bytes, **run_kwargs)

    def vpcs_exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        command_settle_seconds: float | None = None,
        response_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """Execute VPCS commands from a file via vpcs_exec_cmd (comments start with '#' or ';')."""

        _, error = self._get_device(
            project_name,
            device_name,
            "vpcs",
        )
        if error:
            return 1, error

        kwargs: dict[str, Any] = {}
        if command_settle_seconds is not None:
            kwargs["command_settle_seconds"] = command_settle_seconds
        if response_timeout_seconds is not None:
            kwargs["response_timeout_seconds"] = response_timeout_seconds

        executor = partial(self.vpcs_exec_cmd, **kwargs) if kwargs else self.vpcs_exec_cmd
        return self._exec_file(
            project_name,
            device_name,
            file_name,
            "Usage: vpcs_exec_file <project_name> <device_name> <file_name>",
            ("#", ";"),
            executor,
            stream_output=True,
        )

    def _docker_container_name(self, project_name: str, device_name: str, device) -> str:
        """
        Build the Docker container name GNS3 uses for a resolved docker
        device: 'GNS3.<device_name>.<project_id>' (see gns3-server's
        DockerVM.docker_name property). Shared by docker_exec_cmd and the
        docker_file_download / docker_file_upload commands, so the naming
        convention only lives in one place.
        """
        project_id = self._get_project_id(project_name)
        device_name_value = getattr(device, "name", device_name) or device_name
        return f"GNS3.{device_name_value}.{project_id}"

    def _docker_exec_binary(
        self,
        container_name: str,
        args: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Run 'docker exec -i <container_name> <args...>' without any text
        decoding, so binary file content passed via stdin/stdout survives
        untouched. Arguments are passed directly (no shell involved), so
        paths with spaces or shell-special characters don't need quoting.
        Shared by docker_file_download and docker_file_upload.
        """
        return subprocess.run(
            ["docker", "exec", "-i", container_name, *args],
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )

    def docker_exec_cmd(
        self,
        project_name: str,
        device_name: str,
        command: str,
        execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Execute a shell command inside the Docker container associated with a GNS3 device.

        Usage:
            gns3-cli docker_exec_cmd untitled DDebian-1 "ip link"
            gns3-cli docker_exec_cmd untitled DDebian-1 "ip address add 10.0.0.1/24 dev eth0"
            gns3-cli docker_exec_cmd untitled DDebian-1 "apt update" --execution_timeout_seconds=20
        """
        if not device_name or not command:
            sig = inspect.signature(self.docker_exec_cmd)
            doc = (self.docker_exec_cmd.__doc__ or "").strip()
            print("docker_exec_cmd help:\n")
            if doc:
                print(doc)
            print(f"\nUsage: {sys.argv[0]} docker_exec_cmd {sig}")
            return 1, None

        device, error = self._get_device(
            project_name,
            device_name,
            "docker",
        )
        if error:
            return 2, error


        try:
            resolved_container = self._docker_container_name(project_name, device_name, device)

        except Exception:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return result.returncode, None

            resolved_container = None
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                container_id, container_display_name = line.split("\t", 1)
                if device_name in {container_id, container_display_name}:
                    resolved_container = container_display_name
                    break
                if container_display_name.startswith(f"GNS3.{device_name}."):
                    resolved_container = container_display_name
                    break

            if not resolved_container:
                return 3, None

        try:
            effective_timeout = None
            if execution_timeout_seconds is not None:
                effective_timeout = self._positive_float_or_default(
                    execution_timeout_seconds,
                    1.0,
                    "execution_timeout_seconds",
                )

            assert resolved_container is not None
            args = ["docker", "exec", "-i", resolved_container]
            args.extend(shlex.split(command))

            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                timeout=effective_timeout,
            )

            # Forward container output
            if process.stdout:
                sys.stdout.write(process.stdout)
            if process.stderr:
                sys.stderr.write(process.stderr)

            # Return the exit code directly (no error message)
            return process.returncode, None

        except subprocess.TimeoutExpired:
            return 124, None  # standard timeout code

        except (FileNotFoundError, RuntimeError, ValueError):
            return 1, None

    def docker_exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """Execute Docker device commands from a file via docker_exec_cmd (comments start with '#')."""

        _, error = self._get_device(
            project_name,
            device_name,
            "docker",
        )
        if error:
            return 1, error


        kwargs: dict[str, Any] = {}
        if execution_timeout_seconds is not None:
            kwargs["execution_timeout_seconds"] = execution_timeout_seconds

        executor = partial(self.docker_exec_cmd, **kwargs) if kwargs else self.docker_exec_cmd
        return self._exec_file(
            project_name,
            device_name,
            file_name,
            "Usage: docker_exec_file <project_name> <device_name> <file_name>",
            ("#",),
            executor,
        )

    def docker_file_download(
        self,
        project_name: str,
        device_name: str,
        remote_file: str,
        local_file: str,
        execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Download a file from the Docker container associated with a GNS3 device.

        Usage:
            gns3-cli docker_file_download untitled DDebian-1 /etc/hostname ./hostname.txt
            gns3-cli docker_file_download untitled DDebian-1 /var/log/syslog ./syslog.log --execution_timeout_seconds=20
        """
        usage = "Usage: docker_file_download <project_name> <device_name> <remote_file> <local_file>"
        if not project_name or not device_name or not remote_file or not local_file:
            return 1, usage

        device, error = self._get_device(
            project_name,
            device_name,
            "docker",
        )
        if error:
            return 2, error

        try:
            effective_timeout = None
            if execution_timeout_seconds is not None:
                effective_timeout = self._positive_float_or_default(
                    execution_timeout_seconds,
                    1.0,
                    "execution_timeout_seconds",
                )

            container_name = self._docker_container_name(project_name, device_name, device)

            process = self._docker_exec_binary(
                container_name,
                ["cat", remote_file],
                timeout_seconds=effective_timeout,
            )
            # Forward container output (stdout only)
            if process.stderr:
                sys.stdout.buffer.write(process.stderr)
            # If docker exec failed → return code + message
            if process.returncode != 0:
                return process.returncode, f"docker exec failed with exit code {process.returncode}"

            with open(local_file, "wb") as f:
                f.write(process.stdout)
        except subprocess.TimeoutExpired as exc:
            if os.path.exists(local_file):
                with contextlib.suppress(OSError):
                    os.remove(local_file)
            return 3, f"docker exec timed out after {exc.timeout} seconds"
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            if os.path.exists(local_file):
                with contextlib.suppress(OSError):
                    os.remove(local_file)
            return 4, str(exc)
        except OSError as exc:
            return 5, f"Error: unable to write to local file '{local_file}': {exc}"

        downloaded_bytes = os.path.getsize(local_file)
        return 0, (
            f"File '{remote_file}' downloaded from '{device_name}' "
            f"({downloaded_bytes} bytes) to '{local_file}'."
        )

    def docker_file_upload(
        self,
        project_name: str,
        device_name: str,
        local_file: str,
        remote_file: str,
        execution_timeout_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """
        Upload a file to the Docker container associated with a GNS3 device.

        Usage:
            gns3-cli docker_file_upload untitled DDebian-1 ./hostname.txt /tmp/hostname.txt
            gns3-cli docker_file_upload untitled DDebian-1 ./big.iso /tmp/big.iso --execution_timeout_seconds=20
        """
        usage = "Usage: docker_file_upload <project_name> <device_name> <local_file> <remote_file>"
        if not project_name or not device_name or not local_file or not remote_file:
            return 1 , usage

        if not os.path.isfile(local_file):
            return 2, f"Error: File '{local_file}' not found."

        device, error = self._get_device(
            project_name,
            device_name,
            "docker",
        )
        if error:
            return 3, error

        try:
            effective_timeout = None
            if execution_timeout_seconds is not None:
                effective_timeout = self._positive_float_or_default(
                    execution_timeout_seconds,
                    1.0,
                    "execution_timeout_seconds",
                )

            container_name = self._docker_container_name(project_name, device_name, device)

            with open(local_file, "rb") as f:
                local_data = f.read()

            # 'tee' both writes stdin to the target file and echoes it back
            # to stdout; we don't need that echo, only the exit code.
            process = self._docker_exec_binary(
                container_name,
                ["tee", remote_file],
                input_bytes=local_data,
                timeout_seconds=effective_timeout,
            )
            
            # Forward stdout only
            if process.stderr:
                sys.stdout.buffer.write(process.stderr)
            # If docker exec failed → return code + message
            if process.returncode != 0:
                return process.returncode, f"docker exec failed with exit code {process.returncode}"

            # Best-effort: 'tee' creates the remote file with the
            # container's default umask, so mirror the local file's
            # permission bits instead of leaving that to chance. Not
            # fatal if it fails (e.g. chmod missing in a minimal image).
            with contextlib.suppress(Exception):
                local_mode = stat.S_IMODE(os.stat(local_file).st_mode)
                self._docker_exec_binary(
                    container_name,
                    ["chmod", oct(local_mode)[2:], remote_file],
                    timeout_seconds=effective_timeout,
                )
        except subprocess.TimeoutExpired as exc:
            return 4, f"docker exec timed out after {exc.timeout} seconds"
        except (FileNotFoundError, RuntimeError, ValueError, OSError) as exc:
            return 5, str(exc)

        return 0, (
            f"File '{local_file}' uploaded to '{device_name}' "
            f"({len(local_data)} bytes) as '{remote_file}'."
        )

    def qemu_wait_qga(
        self,
        project_name: str,
        device_name: str,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float | None = None,
        sock_path: str | None = None,
    ) -> tuple[int, str | None] :
        """
        Wait until the QEMU Guest Agent responds.

        Usage:
            gns3-cli qemu_wait_qga untitled R1
            gns3-cli qemu_wait_qga untitled R1 --timeout_seconds=30 --poll_interval_seconds=0.5

        """
        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error:
            return 1, error

        effective_poll = self._positive_float_or_default(
            poll_interval_seconds,
            QGA_STATUS_POLL_INTERVAL,
            "poll_interval_seconds",
        )

        try:
            # Resolve socket if not provided
            if sock_path is None:
                sock_path, error = self._qemu_resolve_socket(project_name, device_name)
                if error is not None:
                    return 2, error
                assert sock_path is not None # Informs Mypy that sock_path is a guaranteed str

            # Compute deadline only if timeout is finite
            if timeout_seconds is not None:
                deadline = time.monotonic() + timeout_seconds

            while True:
                # Stop if finite timeout exceeded
                if timeout_seconds is not None and time.monotonic() >= deadline:
                    return 3, f"Timeout: QEMU Guest Agent did not respond within {timeout_seconds} seconds."

                try:
                    payload = {"execute": "guest-ping"}
                    result = _qga_request(sock_path, payload, timeout_seconds=timeout_seconds or DEFAULT_TIMEOUT)

                    if result:
                        return 0, f"QEMU Guest Agent for '{device_name}' is now responsive."

                except Exception:
                    # Agent not ready yet → ignore and retry
                    pass

                time.sleep(effective_poll)

        except Exception as exc:
            return 4, self._format_gns3_error(exc, "wait for QEMU Guest Agent")

    def qemu_exec_cmd(
        self,
        project_name: str,
        device_name: str,
        command: str,
        os_type: Literal["linux", "microsoft"] = QEMU_DEFAULT_OS_TYPE,
        windows_console_encoding: str = QEMU_WINDOWS_CONSOLE_ENCODING,
        agent_response_timeout_seconds: float | None = None,
        execution_timeout_seconds: float | None = None,
        status_poll_interval_seconds: float | None = None,
        sock_path: str | None = None,
    ) -> tuple[int, str | None] :
        """
        Execute a shell command inside a QEMU guest via qemu-guest-agent.

        Usage:
            gns3-cli qemu_exec_cmd untitled Debian-1 "ip link"
            gns3-cli qemu_exec_cmd untitled Win11-1 "ipconfig" --os_type=microsoft
            gns3-cli qemu_exec_cmd untitled Win11-1 "ipconfig" --os_type=microsoft --windows_console_encoding=cp437
            gns3-cli qemu_exec_cmd untitled Debian-1 "apt update" --agent_response_timeout_seconds=3.0 --execution_timeout_seconds=60.0
            gns3-cli qemu_exec_cmd untitled Debian-1 "uname -a" --status_poll_interval_seconds=0.2
        """
        if not project_name or not device_name or not command:
            return 1, "Usage: qemu_exec_cmd <project_name> <device_name> <command>"

        normalized_os_type = (os_type or "linux").strip().lower()
        if normalized_os_type not in {"linux","microsoft"}:
            return 2, "Error: '--os_type' must be 'linux' or 'microsoft'."

        effective_request_timeout = self._positive_float_or_default(
            agent_response_timeout_seconds,
            DEFAULT_TIMEOUT,
            "agent_response_timeout_seconds",
        )
        effective_max_wait_seconds = self._positive_float_or_default(
            execution_timeout_seconds,
            QGA_MAX_WAIT_SECONDS,
            "execution_timeout_seconds",
        )
        effective_poll_interval = self._positive_float_or_default(
            status_poll_interval_seconds,
            QGA_STATUS_POLL_INTERVAL,
            "status_poll_interval_seconds",
        )
        effective_windows_console_encoding = self._valid_text_encoding_or_default(
            windows_console_encoding,
            QEMU_WINDOWS_CONSOLE_ENCODING,
            "windows_console_encoding",
        )

        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error:
            return 3, error

        try:
            if sock_path is None:
                sock_path, error = self._qemu_resolve_socket(project_name, device_name)
                if error is not None:
                    return 4, error
                assert sock_path is not None # Informs Mypy that sock_path is a guaranteed str

            # Command based on the selected OS
            if os_type.lower() == "microsoft":
                exec_path = "cmd.exe"
                exec_args = ["/c", command]
            else:
                exec_path = "/bin/sh"
                exec_args = ["-c", command]

            request_payload = {
                "execute": "guest-exec",
                "arguments": {
                    "path": exec_path,
                    "arg": exec_args,
                    "capture-output": True,
                },
            }

            result = _qga_request(sock_path, request_payload, timeout_seconds=effective_request_timeout)
            result_data = json.loads(result or "{}")
            pid = result_data.get("return", {}).get("pid")
            if not pid:
                return 5, f"Error guest-exec\n{result}"

            status_data = {}
            deadline = time.monotonic() + effective_max_wait_seconds
            timed_out = False
            while time.monotonic() < deadline:
                status_payload = {
                    "execute": "guest-exec-status",
                    "arguments": {"pid": pid},
                }
                status_result = _qga_request(
                    sock_path,
                    status_payload,
                    timeout_seconds=effective_request_timeout,
                )
                status_data = json.loads(status_result or "{}")
                if status_data.get("return", {}).get("exited") is True:
                    break
                time.sleep(effective_poll_interval)
            else:
                timed_out = True
            
            if timed_out:
                return 6, f"Timeout waiting for process {pid}"

            status_return = status_data.get("return", {})
            exitcode = status_return.get("exitcode", 255)
            out_data = status_return.get("out-data", "")
            err_data = status_return.get("err-data", "")

            # The guest console encodes text with its own OS-specific charset:
            # Linux shells write UTF-8, but Windows' cmd.exe writes the
            # console's OEM code page (see QEMU_WINDOWS_CONSOLE_ENCODING above,
            # overridable per-call with --windows_console_encoding).
            output_encoding = effective_windows_console_encoding if os_type.lower() == "microsoft" else "utf-8"

            if out_data:
                sys.stdout.write(base64.b64decode(out_data.encode("utf-8")).decode(output_encoding, errors="replace"))
            if err_data:
                sys.stderr.write(base64.b64decode(err_data.encode("utf-8")).decode(output_encoding, errors="replace"))

            return exitcode, None
        except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
            return 7, str(exc)

    def qemu_exec_file(
        self,
        project_name: str,
        device_name: str,
        file_name: str,
        os_type: Literal["linux", "microsoft"] = "linux",
        windows_console_encoding: str = QEMU_WINDOWS_CONSOLE_ENCODING,
        agent_response_timeout_seconds: float | None = None,
        execution_timeout_seconds: float | None = None,
        status_poll_interval_seconds: float | None = None,
    ) -> tuple[int, str | None] :
        """Execute QEMU commands from a file via qemu_exec_cmd (comments start with '#')."""
        usage = "Usage: qemu_exec_file <project_name> <device_name> <file_name>"
        if not project_name or not device_name or not file_name:
            return 1, usage

        if not os.path.isfile(file_name):
            return 2, f"Error: File '{file_name}' not found."

        raw_os_type = os_type or "linux"
        normalized_os_type = raw_os_type.strip().lower()
        if normalized_os_type not in {"linux", "microsoft"}:
            return 3, "Error: '--os_type' must be 'linux' or 'microsoft'."

        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error:
            return 4, error

        # Resolve/verify the socket once for the whole file instead of
        # letting qemu_exec_cmd re-resolve/re-check it for every single line.
        try:
            sock_path, error = self._qemu_resolve_socket(project_name, device_name)
        except (FileNotFoundError, RuntimeError) as exc:
            return 5, str(exc)
        if error is not None:
            return 6, error
        assert sock_path is not None # Informs Mypy that sock_path is a guaranteed str

        kwargs: dict[str, Any] = {
            "os_type": normalized_os_type,
            "windows_console_encoding": windows_console_encoding,
            "sock_path": sock_path,
        }
        if agent_response_timeout_seconds is not None:
            kwargs["agent_response_timeout_seconds"] = agent_response_timeout_seconds
        if execution_timeout_seconds is not None:
            kwargs["execution_timeout_seconds"] = execution_timeout_seconds
        if status_poll_interval_seconds is not None:
            kwargs["status_poll_interval_seconds"] = status_poll_interval_seconds

        executor = partial(self.qemu_exec_cmd, **kwargs)
        return self._exec_file(
            project_name,
            device_name,
            file_name,
            usage,
            ("#",),
            executor,
        )

    def _qemu_open_remote_file(
        self,
        sock_path: str,
        remote_file: str,
        mode: str,
        timeout_seconds: float,
    ) -> int:
        """
        Open a remote file through qemu-guest-agent and return
        its handle.
        """

        payload = {
            "execute": "guest-file-open",
            "arguments": {
                "path": remote_file,
                "mode": mode,
            },
        }

        result = _qga_request(
            sock_path,
            payload,
            timeout_seconds=timeout_seconds,
        )

        data = json.loads(result or "{}")

        handle = data.get("return")

        if handle is None:
            raise RuntimeError(
                f"Error guest-file-open '{remote_file}'\n{result}"
            )

        return handle

    def _qemu_close_remote_file(
        self,
        sock_path: str,
        handle: int,
        timeout_seconds: float,
    ) -> None:
        """
        Close a remote qemu-guest-agent file handle.
        """

        payload = {
            "execute": "guest-file-close",
            "arguments": {
                "handle": handle,
            },
        }

        _qga_request(
            sock_path,
            payload,
            timeout_seconds=timeout_seconds,
        )


    def qemu_file_download(
        self,
        project_name: str,
        device_name: str,
        remote_file: str,
        local_file: str,
        agent_response_timeout_seconds: float | None = None,
        read_chunk_size: int | None = None,
        sock_path: str | None = None,
    ) -> tuple[int, str | None] :
        """
        Download a file from a QEMU guest via qemu-guest-agent.

        Usage:
            gns3-cli qemu_file_download untitled Debian-1 /etc/hostname ./hostname.txt
            gns3-cli qemu_file_download untitled Debian-1 /var/log/syslog ./syslog.log --read_chunk_size=131072
            gns3-cli qemu_file_download untitled Debian-1 /etc/hostname ./hostname.txt --agent_response_timeout_seconds=5.0
        """
        usage = "Usage: qemu_file_download <project_name> <device_name> <remote_file> <local_file>"
        if not project_name or not device_name or not remote_file or not local_file:
            return 1, usage

        effective_request_timeout = self._positive_float_or_default(
            agent_response_timeout_seconds,
            DEFAULT_TIMEOUT,
            "agent_response_timeout_seconds",
        )

        if read_chunk_size is None:
            effective_chunk_size = QGA_FILE_READ_CHUNK_SIZE
        elif read_chunk_size > 0:
            effective_chunk_size = read_chunk_size
        else:
            return 2, "Error: '--read_chunk_size' must be > 0."

        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error:
            return 3, error

        bytes_written = 0
        try:
            if sock_path is None:
                sock_path, sock_error = self._qemu_resolve_socket(project_name, device_name)
                if sock_error is not None:
                    return 4, sock_error
                assert sock_path is not None # Informs Mypy that sock_path is a guaranteed str

            handle = self._qemu_open_remote_file(
                sock_path,
                remote_file,
                "r",
                effective_request_timeout,
            )

            try:
                # Read the file back block by block until EOF, writing the
                # decoded bytes to the local file as they arrive.
                with open(local_file, "wb") as local_handle:
                    while True:
                        read_payload = {
                            "execute": "guest-file-read",
                            "arguments": {"handle": handle, "count": effective_chunk_size},
                        }
                        read_result = _qga_request(
                            sock_path, read_payload, timeout_seconds=effective_request_timeout
                        )
                        read_data = json.loads(read_result or "{}")
                        read_return = read_data.get("return")
                        if read_return is None:
                            return 5, f"Error guest-file-read\n{read_result}"

                        chunk_b64 = read_return.get("buf-b64", "")
                        if chunk_b64:
                            chunk = base64.b64decode(chunk_b64.encode("utf-8"))
                            local_handle.write(chunk)
                            bytes_written += len(chunk)

                        if read_return.get("eof"):
                            break
            finally:
                self._qemu_close_remote_file(
                    sock_path,
                    handle,
                    effective_request_timeout,
                )

        except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
            if os.path.exists(local_file):
                with contextlib.suppress(OSError):
                    os.remove(local_file)
            return 6, str(exc)
        except OSError as exc:
            return 7, f"Error: unable to write to local file '{local_file}': {exc}"

        return 0, f"File '{remote_file}' downloaded from '{device_name}' ({bytes_written} bytes) to '{local_file}'."

    def qemu_file_upload(
        self,
        project_name: str,
        device_name: str,
        local_file: str,
        remote_file: str,
        agent_response_timeout_seconds: float | None = None,
        write_chunk_size: int | None = None,
        sock_path: str | None = None,
    ) -> tuple[int, str | None] :
        """
        Upload a file to a QEMU guest via qemu-guest-agent.

        Usage:
            gns3-cli qemu_file_upload untitled Debian-1 ./hostname.txt /tmp/hostname.txt
            gns3-cli qemu_file_upload untitled Debian-1 ./big.iso /tmp/big.iso --write_chunk_size=131072
            gns3-cli qemu_file_upload untitled Debian-1 ./hostname.txt /tmp/hostname.txt --agent_response_timeout_seconds=5.0
        """
        usage = "Usage: qemu_file_upload <project_name> <device_name> <local_file> <remote_file>"
        if not project_name or not device_name or not local_file or not remote_file:
            return 1, usage

        if not os.path.isfile(local_file):
            return 2, f"Error: File '{local_file}' not found."

        effective_request_timeout = self._positive_float_or_default(
            agent_response_timeout_seconds,
            DEFAULT_TIMEOUT,
            "agent_response_timeout_seconds",
        )

        if write_chunk_size is None:
            effective_chunk_size = QGA_FILE_WRITE_CHUNK_SIZE
        elif write_chunk_size > 0:
            effective_chunk_size = write_chunk_size
        else:
            return 3, "Error: '--write_chunk_size' must be > 0."

        _, error = self._get_device(
            project_name,
            device_name,
            "qemu",
        )
        if error:
            return 4, error

        bytes_sent = 0
        try:
            if sock_path is None:
                sock_path, sock_error = self._qemu_resolve_socket(project_name, device_name)
                if sock_error is not None:
                    return 5, sock_error
                assert sock_path is not None # Informs Mypy that sock_path is a guaranteed str

            handle = self._qemu_open_remote_file(
                sock_path,
                remote_file,
                "w",
                effective_request_timeout,
            )

            try:
                # Send the local file block by block until it is fully sent.
                with open(local_file, "rb") as local_handle:
                    while True:
                        chunk = local_handle.read(effective_chunk_size)
                        if not chunk:
                            break

                        write_payload = {
                            "execute": "guest-file-write",
                            "arguments": {
                                "handle": handle,
                                "buf-b64": base64.b64encode(chunk).decode("ascii"),
                            },
                        }
                        write_result = _qga_request(
                            sock_path, write_payload, timeout_seconds=effective_request_timeout
                        )
                        write_data = json.loads(write_result or "{}")
                        write_return = write_data.get("return")
                        if write_return is None:
                            return 6, f"Error guest-file-write\n{write_result}"

                        bytes_sent += len(chunk)
            finally:
                self._qemu_close_remote_file(
                    sock_path,
                    handle,
                    effective_request_timeout,
                )

        except (FileNotFoundError, RuntimeError, TimeoutError) as exc:
            return 7, str(exc)
        except OSError as exc:
            return 8, f"Error: unable to read local file '{local_file}': {exc}"

        return 0, f"File '{local_file}' uploaded to '{device_name}' ({bytes_sent} bytes) as '{remote_file}'."

    def _find_qemu_base_disk_image(self, file_name: str) -> str | None:
        """Search QEMU_DEFAULT_HARDDISK_PATH recursively for a file named file_name.

        Equivalent to: find "${DEFAULT_PATH_HARDDISK}" -name "${fileDisk}" -print -quit
        """
        if not os.path.isdir(QEMU_DEFAULT_HARDDISK_PATH):
            return None

        for root, _dirs, files in os.walk(QEMU_DEFAULT_HARDDISK_PATH):
            if file_name in files:
                return os.path.join(root, file_name)

        return None

    def _qemu_img_backing_chain_format(self, file_path: str) -> str | None:
        """Return the file format of the last image in file_path's backing chain.

        Equivalent to:
            qemu-img info --backing-chain "${File}" \
                | awk -F ':' '/^file format:/ {value=$2} END{print value}' | tr -d ' '
        """
        result = subprocess.run(
            ["qemu-img", "info", "--backing-chain", file_path],
            capture_output=True,
            text=True,
            check=False,
        )

        backing_format = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("file format:"):
                backing_format = stripped.split(":", 1)[1].strip()

        return backing_format

    def qemu_reset_disk(
        self, project_name: str, device_name: str, confirme: bool = False
    ) -> tuple[int, str | None] :
        """
        Reset a stopped QEMU VM's disk(s) to their original base image (linked clone).

        Usage:
            gns3-cli qemu_reset_disk untitled Debian-1 --confirme=true
        """
        if not project_name or not device_name:
            return 1, "Usage: qemu_reset_disk <project_name> <device_name>"

        if not confirme:
            return 2, "'--confirme=true' is required to reset the disk(s)."

        device, error = self._get_device(
            project_name,
            device_name,
            "qemu",
            require_started=False,
        )
        if error:
            return 3, error

        status = (getattr(device, "status", "") or "").strip().lower()
        if status != "stopped":
            return 4, (
                f"Error: Device {device_name} must be stopped before resetting its disk(s) "
                f"(Status: {getattr(device, 'status', 'unknown')})."
            )

        device_directory = getattr(device, "node_directory", None)
        if not device_directory:
            return 5, f"Error: Device {device_name} has no node_directory."

        if shutil.which("qemu-img") is None:
            return 6, "Error: 'qemu-img' binary not found in PATH."

        properties = getattr(device, "properties", None)
        if not isinstance(properties, dict):
            properties = {}

        print(device_name)

        reset_count = 0
        for letter in QEMU_DISK_LETTERS:
            overlay_path = os.path.join(device_directory, f"hd{letter}_disk.qcow2")
            if not os.path.isfile(overlay_path):
                continue

            base_image_name = properties.get(f"hd{letter}_disk_image")
            if not base_image_name:
                continue

            if base_image_name.startswith("/"):
                base_image_path = base_image_name
            else:
                base_image_path = self._find_qemu_base_disk_image(base_image_name)

            if not base_image_path or not os.path.isfile(base_image_path):
                print(
                    f"\tError: base disk image '{base_image_name}' for hd{letter} not found "
                    f"(looked under '{QEMU_DEFAULT_HARDDISK_PATH}').",
                    file=sys.stderr,
                )
                continue

            reset_count += 1
            print(f"\thd{letter}: {base_image_path}")

            backing_format = self._qemu_img_backing_chain_format(base_image_path)
            create_args = ["qemu-img", "create", "-f", "qcow2"]
            if backing_format:
                create_args.extend(["-F", backing_format])
            create_args.extend(["-b", base_image_path, overlay_path])

            result = subprocess.run(create_args, capture_output=True, text=True, check=False)
            if result.stdout:
                sys.stdout.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
            if result.returncode != 0:
                return result.returncode, f"Error: 'qemu-img create' failed for hd{letter} (exit code {result.returncode})."

        if reset_count == 0:
            return 7, f"Error: This VM {device_name} has no linked disk."

        return 0, f"Node '{device_name}' disk(s) have been reset ({reset_count} disk(s))."

    def qemu_get_ip(
        self,
        project_name: str,
        device_name: str,
        interface_name: str | None = None,
        agent_response_timeout_seconds: float | None = None,
        execution_timeout_seconds: float | None = None,
        status_poll_interval_seconds: float | None = None,
        sock_path: str | None = None,
    ) -> tuple[int, str | None]:
        """
            Retrieve IP addresses of interfaces.

            Usage:
                gns3-cli qemu_get_ip untitled Debian-1
                gns3-cli qemu_get_ip untitled Debian-1 --interface_name ens3
        """

        if not project_name or not device_name:
            return 1, "Usage: qemu_get_ip <project_name> <device_name> [interface_name]"

        # Ensure device exists and is QEMU
        _, error = self._get_device(project_name, device_name, "qemu")
        if error:
            return 2, error

        # Resolve socket
        if sock_path is None:
            try:
                sock_path, error = self._qemu_resolve_socket(project_name, device_name)
            except FileNotFoundError as e:
                return 3, str(e)
            if error:
                return 3, error
            assert sock_path is not None

        # Effective timers
        effective_request_timeout = self._positive_float_or_default(
            agent_response_timeout_seconds,
            DEFAULT_TIMEOUT,
            "agent_response_timeout_seconds",
        )
        effective_max_wait_seconds = self._positive_float_or_default(
            execution_timeout_seconds,
            QGA_MAX_WAIT_SECONDS,
            "execution_timeout_seconds",
        )
        effective_poll_interval = self._positive_float_or_default(
            status_poll_interval_seconds,
            QGA_STATUS_POLL_INTERVAL,
            "status_poll_interval_seconds",
        )

        # Build QGA request
        payload = {
            "execute": "guest-network-get-interfaces",
            "arguments": {}
        }

        # Send initial request
        raw = _qga_request(sock_path, payload, timeout_seconds=effective_request_timeout)
        data = json.loads(raw or "{}")

        # If QGA returns directly → no PID, no polling
        if "return" in data:
            interfaces = data["return"]
        else:
            # Some QGA versions return a PID → poll until finished
            pid = data.get("return", {}).get("pid")
            if not pid:
                return 4, f"Unexpected QGA response\n{raw}"

            deadline = time.monotonic() + effective_max_wait_seconds

            while time.monotonic() < deadline:
                status_payload = {
                    "execute": "guest-exec-status",
                    "arguments": {"pid": pid},
                }
                status_raw = _qga_request(
                    sock_path,
                    status_payload,
                    timeout_seconds=effective_request_timeout,
                )
                status_data = json.loads(status_raw or "{}")
                ret = status_data.get("return", {})

                if ret.get("exited"):
                    interfaces = ret.get("out-data")
                    break

                time.sleep(effective_poll_interval)
            else:
                return 5, f"Timeout waiting for QGA response"

            # Decode JSON returned by guest-exec
            interfaces = json.loads(
                base64.b64decode(interfaces.encode("utf-8")).decode("utf-8", errors="replace")
            ).get("return", [])

        if not interfaces:
            return 6, "No interfaces returned by QEMU Guest Agent"

        # Filter by interface name
        if interface_name:
            for iface in interfaces:
                if iface.get("name") == interface_name:
                    ips = iface.get("ip-addresses", [])
                    if not ips:
                        return 0, "(none)"
                    lines = [
                        f"{ip['ip-address']}/{ip.get('prefix', '')}"
                        for ip in ips
                    ]
                    return 0, "\n".join(lines)
            return 7, f"Interface '{interface_name}' not found"

        # Otherwise list all interfaces
        output = []
        for iface in interfaces:
            name = iface.get("name")
            ips = iface.get("ip-addresses", [])
            if not ips:
                output.append(f"{name}: (none)")
                continue
            for ip in ips:
                prefix = ip.get("prefix")
                output.append(f"{name}: {ip['ip-address']}/{prefix}")

        return 0, "\n".join(output)

def _argv_requests_help(argv: Sequence[str]) -> bool:
    return any(arg in {"-h", "--help"} for arg in argv[1:])


def _argv_has_known_subcommand(argv: Sequence[str]) -> bool:
    known = set(_public_cli_methods())
    return any(arg in known for arg in argv[1:])


def _first_known_subcommand(argv: Sequence[str]) -> str | None:
    known = set(_public_cli_methods())
    for arg in argv[1:]:
        if arg in known:
            return arg
    return None


def _argv_uses_only_global_options(argv: Sequence[str]) -> bool:
    global_options = {
        "--config_path",
        "--ipgns3",
        "--ipdevice",
        "--portgns3",
        "--qemu_path_socket",
        "--qemu_default_harddisk_path",
    }
    expecting_value = False

    for token in argv[1:]:
        if expecting_value:
            expecting_value = False
            continue

        if token in {"-h", "--help"}:
            continue

        if any(token.startswith(f"{option}=") for option in global_options):
            continue

        if token in global_options:
            expecting_value = True
            continue

        return False

    return not expecting_value


def _annotation_base_type(annotation: Any) -> type | None:
    if annotation in {str, int, float, bool}:
        return annotation

    if annotation is inspect._empty:
        return None

    args = get_args(annotation)
    if not args:
        return None

    non_none = [item for item in args if item is not type(None)]
    if len(non_none) != 1:
        return None

    base_type = non_none[0]
    if base_type in {str, int, float, bool}:
        return base_type

    return None


def _annotation_literal_choices(annotation: Any) -> tuple[str, ...] | None:
    if annotation is inspect._empty:
        return None

    origin = get_origin(annotation)
    if origin is Literal:
        values = get_args(annotation)
    else:
        args = get_args(annotation)
        non_none = [item for item in args if item is not type(None)]
        if len(non_none) != 1:
            return None

        literal_candidate = non_none[0]
        if get_origin(literal_candidate) is not Literal:
            return None
        values = get_args(literal_candidate)

    if not values or not all(isinstance(value, str) for value in values):
        return None

    return tuple(values)


def _should_colorize_help() -> bool:
    color_mode = os.environ.get(COLOR_MODE_ENV, "auto").strip().lower()
    if color_mode == "always":
        return True
    if color_mode == "never":
        return False

    if os.environ.get("NO_COLOR") is not None:
        return False

    if os.environ.get("TERM", "").lower() == "dumb":
        return False

    stream = getattr(sys, "stdout", None)
    return bool(stream and hasattr(stream, "isatty") and stream.isatty())


def _style_help_heading(heading: str, use_color: bool) -> str:
    heading = heading.upper()
    if not use_color:
        return heading
    return f"{COLOR_TITLE}{heading}{COLOR_RESET}"


def _style_option_name(name: str, use_color: bool) -> str:
    if not use_color:
        return name
    return f"{COLOR_OPTION}{name}{COLOR_RESET}"


def _style_usage_prefix(use_color: bool) -> str:
    prefix = "USAGE: "
    if not use_color:
        return prefix
    return f"{COLOR_TITLE}{prefix}{COLOR_RESET}"


def _style_usage_text(usage: str, use_color: bool) -> str:
    if not use_color:
        return usage

    if not usage.strip():
        return usage

    option_pattern = r"(?<![A-Za-z0-9_])(--?[A-Za-z0-9][A-Za-z0-9_-]*)"
    styled_lines = []
    for index, line in enumerate(usage.splitlines()):
        if not line.strip():
            styled_lines.append(line)
            continue

        raw_leading_whitespace = line[: len(line) - len(line.lstrip())]
        content = line[len(raw_leading_whitespace):]

        if index == 0:
            program_name, separator, remainder = content.partition(" ")
            styled_remainder = re.sub(
                option_pattern,
                lambda match: _style_option_name(match.group(1), True),
                remainder,
            )
            styled_line = f"{raw_leading_whitespace}{program_name}"
            if separator:
                styled_line += f" {styled_remainder}"
            styled_lines.append(styled_line)
            continue

        styled_line = re.sub(
            option_pattern,
            lambda match: _style_option_name(match.group(1), True),
            content,
        )
        styled_lines.append(f"{raw_leading_whitespace}{styled_line}")

    return "\n".join(styled_lines)


def _normalize_usage_option_value_syntax(usage: str) -> str:
    # Keep a single style in usage blocks: --option=VALUE.
    pattern = r"(--[A-Za-z0-9][A-Za-z0-9_-]*)\s+(\[[^\]]+\]|[A-Za-z][A-Za-z0-9_|{}-]*)"
    return re.sub(pattern, r"\1=\2", usage)


def _style_examples_heading(use_color: bool) -> str:
    heading = "EXAMPLES:"
    if not use_color:
        return heading
    return f"{COLOR_TITLE}{heading}{COLOR_RESET}"


def _style_commands_heading(use_color: bool) -> str:
    heading = "COMMANDS:"
    if not use_color:
        return heading
    return f"{COLOR_TITLE}{heading}{COLOR_RESET}"


def _build_compact_options_lines(use_color: bool) -> list[str]:
    entries = [
        (
            "-h, --help",
            "",
            "show this help message and exit",
        ),
        (
            "--config_path",
            "CONFIG_PATH",
            "Override configuration file path (for example: /etc/gns3/gns3.conf)",
        ),
        (
            "--ipgns3",
            "IP_GNS3",
            "Override GNS3 server host/base URL (for example: 192.0.2.10 or http://192.0.2.10)",
        ),
        (
            "--ipdevice",
            "IP_DEVICE",
            "Override device console host (for example: 192.0.2.20)",
        ),
        (
            "--portgns3",
            "PORT_GNS3",
            "Override GNS3 server port (for example: 3080)",
        ),
        (
            "--qemu_path_socket",
            "QEMU_PATH_SOCKET",
            "Override QEMU guest-agent socket folder (for example: /usr/lib/qemu/sockets)",
        ),
        (
            "--qemu_default_harddisk_path",
            "QEMU_DEFAULT_HARDDISK_PATH",
            "Override QEMU base hard-disk image search folder (for example: /opt/raizo/user/OS)",
        ),
    ]

    lines: list[str] = []
    for option_name, option_metavar, help_text in entries:
        option_display = option_name if not option_metavar else f"{option_name}={option_metavar}"
        styled_option = _style_option_name(option_name, use_color)
        styled_display = styled_option if not option_metavar else f"{styled_option}={option_metavar}"
        padding = " " * max(1, OPTION_COLUMN_WIDTH - len(option_display) + 1)
        lines.append(f"  {styled_display}{padding}: {help_text}")

    return lines


def _build_examples_epilog(examples: list[str], use_color: bool) -> str | None:
    if not examples:
        return None

    return _style_examples_heading(use_color) + "\n" + "\n".join(
        f"  {example}" for example in examples
    )


def _split_doc_for_help(doc: str) -> tuple[str, str, list[str]]:
    if not doc:
        return "", "", []

    lines = [line.rstrip() for line in doc.splitlines()]
    summary = lines[0].strip() if lines else ""

    description_lines: list[str] = []
    examples: list[str] = []
    in_usage_block = False

    for raw_line in lines[1:]:
        stripped = raw_line.strip()
        if stripped.lower() == "usage:":
            in_usage_block = True
            continue

        if in_usage_block:
            if stripped:
                examples.append(stripped)
            continue

        description_lines.append(raw_line)

    details = "\n".join(description_lines).strip()
    description = summary if not details else f"{summary}\n\n{details}"

    return summary, description, examples


def _make_help_formatter_class(use_color: bool) -> type[argparse.HelpFormatter]:
    class _Gns3HelpFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self, prog: str) -> None:
            terminal_width = shutil.get_terminal_size((HELP_MIN_WIDTH, 24)).columns
            super().__init__(
                prog,
                indent_increment=HELP_INDENT_INCREMENT,
                max_help_position=HELP_MAX_POSITION,
                width=max(HELP_MIN_WIDTH, terminal_width),
            )

        def start_section(self, heading: str | None) -> None:
            styled_heading = _style_help_heading(heading or "", use_color)
            super().start_section(styled_heading)

        def _format_action_invocation(self, action: argparse.Action) -> str:
            if not action.option_strings:
                return super()._format_action_invocation(action)

            if action.nargs == 0:
                return ", ".join(
                    _style_option_name(option, use_color)
                    for option in action.option_strings
                )

            args_string = self._format_args(
                action,
                self._get_default_metavar_for_optional(action),
            )
            return ", ".join(
                f"{_style_option_name(option, use_color)}={args_string}"
                for option in action.option_strings
            )

        def _format_action(self, action: argparse.Action) -> str:
            # Same single-line layout as the top-level COMMANDS list (see
            # _build_no_args_help / _build_compact_options_lines) instead of
            # argparse's default wrapped, multi-line help: "<option>" padded
            # out to OPTION_COLUMN_WIDTH, then " : ", then the full
            # description on that same line. Padding is computed on the
            # visible (ANSI-stripped) width of the invocation so colorized
            # option names still line up correctly.
            action_header = self._format_action_invocation(action)
            indent = " " * self._current_indent

            if not action.help or not action.help.strip():
                lines = [f"{indent}{action_header}\n"]
            else:
                help_text = self._expand_help(action)
                header_visible_length = _visible_length(action_header)
                padding = " " * max(1, OPTION_COLUMN_WIDTH - header_visible_length + 1)
                lines = [f"{indent}{action_header}{padding}: {help_text}\n"]

            for subaction in self._iter_indented_subactions(action):
                lines.append(self._format_action(subaction))

            return "".join(lines)

    return _Gns3HelpFormatter


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False

    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def _add_runtime_override_arguments(
    target_parser: argparse.ArgumentParser,
    *,
    use_none_defaults: bool,
) -> None:
    option_default = None if use_none_defaults else argparse.SUPPRESS
    target_parser.add_argument(
        "--config_path",
        default=option_default,
        metavar="CONFIG_PATH",
        help="Override configuration file path (for example: /etc/gns3/gns3.conf)",
    )
    target_parser.add_argument(
        "--ipgns3",
        default=option_default,
        metavar="IP_GNS3",
        help="Override GNS3 server host/base URL (for example: 192.0.2.10 or http://192.0.2.10)",
    )
    target_parser.add_argument(
        "--ipdevice",
        default=option_default,
        metavar="IP_DEVICE",
        help="Override device console host (for example: 192.0.2.20)",
    )
    target_parser.add_argument(
        "--portgns3",
        default=option_default,
        metavar="PORT_GNS3",
        help="Override GNS3 server port (for example: 3080)",
    )
    target_parser.add_argument(
        "--qemu_path_socket",
        default=option_default,
        metavar="QEMU_PATH_SOCKET",
        help="Override QEMU guest-agent socket folder (for example: /usr/lib/qemu/sockets)",
    )
    target_parser.add_argument(
        "--qemu_default_harddisk_path",
        default=option_default,
        metavar="QEMU_DEFAULT_HARDDISK_PATH",
        help="Override QEMU base hard-disk image search folder (for example: /opt/raizo/user/OS)",
    )


def _normalize_base_url(value: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise SystemExit("Error: '--ipgns3' requires a non-empty value.")
    return trimmed if "://" in trimmed else f"http://{trimmed}"


def _normalize_host(value: str, option_name: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise SystemExit(f"Error: '{option_name}' requires a non-empty value.")

    normalized = trimmed if "://" in trimmed else f"http://{trimmed}"
    parsed = urlparse(normalized)
    return parsed.hostname or trimmed


def _normalize_port(value: str, option_name: str) -> int:
    trimmed = str(value).strip()
    if not trimmed:
        raise SystemExit(f"Error: '{option_name}' requires a non-empty value.")

    try:
        numeric = int(trimmed)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"Error: '{option_name}' must be an integer between 1 and 65535.") from exc

    if numeric < 1 or numeric > 65535:
        raise SystemExit(f"Error: '{option_name}' must be between 1 and 65535.")

    return numeric


def _normalize_path(value: str, option_name: str) -> str:
    trimmed = str(value).strip()
    if not trimmed:
        raise SystemExit(f"Error: '{option_name}' requires a non-empty value.")

    return trimmed


def _apply_runtime_overrides(parsed: argparse.Namespace) -> None:
    global CONFIG_PATH
    global GNS3_SERVER_BASE_URL
    global GNS3_SERVER_PORT
    global GNS3_SERVER_URL
    global DEFAULT_CONSOLE_HOST
    global CONSOLE_HOST
    global QEMU_PATH_SOCKET
    global QEMU_DEFAULT_HARDDISK_PATH

    config_path_value = getattr(parsed, "config_path", None)
    ipgns3_value = getattr(parsed, "ipgns3", None)
    ipdevice_value = getattr(parsed, "ipdevice", None)
    portgns3_value = getattr(parsed, "portgns3", None)
    qemu_path_socket_value = getattr(parsed, "qemu_path_socket", None)
    qemu_default_harddisk_path_value = getattr(parsed, "qemu_default_harddisk_path", None)

    if config_path_value is not None:
        CONFIG_PATH = _normalize_path(config_path_value, "--config_path")

    if portgns3_value is not None:
        GNS3_SERVER_PORT = _normalize_port(portgns3_value, "--portgns3")

    if ipgns3_value is not None:
        GNS3_SERVER_BASE_URL = _normalize_base_url(ipgns3_value)

    if ipgns3_value is not None or portgns3_value is not None:
        GNS3_SERVER_URL = f"{GNS3_SERVER_BASE_URL}:{GNS3_SERVER_PORT}"

    if ipdevice_value is not None:
        DEFAULT_CONSOLE_HOST = _normalize_host(ipdevice_value, "--ipdevice")
        CONSOLE_HOST = DEFAULT_CONSOLE_HOST
    elif ipgns3_value is not None:
        CONSOLE_HOST = _resolve_console_host()

    if qemu_path_socket_value is not None:
        QEMU_PATH_SOCKET = _normalize_path(qemu_path_socket_value, "--qemu_path_socket")

    if qemu_default_harddisk_path_value is not None:
        QEMU_DEFAULT_HARDDISK_PATH = _normalize_path(
            qemu_default_harddisk_path_value, "--qemu_default_harddisk_path"
        )


# Auto-generated options normally show "OPTION=PARAM_NAME_UPPERCASED" in the
# help (argparse's default). For plain str parameters that isn't always a
# helpful hint of what value is expected, so specific ones get a friendlier
# placeholder here instead.
_ARGUMENT_METAVAR_OVERRIDES: dict[str, str] = {
    "windows_console_encoding": "[cp437|cp852|cp850|...]",
    "qemu_windows_console_encoding": "[cp437|cp852|cp850|...]",
}

# Auto-generated options have no help text by default (argparse only shows
# the option name/metavar). Specific ones get an explanatory description
# here instead, keyed by parameter name. This covers parameters whose
# meaning is the same in every command that exposes them.
_ARGUMENT_HELP_OVERRIDES: dict[str, str] = {
    "attribute": "Only display the value of this attribute instead of the full JSON (for example: node_type)",
    "startall": "Starts all the project's devices.",
    "device_type": "Only list devices of this GNS3 node type (for example: dynamips, qemu, vpcs, docker, iou)",
    "custom_path": "Override default project directory path (for example: /home/user/my_projects)",
    "show_interface_labels": "Toggle display of interface labels on the project canvas",
    "name_only": "Print only device names, one per line, instead of full JSON details",
    "x": "X coordinate of the device on the project canvas",
    "y": "Y coordinate of the device on the project canvas",
    "disable_paging": "Disable console pagination ('terminal length 0') before sending the command",
    "command_settle_seconds": "Seconds to wait after sending the command before reading the console output",
    "response_timeout_seconds": "Seconds to wait for a console response before giving up",
    "execution_timeout_seconds": "Maximum seconds to wait for the command to finish executing before giving up",
    "os_type": "Guest OS type: 'linux' uses /bin/sh, 'microsoft' uses cmd.exe",
    "windows_console_encoding": "Text encoding of the Windows console output (see 'chcp' inside cmd.exe)",
    "agent_response_timeout_seconds": "Seconds to wait for a qemu-guest-agent response before giving up",
    "status_poll_interval_seconds": "Seconds between polls while waiting for the command to finish",
    "sock_path": "Advanced: reuse an already-resolved qemu-guest-agent socket path instead of resolving it again",
    "read_chunk_size": "Number of bytes requested per guest-file-read call (block size) while downloading the file",
    "write_chunk_size": "Number of bytes read from the local file per guest-file-write call (block size) while uploading the file",
    "cisco_command_settle_seconds": (
        "Seconds to wait after sending the command before reading the console output "
        "(used when the device is a Cisco dynamips/iou node)"
    ),
    "cisco_response_timeout_seconds": (
        "Seconds to wait for a console response before giving up "
        "(used when the device is a Cisco dynamips/iou node)"
    ),
    "vpcs_command_settle_seconds": (
        "Seconds to wait after sending the command before reading the console output "
        "(used when the device is a VPCS node)"
    ),
    "vpcs_response_timeout_seconds": (
        "Seconds to wait for a console response before giving up "
        "(used when the device is a VPCS node)"
    ),
    "qemu_os_type": (
        "Force the guest OS type instead of auto-detecting it via qemu-guest-agent "
        "(used when the device is a QEMU node)"
    ),
    "qemu_windows_console_encoding": (
        "Text encoding of the Windows console output "
        "(used when the device is a QEMU node running Windows)"
    ),
    "qemu_agent_response_timeout_seconds": (
        "Seconds to wait for a qemu-guest-agent response before giving up "
        "(used when the device is a QEMU node)"
    ),
    "qemu_execution_timeout_seconds": (
        "Maximum seconds to wait for the command to finish executing in the guest "
        "(used when the device is a QEMU node)"
    ),
    "qemu_status_poll_interval_seconds": (
        "Seconds between polls while waiting for the command to finish "
        "(used when the device is a QEMU node)"
    ),
    "interface_name": "Return IPs only for the specified interface",
    "docker_execution_timeout_seconds": (
        "Maximum seconds to wait for the command to finish executing in the container "
        "(used when the device is a Docker node)"
    ),
}

# Some parameter names mean different things depending on the command they
# belong to (e.g. 'status' is a project state in projects but a device
# runtime state in devices). Entries here are keyed by
# (command_name, parameter_name) and take priority over
# _ARGUMENT_HELP_OVERRIDES.
_COMMAND_ARGUMENT_HELP_OVERRIDES: dict[tuple[str, str], str] = {
    ("project_delete", "confirme"): "Confirm deletion of this project",
    ("template_delete", "confirme"): "Confirm deletion of this template",
    ("device_del", "confirme"): "Confirm deletion of this device",
    ("qemu_reset_disk", "confirme"): "Confirm resetting this QEMU device's disk(s)",
    ("projects", "status"): "Only list projects in this state",
    ("devices", "status"): "Only list devices with this runtime status",
    ("template_attributes", "attribute"): (
        "Only display the value of this attribute instead of the full JSON (for example: template_type)"
    ),
}


def _resolve_argument_help(command_name: str, parameter_name: str) -> str | None:
    override = _COMMAND_ARGUMENT_HELP_OVERRIDES.get((command_name, parameter_name))
    if override is not None:
        return override
    return _ARGUMENT_HELP_OVERRIDES.get(parameter_name)


def _add_method_arguments(
    subparser: argparse.ArgumentParser,
    method: Callable[..., Any],
    command_name: str,
) -> None:
    signature = inspect.signature(method)
    for parameter in list(signature.parameters.values())[1:]:
        name = parameter.name
        default = parameter.default
        annotation_type = _annotation_base_type(parameter.annotation)
        is_required = default is inspect._empty
        help_text = _resolve_argument_help(command_name, name)

        if is_required:
            subparser.add_argument(
                name,
                type=annotation_type or str,
            )
            continue

        option_name = f"--{name}"
        if isinstance(default, bool):
            subparser.add_argument(
                option_name,
                nargs="?",
                const=True,
                default=default,
                type=_parse_bool,
                metavar="true|false",
                help=help_text,
            )
            subparser.add_argument(
                f"--no-{name}",
                dest=name,
                action="store_false",
                help=f"Shorthand for --{name}=false",
            )
            continue

        kwargs: dict[str, Any] = {"default": default}
        if annotation_type is not None and annotation_type is not bool:
            kwargs["type"] = annotation_type
        elif default is not None and type(default) in {str, int, float}:
            kwargs["type"] = type(default)

        literal_choices = _annotation_literal_choices(parameter.annotation)
        if literal_choices:
            kwargs["choices"] = list(literal_choices)
            kwargs["metavar"] = f"[{'|'.join(literal_choices)}]"
        elif name in _ARGUMENT_METAVAR_OVERRIDES:
            kwargs["metavar"] = _ARGUMENT_METAVAR_OVERRIDES[name]

        if help_text is not None:
            kwargs["help"] = help_text

        subparser.add_argument(option_name, **kwargs)


def _public_cli_methods() -> dict[str, Callable[..., Any]]:
    methods: dict[str, Callable[..., Any]] = {}

    for name, value in Gns3CLI.__dict__.items():
        if name.startswith("_"):
            continue
        if inspect.isfunction(value):
            methods[name] = value

    return methods

def _extract_invalid_cli_command(error_message: str) -> str | None:
    match = re.search(r"argument\s+cli_command:\s+invalid\s+choice:\s+'([^']+)'", error_message)
    if match:
        return match.group(1)
    return None


def _closest_cli_command_name(command_name: str) -> str | None:
    available = list(_public_cli_methods())
    if not available:
        return None

    matches = difflib.get_close_matches(command_name, available, n=1, cutoff=0.4)
    if matches:
        return matches[0]

    return None


def _build_parser() -> argparse.ArgumentParser:
    use_color = _should_colorize_help()
    formatter_class = _make_help_formatter_class(use_color)

    class _Gns3ArgumentParser(argparse.ArgumentParser):
        def _has_subparsers_action(self) -> bool:
            return any(isinstance(action, argparse._SubParsersAction) for action in self._actions)

        def _print_subcommand_help(self, command_name: str) -> bool:
            for action in self._actions:
                if isinstance(action, argparse._SubParsersAction):
                    parser = action.choices.get(command_name)
                    if parser is not None:
                        parser.print_help(file=sys.stderr)
                        return True
            return False

        def error(self, message: str) -> NoReturn:
            invalid_command = _extract_invalid_cli_command(message)
            if invalid_command is None:
                print(f"Error: {message}", file=sys.stderr)
                print(file=sys.stderr)

                # Subcommand parsers have no subparser action: show local command help.
                if not self._has_subparsers_action():
                    self.print_help(file=sys.stderr)
                    raise SystemExit(2)

                current_argv = getattr(self, "_current_argv", sys.argv)
                known_subcommand = _first_known_subcommand(current_argv)
                if known_subcommand and self._print_subcommand_help(known_subcommand):
                    raise SystemExit(2)

                program_name = os.path.basename(self.prog) if self.prog else "gns3-cli"
                print(_build_no_args_help(program_name), file=sys.stderr)
                raise SystemExit(2)

            suggested_command = _closest_cli_command_name(invalid_command)
            print(f"Error: unknown command '{invalid_command}'.", file=sys.stderr)
            if suggested_command:
                print(f"Did you mean '{suggested_command}'?", file=sys.stderr)
            print(file=sys.stderr)

            if suggested_command and self._print_subcommand_help(suggested_command):
                raise SystemExit(2)

            program_name = os.path.basename(self.prog) if self.prog else "gns3-cli"
            print(_build_no_args_help(program_name), file=sys.stderr)
            raise SystemExit(2)

    parser = _Gns3ArgumentParser(description="GNS3 CLI", formatter_class=formatter_class)
    _add_runtime_override_arguments(parser, use_none_defaults=True)
    subparsers = parser.add_subparsers(dest="cli_command", required=True)

    for name, method in _public_cli_methods().items():
        doc = inspect.getdoc(method) or ""
        summary, description, examples = _split_doc_for_help(doc)
        command_parser = subparsers.add_parser(
            name,
            help=summary,
            description=description or None,
            epilog=_build_examples_epilog(examples, use_color),
            formatter_class=formatter_class,
        )
        _add_runtime_override_arguments(command_parser, use_none_defaults=False)
        _add_method_arguments(command_parser, method, name)

    return parser


def _build_no_args_help(program_name: str, use_color: bool | None = None) -> str:
    if use_color is None:
        use_color = _should_colorize_help()

    lines = [
        f"gns3-cli {GNS3_CLI_VERSION} ({GNS3_CLI_URL})",
        f"{_style_usage_prefix(use_color)}{program_name} <command> --help",
        "",
        _style_commands_heading(use_color),
    ]

    for name, method in _public_cli_methods().items():
        summary, _, _ = _split_doc_for_help(inspect.getdoc(method) or "")
        help_text = summary or "No description provided."
        lines.append(f"  + {name:<26} : {help_text}")

    lines.append("")
    lines.append(_style_help_heading("OPTIONS:", use_color))
    lines.extend(_build_compact_options_lines(use_color))

    return "\n".join(lines)


def _show_no_args_help(program_name: str) -> None:
    print(_build_no_args_help(program_name))


def _emit_cli_result(result: Any) -> None:
    if result is None:
        return

    if isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if isinstance(result, (list, tuple)):
        if all(not isinstance(item, (dict, list, tuple)) for item in result):
            for item in result:
                print(item)
            return

        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    print(result)


def _run_cli(argv: Sequence[str] | None = None) -> None:
    global USERNAME, PASSWORD
    current_argv = list(sys.argv if argv is None else argv)
    if len(current_argv) <= 1:
        program_name = os.path.basename(current_argv[0]) if current_argv else "gns3-cli"
        _show_no_args_help(program_name)
        return

    has_known_subcommand = _argv_has_known_subcommand(current_argv)
    uses_only_global_options = _argv_uses_only_global_options(current_argv)
    program_name = os.path.basename(current_argv[0]) if current_argv else "gns3-cli"

    if not has_known_subcommand and uses_only_global_options:
        if _argv_requests_help(current_argv):
            _show_no_args_help(program_name)
            return

        print("Error: a command is required.", file=sys.stderr)
        print(file=sys.stderr)
        print(_build_no_args_help(program_name), file=sys.stderr)
        raise SystemExit(2)

    parser = _build_parser()
    setattr(parser, "_current_argv", current_argv)
    parsed = parser.parse_args(current_argv[1:])
    _apply_runtime_overrides(parsed)

    USERNAME, PASSWORD, error = load_config()
    if error:
        print(error, file=sys.stderr)
        raise SystemExit(1)

    command_name = parsed.cli_command
    cli = Gns3CLI()
    command = getattr(cli, command_name)
    signature = inspect.signature(command)

    kwargs = {}
    for parameter_name in signature.parameters:
        kwargs[parameter_name] = getattr(parsed, parameter_name)

    try:
        code, result = command(**kwargs)
    except (OSError, ConnectionError, TimeoutError,
            json.JSONDecodeError, ValueError) as e:
        code, result = 99, f"Error: {e}"

    if result is not None:
        _emit_cli_result(result)
    raise SystemExit(code)



if __name__ == "__main__":
    _run_cli()
