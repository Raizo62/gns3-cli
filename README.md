# gns3-cli

A command-line tool to manage [GNS3](https://www.gns3.com/) directly from your terminal, built on top of the [gns3fy](https://github.com/davidban77/gns3fy) library.

`gns3-cli` lets you create and manage GNS3 projects, add and control devices (Dynamips, Docker, VPCS, QEMU), and run commands directly on those devices without opening the GNS3 GUI.

## Features

- **Project management**
  - Create, open, close and delete GNS3 projects
  - List projects and their status (opened / closed)
  - List available templates
- **Device management**
  - Add and delete devices (Dynamips, Docker, VPCS, QEMU, Ethernet switch, ...) from a template
  - Start, stop, suspend devices, individually or for a whole project
  - Check if a device is currently running
  - List device interfaces and their connections
  - Read and update device attributes (JSON)
  - Connect and disconnect links between devices using port names
- **Command execution on devices**
  - Run a single command or a batch of commands from a file
  - Auto-detect the device type and dispatch to the right executor (`device_exec_cmd` / `device_exec_file`)
  - Dedicated Cisco helpers: wake console, enter enable mode (with password), enter `configure terminal`, retrieve running-config
  - Dedicated VPCS, Docker and QEMU command execution
  - Run commands on **QEMU** devices through the **QEMU Guest Agent** (`qemu-guest-agent`), if it is running inside the guest
- **File transfer**
  - Upload/download files to/from Docker containers
  - Upload/download files to/from QEMU guests via the QEMU Guest Agent
  - Reset a stopped QEMU VM's disk(s) back to their original base image (linked clone)
- **Switch management**
  - Display Ethernet switch interfaces (VLAN / trunk mode)
  - Set the VLAN or trunk mode of a switch port
- **Networking helpers**
  - Retrieve the IP addresses of a device's interfaces
- **CLI conveniences**
  - Auto-generated `--help` for every command, built from the code's docstrings and type hints
  - Fuzzy suggestions when a subcommand name is mistyped
  - Runtime overrides for GNS3 server host/port, device console host, config file path and QEMU-related paths

## Requirements

- Python 3
- [gns3fy](https://github.com/davidban77/gns3fy)
- [requests](https://pypi.org/project/requests/)

Install the dependencies with:

```bash
pip install -r requirements.txt
```

It is recommended to install them inside a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

`gns3-cli` reads the GNS3 server credentials from `/etc/gns3.conf`:

```
GNS3Login=user
GNS3Password=user
```

- If the file does not exist, the default credentials `user` / `user` are used.
- The configuration file path can be overridden at runtime with `--config_path`.

## Usage

```bash
./gns3-cli.py <command> --help
```

Running the script without any argument, or with `--help`, lists all available commands:

```bash
./gns3-cli.py --help
```

Get the detailed help (arguments, description) of a specific command:

```bash
./gns3-cli.py device_exec_cmd --help
```

### Examples

- Create a project:
  ```bash
  ./gns3-cli.py project_create --project_name=my_lab
  ```
- Open a project and start all its devices:
  ```bash
  ./gns3-cli.py project_open --project_name=my_lab --startall
  ```
- Add a device from a template:
  ```bash
  ./gns3-cli.py device_add --project_name=my_lab --device_name=R1 --template_name=c3725
  ```
- Run a command on a device (auto-detects the device type):
  ```bash
  ./gns3-cli.py device_exec_cmd --project_name=my_lab --device_name=R1 --command="show ip interface brief"
  ```
- Run a command on a QEMU device via the QEMU Guest Agent:
  ```bash
  ./gns3-cli.py qemu_exec_cmd --project_name=my_lab --device_name=Q1 --command="ip a"
  ```
- Retrieve the IP addresses of a device:
  ```bash
  ./gns3-cli.py qemu_get_ip --project_name=my_lab --device_name=Q1
  ```

## Commands reference

This is the full list of commands, as reported by `./gns3-cli.py --help`:

- `projects` : List the GNS3 projects, optionally filtered by status (opened / closed).
- `templates` : List the available templates in GNS3.
- `project_open` : Open a project, optionally starting all its devices.
- `project_close` : Close a project in GNS3.
- `project_create` : Create an empty project in GNS3 with interface labels enabled by default.
- `project_delete` : Delete a GNS3 project.
- `template_clone` : Clone an existing GNS3 template.
- `template_delete` : Delete a GNS3 template.
- `template_attributes` : Display all available JSON information for a template, or only the value of one attribute.
- `template_set_attribute` : Update a template attribute in GNS3.
- `devices` : Display devices in a project, optionally filtered by runtime status.
- `devices_start` : Start all devices in a project, but only if the project is opened.
- `devices_stop` : Stop all devices in a project, but only if the project is opened.
- `devices_suspend` : Suspend all devices in a project, but only if the project is opened.
- `devices_connect` : Create a link between 2 devices in a project using their port names.
- `devices_disconnect` : Remove the link between 2 devices in a project using their port names.
- `device_add` : Add a device to a project from an existing template.
- `device_del` : Delete a device from a GNS3 project.
- `device_interfaces` : Return the list of interface names (eth0, eth1, ...) for a device.
- `device_connections` : Return all interfaces of a device and what they are connected to.
- `device_attributes` : Display all available JSON information for a project's device, or only the value of one attribute.
- `device_set_attribute` : Update a stopped device attribute in a project.
- `device_start` : Start the device passed in parameter.
- `device_stop` : Stop the device passed in parameter.
- `device_suspend` : Suspend the device passed in parameter.
- `device_is_running` : Check whether a device in a GNS3 project is currently running.
- `device_exec_cmd` : Execute a command on a device by auto-detecting its GNS3 device type.
- `device_exec_file` : Execute commands from a file on a device by auto-detecting its GNS3 device type.
- `switch_interfaces` : Display all interfaces of an ethernet_switch with VLAN or trunk mode.
- `switch_set_vlan` : Set the VLAN or trunk mode of a port on an ethernet_switch.
- `cisco_wake` : Wake the Cisco terminal, disable pagination (`--More--`) and clear the buffer.
- `cisco_enable` : Put the Cisco device into privileged mode (enable).
- `cisco_enable_password` : Run `enable` and provide a password when the device asks for it.
- `cisco_mode_conf_t` : Wake Cisco console, enter enable mode, then run `conf term`.
- `cisco_show_running_config` : Retrieve the running-config of a router via the TCP console.
- `cisco_exec_cmd` : Execute a custom command on a Cisco device via its TCP console.
- `cisco_exec_file` : Execute Cisco commands from a file.
- `vpcs_exec_cmd` : Execute a custom command on a VPCS device via its TCP console.
- `vpcs_exec_file` : Execute VPCS commands from a file via `vpcs_exec_cmd` (comments start with `#` or `;`).
- `docker_exec_cmd` : Execute a shell command inside the Docker container associated with a GNS3 device.
- `docker_exec_file` : Execute Docker device commands from a file via `docker_exec_cmd` (comments start with `#`).
- `docker_file_download` : Download a file from the Docker container associated with a GNS3 device.
- `docker_file_upload` : Upload a file to the Docker container associated with a GNS3 device.
- `qemu_wait_qga` : Wait until the QEMU Guest Agent responds.
- `qemu_exec_cmd` : Execute a shell command inside a QEMU guest via qemu-guest-agent.
- `qemu_exec_file` : Execute QEMU commands from a file via `qemu_exec_cmd` (comments start with `#`).
- `qemu_file_download` : Download a file from a QEMU guest via qemu-guest-agent.
- `qemu_file_upload` : Upload a file to a QEMU guest via qemu-guest-agent.
- `qemu_reset_disk` : Reset a stopped QEMU VM's disk(s) to their original base image (linked clone).
- `qemu_get_ip` : Retrieve IP addresses of interfaces.

Get the full details (arguments, types, defaults) of any command with:

```bash
./gns3-cli.py <command> --help
```

## Runtime overrides

Most connection settings are defined as constants at the top of `gns3-cli.py` and can be edited directly in the source, but the most common ones can also be overridden from the command line:

- `--config_path` : override the configuration file path (default: `/etc/gns3.conf`)
- `--ipgns3` : override the GNS3 server host/base URL
- `--ipdevice` : override the device console host
- `--portgns3` : override the GNS3 server port
- `--qemu_path_socket` : override the QEMU guest-agent socket folder
- `--qemu_default_harddisk_path` : override the QEMU base hard-disk image search folder

## QEMU Guest Agent

To run commands or transfer files on a QEMU device (`qemu_exec_cmd`, `qemu_exec_file`, `qemu_file_download`, `qemu_file_upload`), the **QEMU Guest Agent** (`qemu-guest-agent`) must be installed and running inside the guest, and its Unix socket must be reachable from the host running `gns3-cli`.

- By default, `gns3-cli` expects the socket at:
  ```
  /usr/lib/qemu/sockets/GNS3.%vm-name%.%project-id%.qga.sock
  ```
  (the folder can be overridden with `--qemu_path_socket`).
- For GNS3 to create this socket, the QEMU VM template/device must have the following extra options added to its QEMU command line:
  ```
  -chardev socket,path=/usr/lib/qemu/sockets/GNS3.%vm-name%.%project-id%.qga.sock,server=on,wait=off,id=qga0 -device virtio-serial -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0
  ```
- Inside the guest, `qemu-guest-agent` must be installed and running so it can talk to this virtio-serial channel.

## License

See the repository for license information.
