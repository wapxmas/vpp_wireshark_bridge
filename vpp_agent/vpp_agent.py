#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vpp_agent.py - VPP Agent for Wireshark Bridge

Provides a REST API interface to VPP (Vector Packet Processing) for:
- Retrieving interface information
- Managing Wireshark bridge connections
- Executing VPP commands
- Collecting statistics
"""

import json
import logging
import argparse
import threading
import subprocess
import time
import shlex
import socket
import os
import select
import sys
import fcntl  # For file locking
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, List, Any, Optional, Union, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vpp_agent')

# Global variables
GLOBAL_UNIX_SOCKET = None
GLOBAL_BRIDGE_ADDRESS = None
GLOBAL_PROXY_THREAD = None
GLOBAL_PROXY_RUNNING = False
GLOBAL_PROXY_LOCK = threading.Lock()  # Lock for synchronizing proxy thread operations

# Path to store agent data (lock files, etc.)
DATA_DIR = os.path.join(os.path.expanduser("~"), ".vpp_agent")

# Maximum UDP datagram size
MAX_DATAGRAM_SIZE = 65507
# Lock file for single instance
LOCK_FILE = '/tmp/vpp_agent.lock'
# Lock file descriptor
lock_fd = None


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server implementation"""
    daemon_threads = True


class VPPCommandExecutor:
    """Handles execution of VPP commands and parsing of results"""
    
    # Default command to execute VPP
    vppcmd = "vppctl"
    
    @classmethod
    def set_vppcmd(cls, path: str) -> None:
        """
        Set the VPP command to use
        
        Args:
            path: Command to use for VPP (e.g., 'vppctl' or 'docker exec vpp.vpp vppctl')
        """
        cls.vppcmd = path
        logger.info(f"Set VPP command to: {path}")
    
    @classmethod
    def execute_command(cls, command: str) -> Dict[str, Any]:
        """
        Execute a VPP command safely
        
        Args:
            command: The VPP command to execute
            
        Returns:
            Dict containing success status, output and error message
        """
        try:
            # Split vppcmd by space to handle complex commands like "docker exec vpp.vpp vppctl"
            vppcmd_parts = shlex.split(cls.vppcmd)
            
            # Split command safely to prevent command injection
            cmd_parts = vppcmd_parts + shlex.split(command)

            logger.info(f"VPP command: {' '.join(cmd_parts)}")
            
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                check=False
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else ""
            }
        except Exception as e:
            logger.error(f"Error executing VPP command: {e}")
            return {"success": False, "error": f"Command execution failed: {str(e)}"}


class VPPInterfaceManager:
    """Manages VPP interface operations"""
    
    def __init__(self, executor: VPPCommandExecutor):
        self.executor = executor
    
    def get_interfaces(self) -> Dict[str, Any]:
        """
        Get list of VPP interfaces with their details
        
        Returns:
            Dict containing interfaces information or error
        """
        try:
            # First get basic interface information
            output = self.executor.execute_command("show interface")
            
            if not output["success"]:
                logger.error(f"Failed to get interface information: {output.get('error', 'Unknown error')}")
                return {"error": "Failed to get interface information"}
            
            # Log the raw output for debugging
            logger.debug(f"Raw interface output: {output.get('output', '')}")
            
            interfaces = []
            current_interface = None
            lines = output.get('output', '').split('\n')
            
            # First find the header line for proper column alignment
            header_line = None
            header_index = -1
            
            for i, line in enumerate(lines):
                if "Name" in line and "Idx" in line and "State" in line:
                    header_line = line
                    header_index = i
                    break
            
            if header_line is None:
                logger.warning("Could not find header line in interface output")
                return {"interfaces": [], "error": "Could not parse interface output format"}
            
            # Process the interfaces and their details
            i = header_index + 1
            while i < len(lines):
                line = lines[i].strip()
                i += 1
                
                if not line:
                    continue
                    
                # Real interface entries are flush left (not indented)
                # and start with an interface name followed by an index and state
                if not line.startswith(' '):
                    # Split on whitespace and filter out empty parts
                    parts = [p for p in line.split() if p]
                    
                    if len(parts) >= 3:  # Need at least name, index, and state
                        try:
                            # Check if the second part is a number (interface index)
                            # This effectively distinguishes interface lines from statistics lines
                            idx = int(parts[1])
                            
                            # If we can parse the index, it's likely an interface line
                            interface_name = parts[0]
                            is_up = parts[2].lower() == "up"
                            
                            # Extract MTU information if available
                            mtu_info = {}
                            if len(parts) >= 4 and "MTU" in line:
                                # Try to parse MTU values which are typically in format like "2026/0/0/0"
                                try:
                                    mtu_str = None
                                    for j in range(3, len(parts)):
                                        if "/" in parts[j]:
                                            mtu_str = parts[j]
                                            break
                                    
                                    if mtu_str:
                                        mtu_values = mtu_str.split('/')
                                        if len(mtu_values) >= 4:
                                            mtu_info = {
                                                "l3": int(mtu_values[0]) if mtu_values[0] else 0,
                                                "ip4": int(mtu_values[1]) if mtu_values[1] else 0,
                                                "ip6": int(mtu_values[2]) if mtu_values[2] else 0,
                                                "mpls": int(mtu_values[3]) if mtu_values[3] else 0
                                            }
                                except (ValueError, IndexError) as e:
                                    logger.debug(f"Could not parse MTU information for {interface_name}: {e}")
                            
                            interface = {
                                "name": interface_name,
                                "description": interface_name,
                                "is_up": is_up,
                                "mac_address": "",
                                "ip_addresses": [],
                                "sw_if_index": idx,
                                "mtu": mtu_info,
                                "stats": {}
                            }
                            
                            # Set as current interface for subsequent detail lines
                            current_interface = interface
                            interfaces.append(interface)
                            logger.debug(f"Found interface: {interface_name}, idx: {idx}, is_up: {is_up}, mtu: {mtu_info}")
                        except (ValueError, IndexError) as e:
                            # This handles both statistics lines and malformed interface lines
                            logger.debug(f"Skipping non-interface line: '{line}' - {e}")
                # Process indented lines for the current interface (stats and other details)
                elif current_interface and line.strip():
                    parts = [p for p in line.split() if p]
                    
                    # Check for statistics data
                    if len(parts) >= 2:
                        try:
                            # Handle different stat types
                            if parts[0] == "rx" and len(parts) >= 3:
                                stat_type = parts[1]  # e.g., "bytes", "packets"
                                try:
                                    value = int(parts[2])
                                    if "rx_stats" not in current_interface["stats"]:
                                        current_interface["stats"]["rx_stats"] = {}
                                    current_interface["stats"]["rx_stats"][stat_type] = value
                                except (ValueError, IndexError):
                                    pass
                            elif parts[0] == "tx" and len(parts) >= 3:
                                stat_type = parts[1]  # e.g., "bytes", "packets"
                                try:
                                    value = int(parts[2])
                                    if "tx_stats" not in current_interface["stats"]:
                                        current_interface["stats"]["tx_stats"] = {}
                                    current_interface["stats"]["tx_stats"][stat_type] = value
                                except (ValueError, IndexError):
                                    pass
                            elif parts[0] in ["ip4", "ip6", "drops"] and len(parts) >= 2:
                                # Handle other statistics
                                try:
                                    value = int(parts[1])
                                    if "other_stats" not in current_interface["stats"]:
                                        current_interface["stats"]["other_stats"] = {}
                                    current_interface["stats"]["other_stats"][parts[0]] = value
                                except (ValueError, IndexError):
                                    pass
                        except Exception as e:
                            logger.debug(f"Error processing stat line '{line}' for interface {current_interface['name']}: {e}")
            
            # Now try to get additional details like MAC addresses from show hardware
            try:
                hw_output = self.executor.execute_command("show hardware")
                if hw_output["success"]:
                    self._parse_hardware_details(hw_output.get('output', ''), interfaces)
            except Exception as e:
                logger.warning(f"Error getting hardware details: {e}")
                
            # Try to get IP information
            try:
                ip_output = self.executor.execute_command("show ip interface")
                if ip_output["success"]:
                    self._parse_ip_details(ip_output.get('output', ''), interfaces)
            except Exception as e:
                logger.warning(f"Error getting IP details: {e}")
            
            logger.debug(f"Parsed interfaces: {interfaces}")
            return {"interfaces": interfaces}
        
        except Exception as e:
            logger.error(f"Error parsing interfaces: {e}")
            return {"interfaces": [], "error": f"Failed to parse interfaces: {e}"}
            
    def _parse_hardware_details(self, output: str, interfaces: List[Dict[str, Any]]) -> None:
        """
        Parse hardware information to extract MAC addresses
        
        Args:
            output: Raw output from 'show hardware' command
            interfaces: List of interface dictionaries to update
        """
        # Create a lookup dictionary for easier access
        interfaces_by_name = {interface["name"]: interface for interface in interfaces}
        
        lines = output.split('\n')
        current_interface_name = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Interface entries typically contain the name at the beginning
            parts = [p for p in line.split() if p]
            if len(parts) >= 1 and parts[0] in interfaces_by_name:
                current_interface_name = parts[0]
                
            # Look for MAC address pattern (typically shown as aa:bb:cc:dd:ee:ff)
            if current_interface_name and ":" in line and len(parts) >= 2:
                # Simple MAC address detection (six hex numbers separated by colons)
                for part in parts:
                    if len(part.split(':')) == 6 and all(len(seg) == 2 for seg in part.split(':')):
                        interfaces_by_name[current_interface_name]["mac_address"] = part
                        logger.debug(f"Found MAC address {part} for interface {current_interface_name}")
                        break
                        
    def _parse_ip_details(self, output: str, interfaces: List[Dict[str, Any]]) -> None:
        """
        Parse IP interface information to extract IP addresses
        
        Args:
            output: Raw output from 'show ip interface' command
            interfaces: List of interface dictionaries to update
        """
        # Create a lookup dictionary for easier access
        interfaces_by_name = {interface["name"]: interface for interface in interfaces}
        interfaces_by_idx = {interface["sw_if_index"]: interface for interface in interfaces}
        
        lines = output.split('\n')
        current_interface = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Try to identify interface names or indices
            parts = [p for p in line.split() if p]
            if len(parts) >= 2:
                # Check if this line contains an interface name
                interface_name = None
                for name in interfaces_by_name.keys():
                    if name in line:
                        interface_name = name
                        current_interface = interfaces_by_name[name]
                        break
                        
                # If no name found, try to match by index
                if not interface_name:
                    for idx_str in parts:
                        try:
                            idx = int(idx_str)
                            if idx in interfaces_by_idx:
                                current_interface = interfaces_by_idx[idx]
                                break
                        except (ValueError, TypeError):
                            pass
                
            # Look for IP address patterns (IPv4 or IPv6)
            if current_interface and len(parts) >= 1:
                for part in parts:
                    # Simple IPv4 check (four numbers separated by dots)
                    if part.count('.') == 3 and all(seg.isdigit() for seg in part.split('.')):
                        if part not in current_interface["ip_addresses"]:
                            current_interface["ip_addresses"].append(part)
                            logger.debug(f"Found IPv4 address {part} for interface {current_interface['name']}")
                    
                    # Simple IPv6 check (contains multiple colons)
                    elif ':' in part and part.count(':') >= 2:
                        if part not in current_interface["ip_addresses"]:
                            current_interface["ip_addresses"].append(part)
                            logger.debug(f"Found IPv6 address {part} for interface {current_interface['name']}")


class VPPStatisticsCollector:
    """Collects and processes VPP statistics"""
    
    def __init__(self, executor: VPPCommandExecutor):
        self.executor = executor
    
    def get_vpp_stats(self) -> Dict[str, Any]:
        """
        Get VPP statistics for all interfaces
        
        Returns:
            Dict containing interface statistics or error
        """
        try:
            output = self.executor.execute_command("show interface")
            
            if not output["success"]:
                return {"error": "Failed to get statistics"}
            
            stats = {}
            lines = output.get('output', '').split('\n')
            current_interface = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check if the line is an interface header
                if line[0].isalpha() and ':' not in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        current_interface = parts[0]
                        stats[current_interface] = {
                            "rx_packets": 0,
                            "rx_bytes": 0,
                            "tx_packets": 0,
                            "tx_bytes": 0
                        }
                
                # Process statistics if we have a current interface
                elif current_interface and stats.get(current_interface):
                    self._parse_interface_stats(line, stats[current_interface])
            
            # Get Wireshark bridge statistics and merge them
            bridge_stats = self.get_wireshark_bridge_stats()
            
            for interface_name, bridge_stat in bridge_stats.get("stats", {}).items():
                if interface_name in stats:
                    stats[interface_name]["wireshark_rx_packets"] = bridge_stat.get("rx_packets", 0)
                    stats[interface_name]["wireshark_rx_bytes"] = bridge_stat.get("rx_bytes", 0)
                    stats[interface_name]["wireshark_tx_packets"] = bridge_stat.get("tx_packets", 0)
                    stats[interface_name]["wireshark_tx_bytes"] = bridge_stat.get("tx_bytes", 0)
            
            return {"stats": stats}
        
        except Exception as e:
            logger.error(f"Error getting VPP stats: {e}")
            return {"error": f"Failed to get statistics: {str(e)}"}
    
    def _parse_interface_stats(self, line: str, stats_dict: Dict[str, int]) -> None:
        """
        Parse a line of interface statistics output
        
        Args:
            line: Line from VPP output to parse
            stats_dict: Dictionary to update with parsed values
        """
        # Try to extract RX packets
        if "rx packets" in line.lower():
            parts = line.split()
            self._extract_stat_value(parts, "rx", "packets", stats_dict, "rx_packets")
        
        # Try to extract RX bytes
        if "rx bytes" in line.lower():
            parts = line.split()
            self._extract_stat_value(parts, "rx", "bytes", stats_dict, "rx_bytes")
        
        # Try to extract TX packets
        if "tx packets" in line.lower():
            parts = line.split()
            self._extract_stat_value(parts, "tx", "packets", stats_dict, "tx_packets")
        
        # Try to extract TX bytes
        if "tx bytes" in line.lower():
            parts = line.split()
            self._extract_stat_value(parts, "tx", "bytes", stats_dict, "tx_bytes")
    
    def _extract_stat_value(self, parts: List[str], direction: str, stat_type: str, 
                           stats_dict: Dict[str, int], key: str) -> None:
        """
        Extract a statistic value from split line parts
        
        Args:
            parts: Line split into parts
            direction: "rx" or "tx"
            stat_type: "packets" or "bytes"
            stats_dict: Dictionary to update with extracted value
            key: Key to update in the dictionary
        """
        for i, part in enumerate(parts):
            if part.lower() == stat_type:
                if i - 1 >= 0 and parts[i - 1].lower() == direction and i + 1 < len(parts):
                    try:
                        stats_dict[key] = int(parts[i + 1])
                    except ValueError:
                        pass
    
    def get_wireshark_bridge_stats(self) -> Dict[str, Any]:
        """
        Get Wireshark bridge statistics
        
        Returns:
            Dict containing bridge statistics or empty dict if not available
        """
        try:
            output = self.executor.execute_command("wireshark bridge stats")
            
            if not output.get("success", False):
                return {"stats": {}}
            
            stats = {}
            lines = output.get('output', '').split('\n')
            
            # Find the header line
            header_index = -1
            for i, line in enumerate(lines):
                if "Interface" in line and "RX Packets" in line:
                    header_index = i
                    break
            
            if header_index == -1:
                return {"stats": {}}
            
            # Parse data lines after the header
            for j in range(header_index + 1, len(lines)):
                line = lines[j].strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    interface_name = parts[0]
                    try:
                        rx_packets = int(parts[1])
                        rx_bytes = int(parts[2])
                        tx_packets = int(parts[3])
                        tx_bytes = int(parts[4])
                        
                        stats[interface_name] = {
                            "rx_packets": rx_packets,
                            "rx_bytes": rx_bytes,
                            "tx_packets": tx_packets,
                            "tx_bytes": tx_bytes
                        }
                    except (ValueError, IndexError):
                        logger.warning(f"Failed to parse bridge stats line: {line}")
            
            return {"stats": stats}
        
        except Exception as e:
            logger.error(f"Error getting Wireshark bridge stats: {e}")
            return {"stats": {}}


class VPPBridgeManager:
    """Manages VPP Wireshark bridge operations"""
    
    def __init__(self, executor: VPPCommandExecutor):
        self.executor = executor
    
    def get_bridge_status(self) -> Dict[str, Any]:
        """
        Get status of Wireshark bridge
        
        Returns:
            Dict containing bridge status information
        """
        result = self.executor.execute_command("wireshark bridge status")
        if not result["success"]:
            return {"success": False, "error": result["error"]}
        
        # Parse the output
        output = result["output"]
        lines = output.strip().split('\n')
        
        status = {
            "success": True,
            "enabled": False,
            "interfaces": []
        }
        
        for line in lines:
            if "Bridge is enabled" in line:
                status["enabled"] = True
            elif "Bridge is disabled" in line:
                status["enabled"] = False
            elif "Interface" in line and "enabled" in line:
                parts = line.split()
                if len(parts) >= 3:
                    interface_name = parts[1]
                    status["interfaces"].append(interface_name)
        
        return status
    
    def enable_bridge(self, interface: str, bridge_address: str, unix_socket: str = None) -> Dict[str, Any]:
        """
        Enable Wireshark bridge for an interface
        
        Args:
            interface: Interface name
            bridge_address: Bridge address (IP:port)
            unix_socket: Optional path to Unix socket
            
        Returns:
            Dict containing success status and error message if any
        """
        logger.info(f"Enabling bridge for interface: {interface}, bridge_address: {bridge_address}, unix_socket: {unix_socket}")

        if not interface or not isinstance(interface, str):
            return {"success": False, "error": "Invalid interface name"}
        
        if not unix_socket and (not bridge_address or not isinstance(bridge_address, str)):
            return {"success": False, "error": "Invalid bridge address"}
        
        # Construct the command
        command = ""
        if unix_socket:
            command = f"wireshark bridge enable {interface} {unix_socket}"
        else:
            command = f"wireshark bridge enable {interface} {bridge_address}"
        
        # Execute the command
        result = self.executor.execute_command(command)
        logger.info(f"Bridge enable result: {result}")
        
        # Note: Proxy thread management moved to the REST API handler to avoid deadlocks
        
        return result
    
    def disable_bridge(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Disable Wireshark bridge for an interface
        
        Args:
            interface: Interface name (optional, if None will disable all bridges)
            
        Returns:
            Dict containing success status and error message if any
        """
        # Construct the command
        command = "wireshark bridge disable"
        if interface:
            command += f" {interface}"
        
        # Execute the command
        result = self.executor.execute_command(command)
        
        # Note: Proxy thread management moved to the REST API handler to avoid deadlocks
        
        return result


class VPPAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for VPP API calls"""
    
    # Initialize the service components
    executor = VPPCommandExecutor()
    interface_manager = VPPInterfaceManager(executor)
    stats_collector = VPPStatisticsCollector(executor)
    bridge_manager = VPPBridgeManager(executor)
    
    def _set_cors_headers(self) -> None:
        """Set CORS headers for cross-domain requests"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def _set_headers(self, content_type: str = 'application/json', status_code: int = 200) -> None:
        """
        Set response headers
        
        Args:
            content_type: Content type header value
            status_code: HTTP status code
        """
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self._set_cors_headers()
        self.end_headers()
    
    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200) -> None:
        """
        Send JSON response
        
        Args:
            data: Dictionary to send as JSON
            status_code: HTTP status code
        """
        self._set_headers(status_code=status_code)
        self.wfile.write(json.dumps(data).encode())
    
    def _send_error_response(self, error_message: str, status_code: int = 400) -> None:
        """
        Send error response
        
        Args:
            error_message: Error message
            status_code: HTTP status code
        """
        self._send_json_response({"error": error_message}, status_code)
    
    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        """
        Read and parse JSON request body
        
        Returns:
            Parsed JSON data or None if parsing fails
        """
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                return {}
                
            post_data = self.rfile.read(content_length)
            return json.loads(post_data.decode())
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Error parsing request body: {e}")
            return None
    
    def do_GET(self) -> None:
        """Handle GET requests"""
        # Route requests to appropriate handlers
        if self.path == '/interfaces':
            interfaces = self.interface_manager.get_interfaces()
            
            # Add raw command output for debugging
            try:
                raw_output = self.executor.execute_command("show interface")
                if raw_output["success"]:
                    interfaces["raw_output"] = raw_output["output"]
            except Exception as e:
                interfaces["debug_error"] = str(e)
                
            self._send_json_response(interfaces)
            
        elif self.path == '/stats':
            stats = self.stats_collector.get_vpp_stats()
            self._send_json_response(stats)
            
        elif self.path == '/health':
            self._send_json_response({"status": "ok"})
            
        else:
            self._send_error_response("Not found", 404)
    
    def do_POST(self) -> None:
        """Handle POST requests"""
        global GLOBAL_PROXY_THREAD, GLOBAL_PROXY_RUNNING
        
        # Parse request body
        data = self._read_json_body()
        if data is None:
            self._send_error_response("Invalid JSON", 400)
            return
        
        # Route requests to appropriate handlers
        if self.path == '/enable':
            if 'interface' not in data:
                self._send_error_response("Missing required 'interface' parameter", 400)
                return
            
            # Check if we have either a bridge_address (global or in request) or a unix_socket
            if (not GLOBAL_BRIDGE_ADDRESS and 'bridge_address' not in data) and not GLOBAL_UNIX_SOCKET:
                self._send_error_response("Missing required 'bridge_address' parameter and no global bridge_address or unix_socket is set", 400)
                return
            
            # Use bridge_address with the following precedence:
            # 1. GLOBAL_BRIDGE_ADDRESS from command line
            # 2. bridge_address from request
            bridge_address = GLOBAL_BRIDGE_ADDRESS if GLOBAL_BRIDGE_ADDRESS else data.get('bridge_address', '')
            
            with GLOBAL_PROXY_LOCK:  # Lock during the bridge operation to synchronize with other requests
                # First call the bridge_manager to enable the bridge
                result = self.bridge_manager.enable_bridge(
                    data['interface'], 
                    bridge_address,
                    GLOBAL_UNIX_SOCKET
                )
                
                # If bridge was enabled successfully and we have unix_socket and bridge_address, manage proxy thread
                if result["success"] and GLOBAL_UNIX_SOCKET and bridge_address:
                    # Stop existing proxy thread if running
                    if GLOBAL_PROXY_THREAD and GLOBAL_PROXY_THREAD.is_alive():
                        logger.info("Stopping existing proxy thread")
                        GLOBAL_PROXY_RUNNING = False
                        GLOBAL_PROXY_THREAD.join(timeout=2.0)
                    
                    # Start new proxy thread
                    logger.info(f"Starting new proxy thread between {GLOBAL_UNIX_SOCKET} and {bridge_address}")
                    GLOBAL_PROXY_RUNNING = True
                    GLOBAL_PROXY_THREAD = threading.Thread(
                        target=start_proxy,
                        args=(GLOBAL_UNIX_SOCKET, bridge_address),
                        daemon=True
                    )
                    GLOBAL_PROXY_THREAD.start()
                    result["proxy_started"] = True
                
            self._send_json_response(result)
            
        elif self.path == '/disable':
            if 'interface' not in data:
                self._send_error_response("Missing required 'interface' parameter", 400)
                return
            
            with GLOBAL_PROXY_LOCK:  # Lock during the bridge operation to synchronize with other requests
                # First call the bridge_manager to disable the bridge
                result = self.bridge_manager.disable_bridge(data['interface'])
                
                # If bridge was disabled successfully, stop proxy thread if running
                if result["success"]:
                    if GLOBAL_PROXY_THREAD and GLOBAL_PROXY_THREAD.is_alive():
                        logger.info("Stopping proxy thread due to bridge disable")
                        GLOBAL_PROXY_RUNNING = False
                        GLOBAL_PROXY_THREAD.join(timeout=2.0)
                        result["proxy_stopped"] = True
            
            self._send_json_response(result)
            
        elif self.path == '/command':
            if 'command' not in data:
                self._send_error_response("Missing required 'command' parameter", 400)
                return
            
            # Validate command to prevent security issues
            command = data['command']
            if not isinstance(command, str) or ';' in command or '&' in command or '|' in command:
                self._send_error_response("Invalid command", 400)
                return
                
            result = self.executor.execute_command(command)
            self._send_json_response(result)
            
        else:
            self._send_error_response("Not found", 404)
    
    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests for CORS"""
        self._set_headers()


class VPPAgentServer:
    """Main VPP Agent server class"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
        """
        Initialize the VPP Agent server
        
        Args:
            host: Host address to bind to
            port: Port to listen on
            debug: Enable debug logging
        """
        self.host = host
        self.port = port
        self.debug = debug
        self.server = None
        
        # Configure logging
        if debug:
            logger.setLevel(logging.DEBUG)
    
    def start(self) -> None:
        """Start the HTTP server"""
        try:
            self.server = ThreadingHTTPServer((self.host, self.port), VPPAPIHandler)
            logger.info(f"Starting VPP agent server on {self.host}:{self.port}")
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
                
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            raise
    
    def stop(self) -> None:
        """Stop the HTTP server"""
        if self.server:
            logger.info("Stopping VPP agent server")
            self.server.shutdown()
            self.server.server_close()


def start_proxy(unix_socket_path: str, bridge_address: str) -> None:
    """
    Start a proxy between Unix socket and bridge address
    
    Args:
        unix_socket_path: Path to Unix socket
        bridge_address: Bridge address (IP:port)
    """
    global GLOBAL_PROXY_RUNNING
    
    logger.info(f"Starting proxy between {unix_socket_path} and {bridge_address}")
    
    # Parse bridge address
    host, port = bridge_address.split(':')
    port = int(port)
    
    # Create Unix domain socket
    if os.path.exists(unix_socket_path):
        os.unlink(unix_socket_path)
    
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    unix_socket.bind(unix_socket_path)
    os.chmod(unix_socket_path, 0o777)  # Set permissions to allow VPP to write to it
    
    # Create a UDP socket for sending to bridge (not listening or reading)
    bridge_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    GLOBAL_PROXY_RUNNING = True
    
    try:
        while GLOBAL_PROXY_RUNNING:
            # Set up for select - only unix_socket is monitored
            readable, _, _ = select.select([unix_socket], [], [], 1.0)
            
            if unix_socket in readable:
                # Receive from Unix socket and forward to bridge
                data, _ = unix_socket.recvfrom(MAX_DATAGRAM_SIZE)
                if data:
                    bridge_sender.sendto(data, (host, port))
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
    finally:
        # Clean up
        logger.info("Stopping proxy and cleaning up sockets")
        unix_socket.close()
        bridge_sender.close()
        if os.path.exists(unix_socket_path):
            os.unlink(unix_socket_path)


def main() -> None:
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VPP Agent Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to listen on')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--vppcmd', type=str, default='vppctl', help='VPP command (e.g., vppctl, or "docker exec ...", or /a/b/c/vppctl)')
    parser.add_argument('--unix-socket', type=str, help='Path to Unix socket for proxy')
    parser.add_argument('--bridge-address', type=str, help='Bridge address for proxy')
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create local data directory if it doesn't exist
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    # Ensure we're the only instance running
    LOCK_FILE = os.path.join(DATA_DIR, "vpp_agent.lock")
    try:
        # Get PID
        pid = os.getpid()
        
        # Create lock file
        lockfile = open(LOCK_FILE, 'w+')
        fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lockfile.write(str(pid))
        lockfile.flush()
        
        logger.info(f"Acquired lock on {os.path.abspath(LOCK_FILE)}, proceeding as the only instance (PID: {pid})")
    except IOError:
        # Try to read the PID of the process that has the lock
        try:
            with open(LOCK_FILE, 'r') as f:
                existing_pid = f.read().strip()
                logger.error(f"Another instance of vpp_agent is already running (PID: {existing_pid}). Lock file: {os.path.abspath(LOCK_FILE)}. Exiting.")
        except:
            logger.error(f"Another instance of vpp_agent is already running. Lock file: {os.path.abspath(LOCK_FILE)}. Exiting.")
        sys.exit(1)
    
    # Set vppcmd path
    VPPCommandExecutor.set_vppcmd(args.vppcmd)
    
    # Store unix_socket path in global variable
    global GLOBAL_UNIX_SOCKET
    GLOBAL_UNIX_SOCKET = args.unix_socket
    
    # Store bridge_address in global variable
    global GLOBAL_BRIDGE_ADDRESS
    GLOBAL_BRIDGE_ADDRESS = args.bridge_address
    
    # Note: We no longer start the proxy thread here.
    # It will be started by the enable_bridge method when needed
    
    # Start the server
    server = VPPAgentServer(args.host, args.port, args.debug)
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Clean up
        logger.info("Shutting down")
        
        # Stop proxy thread if running
        global GLOBAL_PROXY_RUNNING, GLOBAL_PROXY_THREAD
        GLOBAL_PROXY_RUNNING = False
        if GLOBAL_PROXY_THREAD:
            GLOBAL_PROXY_THREAD.join(timeout=2.0)
        
        # Release lock
        try:
            if 'lockfile' in locals():
                fcntl.flock(lockfile, fcntl.LOCK_UN)
                lockfile.close()
                os.unlink(LOCK_FILE)
        except Exception as e:
            logger.error(f"Error releasing lock: {e}")


if __name__ == "__main__":
    main() 