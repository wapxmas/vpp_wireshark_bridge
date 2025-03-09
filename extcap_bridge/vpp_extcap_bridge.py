#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vpp_extcap_bridge.py - Python bridge between VPP and Wireshark

Captures packets from VPP and transmits them to Wireshark through the extcap interface.
Cross-platform compatible for Linux, Windows, and macOS.
"""

import os
import sys
import socket
import struct
import argparse
import logging
import time
import threading
import queue
import platform
import signal
from typing import Dict, List, Optional, Union, Tuple, Any
import tempfile
import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from contextlib import contextmanager
import requests
from requests.exceptions import RequestException
import datetime
import select
import errno
import shlex

# Constants
PRODUCT_NAME = "VPP"

# Windows-specific imports
if platform.system() == 'Windows':
    try:
        import win32pipe
        import win32file
        import win32security
        import pywintypes
        import winerror
        import ctypes
        from ctypes import wintypes
    except ImportError:
        print("Error: Required Windows modules not found.", file=sys.stderr)
        print("Please install pywin32 package: pip install pywin32", file=sys.stderr)
        sys.exit(1)
else:
    import fcntl  # For non-blocking FIFO operations on Unix systems

# Constants
DIRECTION_RX = 0
DIRECTION_TX = 1
MAX_DATAGRAM_SIZE = 65507  # Maximum UDP datagram size

# PCAP Constants
PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_NETWORK = 1  # LINKTYPE_ETHERNET

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
IS_LINUX = platform.system() == 'Linux'

# Setup logging
def setup_logging(debug=False):
    """
    Setup logging to file only with ISO date and microseconds in filename
    
    Args:
        debug: Enable debug logging
    """
    # Create timestamp with ISO format and microseconds
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S.%f")
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(script_dir, "logs")
    
    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_file = os.path.join(log_dir, f"vpp_extcap_bridge_{timestamp}.log")
    
    # Configure root logger
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add file handler only
    root_logger.addHandler(file_handler)
    
    # Create logger with specific name
    logger_instance = logging.getLogger('vpp_extcap_bridge')
    
    # Setup stdout and stderr redirection to the logger
    sys.stdout = LoggerWriter(logger_instance, logging.INFO)
    sys.stderr = LoggerWriter(logger_instance, logging.ERROR)
    
    return logger_instance

# Class for redirecting stdout and stderr to the logger
class LoggerWriter:
    """
    A wrapper class that redirects stdout/stderr to the logger
    """
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
        self.terminal = sys.stdout if level == logging.INFO else sys.stderr

    def write(self, message):
        # Write to original terminal first
        self.terminal.write(message)
        
        # Сразу записываем в лог, как есть
        if message and not message.isspace():  # Проверяем только, что сообщение не пустое
            self.logger.log(self.level, f"[stdout/stderr] {message}")
        
        # Сразу сбрасываем буферы
        self.flush()

    def flush(self):
        # Только сбрасываем буфер терминала
        self.terminal.flush()
    
    def isatty(self):
        return self.terminal.isatty()
    
    def fileno(self):
        return self.terminal.fileno()
    
    def read(self, *args, **kwargs):
        return self.terminal.read(*args, **kwargs)
    
    def readline(self, *args, **kwargs):
        return self.terminal.readline(*args, **kwargs)

# Initialize logger with default settings
logger = logging.getLogger('vpp_extcap_bridge')

# Helper function to normalize paths for different platforms
def normalize_path(path: str) -> str:
    """
    Normalize a path for the current platform.
    
    Args:
        path: Path to normalize
        
    Returns:
        Normalized path
    """
    if IS_WINDOWS:
        # Check if the path needs to be properly formatted for Windows named pipes
        if path and not path.startswith(r'\\.\pipe\\'):
            # Windows named pipes need to be in the format \\.\pipe\name
            if path.startswith(r'\\.\pipe\\'):
                return path  # Already in correct format
            elif path.startswith(r'\\.\pipe\\'): 
                return path  # Already in correct format
            elif path.startswith(r'\\pipe\\'):
                return r'\\.\pipe\\' + path[7:]
            elif path.startswith('pipe\\'):
                return r'\\.\pipe\\' + path[5:]
            else:
                # If path is just a name, convert it to a pipe
                if '\\' not in path and '/' not in path:
                    return r'\\.\pipe\\' + path
        return path
    elif IS_MACOS:
        # For macOS, ensure the path is absolute if it doesn't exist
        # macOS may sometimes use /var/tmp/ instead of /tmp/
        if not os.path.exists(path) and not path.startswith('/'):
            # Check common temporary directories
            for tmp_dir in ['/tmp', '/var/tmp']:
                tmp_path = os.path.join(tmp_dir, path)
                if os.path.exists(tmp_path):
                    return tmp_path
            # Default to using /tmp
            return os.path.join('/tmp', path)
        return path
    else:
        # Linux and other Unix-like systems
        return path


@dataclass
class Interface:
    """Class for storing interface information."""
    sw_if_index: int
    name: str
    description: str
    packets_received_rx: int = 0
    bytes_received_rx: int = 0
    packets_received_tx: int = 0
    bytes_received_tx: int = 0


@dataclass
class Packet:
    """Class for storing packet information."""
    sw_if_index: int
    timestamp_sec: int
    timestamp_usec: int
    data: bytes
    direction: int


class PcapWriter:
    """Handles writing packet data in PCAP format."""
    
    @staticmethod
    def write_header(file) -> None:
        """Write PCAP file header.
        
        Args:
            file: File object for writing
        """
        header = struct.pack(
            '!IHHiIII',
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            PCAP_THISZONE,
            PCAP_SIGFIGS,
            PCAP_SNAPLEN,
            PCAP_NETWORK
        )
        file.write(header)
        file.flush()
    
    @staticmethod
    def write_packet(file, data: bytes, timestamp: Optional[float] = None) -> None:
        """Write packet data in PCAP format.
        
        Args:
            file: File object for writing
            data: Packet data
            timestamp: Packet timestamp (seconds since epoch)
        """
        if timestamp is None:
            timestamp = time.time()
        
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Create packet header
        # Format: Timestamp seconds, microseconds, captured length, original length
        packet_header = struct.pack('!IIII', ts_sec, ts_usec, len(data), len(data))
        
        # Write header and data
        file.write(packet_header)
        file.write(data)
        file.flush()


class NetworkUtils:
    """Utility functions for network operations."""
    
    @staticmethod
    def get_local_ip() -> str:
        """Get the local IP address that can reach the internet.
        
        Returns:
            str: Local IP address
        """
        try:
            # This is a common technique that works on Linux, Windows, and macOS
            # Create a socket and connect to a public address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # We don't actually send data, just use the connection to get our local IP
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            logger.debug(f"Determined local IP address: {ip}")
            return ip
        except Exception as e:
            logger.warning(f"Failed to determine local IP: {e}")
            
            # Try alternative method that works without internet connection
            try:
                hostname = socket.gethostname()
                # Try to get a non-loopback IPv4 address
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    if not ip.startswith(('127.', '169.254.')):
                        logger.debug(f"Using alternative IP address detection: {ip}")
                        return ip
            except Exception as e2:
                logger.warning(f"Failed alternative IP detection: {e2}")
            
            # Fallback to localhost
            logger.warning("Falling back to localhost (127.0.0.1)")
            return "127.0.0.1"
    
    @staticmethod
    def find_free_port() -> int:
        """Find a free port to use.
        
        Returns:
            int: Free port number
        """
        logger.debug("Starting search for a free port")
        try:
            # This method works on Linux, Windows, and macOS
            logger.debug("Creating socket for port detection")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.debug("Socket created successfully")
            
            # Binding to 0 lets the OS assign a free port
            logger.debug("Binding socket to address '' and port 0 to let OS assign a free port")
            s.bind(("", 0))
            
            # Get the assigned port
            port = s.getsockname()[1]
            logger.debug(f"OS assigned port: {port}")
            
            # Close the socket
            logger.debug("Closing socket")
            s.close()
            logger.debug(f"Socket closed, returning port {port}")
            
            return port
        except Exception as e:
            logger.error(f"Error finding free port: {e}")
            logger.debug(f"Exception details: {type(e).__name__} - {str(e)}")
            logger.debug("Falling back to default port 9000")
            # Return a default port as fallback
            return 9000


class VppAgent:
    """Handles communication with the VPP agent."""
    
    def __init__(self, host: str, port: int, debug: bool = False):
        """Initialize VPP agent connection.
        
        Args:
            host: VPP agent host
            port: VPP agent port
            debug: Enable debug logging
        """
        self.host = host
        self.port = port
        self.debug = debug
        self.base_url = f"http://{host}:{port}"
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make an HTTP request to the VPP agent.
        
        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint
            data: Request data (for POST)
            
        Returns:
            Dict: Response data
            
        Raises:
            RequestException: If the request fails
        """
        url = f"{self.base_url}/{endpoint}"
        
        if self.debug:
            logger.debug(f"Making {method} request to {url}")
            if data:
                logger.debug(f"Request data: {data}")
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, timeout=10)
            else:  # POST
                response = requests.post(url, json=data, timeout=10)
            
            response.raise_for_status()
            result = response.json()
            
            if self.debug:
                logger.debug(f"Response: {result}")
            
            return result
        except RequestException as e:
            logger.error(f"Error making request to {url}: {e}")
            raise
    
    def fetch_interfaces(self) -> List[Interface]:
        """Fetch available interfaces from VPP.
        
        Returns:
            List[Interface]: List of available interfaces
            
        Raises:
            RequestException: If fetching interfaces fails
        """
        try:
            data = self._make_request("GET", "interfaces")
            
            interfaces = []
            for iface_data in data.get("interfaces", []):
                sw_if_index = iface_data.get("sw_if_index", 0)
                name = iface_data.get("name", "")
                description = iface_data.get("description", name)
                
                interfaces.append(Interface(
                    sw_if_index=sw_if_index,
                    name=name,
                    description=description
                ))
            
            return interfaces
        except Exception as e:
            logger.error(f"Error fetching interfaces: {e}")
            return []
    
    def enable_bridge(self, interface: Union[str, int], bridge_address: str) -> bool:
        """Enable packet forwarding from VPP to bridge.
        
        Args:
            interface: Interface name or SW interface index
            bridge_address: Bridge address (IP:port)
            
        Returns:
            bool: True if successful
        """
        try:
            data = {
                "interface": interface,
                "bridge_address": bridge_address
            }
            
            result = self._make_request("POST", "enable", data)
            success = result.get("success", False)
            if not success:
                logger.error(f"Error enabling bridge: {result.get('error', 'Unknown error')}")
            return success
        except Exception as e:
            logger.error(f"Error enabling bridge: {e}")
            return False
    
    def disable_bridge(self, interface: Union[str, int]) -> bool:
        """Disable packet bridging for the specified interface.
        
        Args:
            interface: Interface name or ID
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            data = {"interface": interface}
            
            result = self._make_request("POST", "disable", data)
            
            return result.get("success", False)
        except Exception as e:
            logger.error(f"Error disabling bridge: {e}")
            return False


class PacketProcessor:
    """Processes packets from VPP and queues them for Wireshark."""
    
    def __init__(self, debug: bool = False):
        """Initialize the packet processor.
        
        Args:
            debug: Enable debug mode
        """
        self.debug = debug
        self.running = False
        self.interfaces = {}  # type: Dict[int, Interface]
        self.interfaces_lock = threading.Lock()  # Add lock for thread-safe access to interfaces
        self.packets_queue = queue.Queue()
        self.server_thread = None
    
    def start_packet_server(self, port: Optional[int] = None) -> int:
        """Start the server for receiving packets from VPP.
        
        Args:
            port: Optional specific port to use. If None, find a free port.
            
        Returns:
            int: Server port number
        """
        # Find available port or use specified port
        self.wireshark_port = port if port is not None else NetworkUtils.find_free_port()
        
        # Set running flag to True
        self.running = True
        
        # Start server thread
        self.packet_server = threading.Thread(
            target=self._receive_packets_thread,
            args=(self.wireshark_port,),
            daemon=True
        )
        self.packet_server.start()
        
        if self.debug:
            logger.debug(f"Packet server started on port {self.wireshark_port}")
        
        return self.wireshark_port
    
    def _receive_packets_thread(self, port: int) -> None:
        """Thread function for receiving packets from VPP.
        
        Args:
            port: Server port number
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            print(f"Receiving packets on port 0.0.0.0:{port}")
            server_socket.bind(('0.0.0.0', port))
            server_socket.settimeout(0.05)  # Use timeout for clean shutdown
            
            if self.debug:
                logger.debug(f"Listening for VPP connections on port {port}")
            
            buffer = bytearray()
            
            while self.running:
                try:
                    data, client_address = server_socket.recvfrom(MAX_DATAGRAM_SIZE)
                    print(f"Received {len(data)} bytes from {client_address[0]}:{client_address[1]}")
                    if data:
                        if self.debug:
                            logger.debug(f"Received {len(data)} bytes from {client_address[0]}:{client_address[1]}")
                        
                        buffer.extend(data)
                        buffer = self._process_packet_buffer(buffer)
                    
                except socket.timeout:
                    # Expected, just retry
                    continue
                except Exception as e:
                    if self.running:  # Only log if not shutting down
                        logger.error(f"Error receiving data: {e}")
                        # Check for broken pipe error on macOS
                        if IS_MACOS and isinstance(e, OSError) and e.errno == 32:  # Broken pipe error
                            logger.error("Broken pipe error detected on macOS, stopping capture")
                            self.running = False
                            break
                    time.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error setting up packet server: {e}")
        
        finally:
            server_socket.close()
            if self.debug:
                logger.debug("Packet server shut down")
    
    def _process_packet_buffer(self, buffer: bytearray) -> bytearray:
        """Process received packet data buffer.
        
        Args:
            buffer: Packet data buffer
            
        Returns:
            Remaining unprocessed data
        """
        # Each packet has a 17-byte header followed by packet data
        # Header format (big-endian):
        # - sw_if_index (4 bytes)
        # - timestamp_sec (4 bytes)
        # - timestamp_usec (4 bytes)
        # - packet_length (4 bytes)
        # - direction (1 byte)
        
        HEADER_SIZE = 17
        
        # Process as many complete packets as possible
        while len(buffer) >= HEADER_SIZE:
            # Parse header (big-endian as used in wireshark_bridge.c)
            sw_if_index = int.from_bytes(buffer[0:4], byteorder='big')
            timestamp_sec = int.from_bytes(buffer[4:8], byteorder='big')
            timestamp_usec = int.from_bytes(buffer[8:12], byteorder='big')
            packet_length = int.from_bytes(buffer[12:16], byteorder='big')
            direction = buffer[16]
            
            # Check if we have the complete packet
            if len(buffer) < HEADER_SIZE + packet_length:
                break
            
            # Extract packet data
            packet_data = buffer[HEADER_SIZE:HEADER_SIZE + packet_length]
            
            # Create packet object
            packet = Packet(
                sw_if_index=sw_if_index,
                timestamp_sec=timestamp_sec,
                timestamp_usec=timestamp_usec,
                data=packet_data,
                direction=direction
            )
            
            # Add to queue
            self.packets_queue.put(packet)
            
            # Update interface statistics
            with self.interfaces_lock:
                if sw_if_index in self.interfaces:
                    if direction == DIRECTION_RX:
                        self.interfaces[sw_if_index].packets_received_rx += 1
                        self.interfaces[sw_if_index].bytes_received_rx += packet_length
                    else:
                        self.interfaces[sw_if_index].packets_received_tx += 1
                        self.interfaces[sw_if_index].bytes_received_tx += packet_length
            
            if self.debug and self.packets_queue.qsize() % 100 == 0:
                logger.debug(f"Queue size: {self.packets_queue.qsize()} packets")
            
            # Remove processed packet from buffer
            buffer = buffer[HEADER_SIZE + packet_length:]
        
        return buffer
    
    def capture_packets(self, interface_index: int, fifo_path: str) -> None:
        """Capture packets for the specified interface and write to pipe/FIFO.
        
        Args:
            interface_index: Interface index
            fifo_path: Path to the pipe/FIFO file
        """
        # Normalize the path for the current platform
        fifo_path = normalize_path(fifo_path)
        
        # Always capture both directions
        capture_rx = True
        capture_tx = True
        
        if self.debug:
            logger.debug(f"Capturing packets for interface {interface_index}, "
                         f"directions: RX={capture_rx}, TX={capture_tx}")
        
        if IS_WINDOWS:
            # Windows named pipe handling
            try:
                pipe_handle = None
                
                try:
                    # Try to open existing pipe first (Wireshark should have created it)
                    pipe_handle = win32file.CreateFile(
                        fifo_path,
                        win32file.GENERIC_WRITE,
                        0,  # No sharing
                        None,  # No security attributes
                        win32file.OPEN_EXISTING,
                        0,  # No flags/attributes
                        None  # No template file
                    )
                    
                    if self.debug:
                        logger.debug(f"Opened existing named pipe at {fifo_path}")
                except pywintypes.error as e:
                    if e.winerror != winerror.ERROR_FILE_NOT_FOUND:
                        raise
                    logger.error(f"Named pipe not found at {fifo_path}")
                    return
                
                # Write PCAP header
                win32file.WriteFile(pipe_handle, struct.pack(
                    '!IHHiIII',
                    PCAP_MAGIC,
                    PCAP_VERSION_MAJOR,
                    PCAP_VERSION_MINOR,
                    PCAP_THISZONE,
                    PCAP_SIGFIGS,
                    PCAP_SNAPLEN,
                    PCAP_NETWORK
                ))
                
                if self.debug:
                    logger.debug(f"Wrote PCAP header to pipe {fifo_path}")
                
                # Process packets
                while self.running:
                    try:
                        # Get packet with timeout for clean shutdown
                        try:
                            packet = self.packets_queue.get(timeout=0.5)
                            self.packets_queue.task_done()
                        except queue.Empty:
                            continue
                        
                        # Check interface match
                        if packet.sw_if_index != interface_index:
                            continue
                        
                        # Check direction match
                        if ((packet.direction == DIRECTION_RX and not capture_rx) or
                            (packet.direction == DIRECTION_TX and not capture_tx)):
                            continue
                        
                        # Write packet to pipe
                        timestamp = packet.timestamp_sec + (packet.timestamp_usec / 1000000.0)
                        ts_sec = int(timestamp)
                        ts_usec = int((timestamp - ts_sec) * 1000000)
                        
                        # Create packet header and write
                        packet_header = struct.pack('!IIII', ts_sec, ts_usec, len(packet.data), len(packet.data))
                        win32file.WriteFile(pipe_handle, packet_header)
                        win32file.WriteFile(pipe_handle, packet.data)
                        
                        if self.debug and packet.sw_if_index == interface_index:
                            dir_str = "RX" if packet.direction == DIRECTION_RX else "TX"
                            logger.debug(f"Wrote {dir_str} packet to pipe, length {len(packet.data)} bytes")
                        
                    except pywintypes.error as e:
                        logger.error(f"Named pipe error: {e}")
                        break
                    except Exception as e:
                        logger.error(f"Error in packet capture: {e}")
            
            except Exception as e:
                logger.error(f"Error handling Windows named pipe {fifo_path}: {e}")
            finally:
                if pipe_handle:
                    win32file.CloseHandle(pipe_handle)
        else:
            # UNIX/macOS FIFO handling
            try:
                # Ensure FIFO exists (might be created by Wireshark, but check anyway)
                if not os.path.exists(fifo_path):
                    if self.debug:
                        logger.debug(f"FIFO not found at {fifo_path}, waiting for it to be created")
                    
                    # Wait a bit for Wireshark to create the FIFO
                    timeout = time.time() + 5.0
                    while not os.path.exists(fifo_path) and time.time() < timeout:
                        time.sleep(0.1)
                
                if not os.path.exists(fifo_path):
                    logger.error(f"FIFO not found at {fifo_path} after waiting")
                    return
                
                # Handle macOS-specific issues with FIFOs
                if IS_MACOS:
                    try:
                        if self.debug:
                            logger.debug(f"Opening macOS FIFO: {fifo_path}")
                        # For macOS, we open the FIFO in non-blocking mode first to prevent blocking
                        # if Wireshark hasn't opened the other end yet
                        fifo_fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                        # Then convert to normal file for easier handling
                        with os.fdopen(fifo_fd, 'wb') as fifo:
                            # Use improved FIFO handling with select for better macOS compatibility
                            self._write_packets_to_fifo(fifo, interface_index, capture_rx, capture_tx)
                    except OSError as e:
                        if e.errno == errno.ENXIO:  # No such device or address - FIFO not opened on the other end
                            logger.debug("Waiting for Wireshark to open the FIFO...")
                            # Retry loop with backoff
                            retry_count = 0
                            max_retries = 10
                            while retry_count < max_retries and self.running:
                                time.sleep(0.5 * (1 + retry_count * 0.2))  # Incremental backoff
                                retry_count += 1
                                
                                # Check if FIFO still exists
                                if not os.path.exists(fifo_path):
                                    logger.info("FIFO file no longer exists, ending capture")
                                    return
                                    
                                try:
                                    fifo_fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                                    with os.fdopen(fifo_fd, 'wb') as fifo:
                                        self._write_packets_to_fifo(fifo, interface_index, capture_rx, capture_tx)
                                    break
                                except OSError as inner_e:
                                    if inner_e.errno == errno.ENXIO and retry_count < max_retries:
                                        continue
                                    logger.error(f"Failed to open FIFO after {retry_count} retries: {inner_e}")
                                    break
                        else:
                            logger.error(f"Error opening FIFO on macOS: {e}")
                else:
                    # Linux and other Unix systems
                    with open(fifo_path, 'wb') as fifo:
                        self._write_packets_to_fifo(fifo, interface_index, capture_rx, capture_tx)
                        
            except BrokenPipeError:
                logger.error("FIFO pipe broken, ending capture")
            except Exception as e:
                logger.error(f"Error opening or writing to FIFO: {e}")
    
    def _write_packets_to_fifo(self, fifo, interface_index: int, capture_rx: bool, capture_tx: bool) -> None:
        """Helper method to write packets to a FIFO/pipe.
        
        Args:
            fifo: Open file object for the FIFO/pipe
            interface_index: Interface index to capture
            capture_rx: Whether to capture RX packets
            capture_tx: Whether to capture TX packets
        """
        # Write PCAP header
        PcapWriter.write_header(fifo)
        
        if self.debug:
            logger.debug(f"Wrote PCAP header to FIFO")
        
        # Store FIFO path for macOS existence check
        fifo_path = None
        if IS_MACOS:
            try:
                fifo_path = fifo.name
                logger.debug(f"Monitoring FIFO file: {fifo_path}")
            except AttributeError:
                logger.warning("Could not get FIFO path for monitoring")
        
        # For macOS, set up a counter to check FIFO existence periodically
        fifo_check_counter = 0
        fifo_check_interval = 20  # Check every 20 packet attempts
        
        # Process packets
        while self.running:
            try:
                # Get packet with timeout for clean shutdown
                try:
                    packet = self.packets_queue.get(timeout=0.5)
                    self.packets_queue.task_done()
                except queue.Empty:
                    # For macOS, check if FIFO file still exists during idle periods
                    if IS_MACOS and fifo_path:
                        if not os.path.exists(fifo_path):
                            logger.info("FIFO file no longer exists, ending capture")
                            break
                    continue
                
                # Check interface match
                if packet.sw_if_index != interface_index:
                    continue
                
                # Check direction match
                if ((packet.direction == DIRECTION_RX and not capture_rx) or
                    (packet.direction == DIRECTION_TX and not capture_tx)):
                    continue
                
                # Write packet to FIFO
                timestamp = packet.timestamp_sec + (packet.timestamp_usec / 1000000.0)
                
                # For macOS, use improved FIFO handling with extra error checking
                if IS_MACOS:
                    try:
                        # Periodically check if FIFO still exists (macOS only)
                        fifo_check_counter += 1
                        if fifo_path and fifo_check_counter >= fifo_check_interval:
                            fifo_check_counter = 0
                            if not os.path.exists(fifo_path):
                                logger.info("FIFO file no longer exists, ending capture")
                                break
                        
                        # Check if FIFO is still open before writing
                        if fifo.closed:
                            logger.error("FIFO is closed, ending capture")
                            break
                            
                        # Write packet data with proper flushing
                        PcapWriter.write_packet(fifo, packet.data, timestamp)
                        fifo.flush()  # Ensure data is written immediately
                        
                        if self.debug and packet.sw_if_index == interface_index:
                            dir_str = "RX" if packet.direction == DIRECTION_RX else "TX"
                            logger.debug(f"Wrote {dir_str} packet to FIFO, length {len(packet.data)} bytes")
                            
                    except BrokenPipeError:
                        logger.error("macOS FIFO pipe broken, ending capture")
                        break
                    except IOError as e:
                        if e.errno == errno.EPIPE:  # Broken pipe
                            logger.error("macOS FIFO pipe broken (EPIPE), ending capture")
                            break
                        else:
                            logger.error(f"macOS FIFO error: {e}")
                            break
                else:
                    # Standard handling for other platforms
                    try:
                        PcapWriter.write_packet(fifo, packet.data, timestamp)
                        
                        if self.debug and packet.sw_if_index == interface_index:
                            dir_str = "RX" if packet.direction == DIRECTION_RX else "TX"
                            logger.debug(f"Wrote {dir_str} packet to FIFO, length {len(packet.data)} bytes")
                            
                    except BrokenPipeError:
                        logger.error("FIFO pipe broken, ending capture")
                        break
                    except Exception as e:
                        logger.error(f"Error in packet capture: {e}")
                
            except Exception as e:
                logger.error(f"Error in packet capture processing: {e}")
    
    def stop(self) -> None:
        """Stop packet processing."""
        self.running = False
        if self.packet_server:
            self.packet_server.join(timeout=2.0)


class ExtcapFormatter:
    """Formatter for Wireshark extcap output."""
    
    @staticmethod
    def print_interfaces(interfaces: List[Interface], vpp_host: str) -> None:
        """Print list of interfaces in Wireshark extcap format.
        
        Args:
            interfaces: List of interfaces
            vpp_host: VPP host address
        """
        print("extcap {version=1.0.0}{help=https://fd.io/vpp/}")
        if not interfaces:
            print("interface {value=vpp_all}{display=VPP All Interfaces}")
            
        for interface in interfaces:
            sw_if_index = interface.sw_if_index
            name = interface.name
            description = interface.description or name
            
            # Get only the last two octets of the VPP host IP
            short_host = vpp_host.split('.')[-2:] if '.' in vpp_host else vpp_host
            short_host = '.' + '.'.join(short_host)
            
            print(f"interface {{value=vpp_{sw_if_index}}}{{display={PRODUCT_NAME}[{short_host}]: {name}}}")
    
    @staticmethod
    def print_dlts() -> None:
        """Print available DLTs for the interface."""
        print("dlt {number=1}{name=EN10MB}{display=Ethernet}")
    
    @staticmethod
    def print_config() -> None:
        """Print configuration options for the interface."""
        print("arg {number=0}{call=--debug}{display=Debug mode}{type=boolflag}{default=false}")


class VppExtcapBridge:
    """Main class for VPP Extcap Bridge."""
    
    def __init__(self):
        """Initialize the extcap bridge."""
        self.args = None
        self.debug = False
        self.running = True
        self.vpp_agent = None
        self.packet_processor = None
        self.capture_thread = None
        self.socket_path = None
        
        # Set up signal handling for proper termination
        if not IS_WINDOWS:
            signal.signal(signal.SIGINT, self._signal_handler)   # Ctrl+C
            signal.signal(signal.SIGTERM, self._signal_handler)  # kill command
            signal.signal(signal.SIGHUP, self._signal_handler)   # Terminal closed
        else:
            # Windows doesn't have the same signal handling
            # Handle CTRL_C_EVENT and CTRL_BREAK_EVENT
            try:
                signal.signal(signal.CTRL_C_EVENT, self._signal_handler)
                signal.signal(signal.CTRL_BREAK_EVENT, self._signal_handler)
            except (AttributeError, ValueError):
                # If these signals aren't available, fall back to basic SIGINT
                signal.signal(signal.SIGINT, self._signal_handler)
                pass
    
    def _signal_handler(self, sig: int, frame) -> None:
        """Handle signals to gracefully shut down.
        
        Args:
            sig: Signal number
            frame: Current stack frame
        """
        # Get signal name for better logging
        signal_names = {
            signal.SIGINT: "SIGINT",
            signal.SIGTERM: "SIGTERM",
        }
        
        # Add platform-specific signals
        if hasattr(signal, 'SIGHUP'):
            signal_names[signal.SIGHUP] = "SIGHUP"
        if hasattr(signal, 'SIGBREAK'):
            signal_names[signal.SIGBREAK] = "SIGBREAK"
        if IS_WINDOWS:
            if hasattr(signal, 'CTRL_C_EVENT'):
                signal_names[signal.CTRL_C_EVENT] = "CTRL_C_EVENT"
            if hasattr(signal, 'CTRL_BREAK_EVENT'):
                signal_names[signal.CTRL_BREAK_EVENT] = "CTRL_BREAK_EVENT"
                
        signal_name = signal_names.get(sig, f"Unknown signal ({sig})")
        logger.info(f"Received {signal_name} signal, shutting down gracefully...")
        
        # Set flag to stop all processing loops
        self.running = False
        
        # Clean up packet processor if it exists
        if self.packet_processor:
            logger.debug("Stopping packet processor...")
            try:
                self.packet_processor.stop()
            except Exception as e:
                logger.error(f"Error stopping packet processor: {e}")
        
        # Specific handling for macOS to ensure FIFOs are properly cleaned up
        if IS_MACOS and hasattr(self, 'args') and hasattr(self.args, 'fifo') and self.args.fifo:
            fifo_path = normalize_path(self.args.fifo)
            if os.path.exists(fifo_path):
                logger.debug(f"Ensuring FIFO {fifo_path} is properly cleaned up")
                try:
                    # On macOS, try to close any open FIFOs
                    # This is a best-effort operation
                    os.system(f"lsof {shlex.quote(fifo_path)} 2>/dev/null | tail -n +2 | awk '{{print $2}}' | xargs -r kill -9 2>/dev/null || true")
                except Exception as e:
                    logger.debug(f"Non-critical error during FIFO cleanup: {e}")
        
        logger.info("Graceful shutdown completed")
        
        # If this is a terminal signal (like SIGTERM), we should exit the program
        if sig in [signal.SIGTERM, signal.SIGINT]:
            # Use a sys.exit to exit "cleanly" without a traceback
            # The zero code indicates success - the program quit as expected
            os._exit(0)
    
    def parse_args(self) -> None:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(description='VPP Extcap Bridge')
        
        # Extcap arguments
        parser.add_argument('--extcap-interfaces', action='store_true', help='List available interfaces')
        parser.add_argument('--extcap-interface', help='Interface to capture from')
        parser.add_argument('--extcap-dlts', action='store_true', help='List DLTs for the interface')
        parser.add_argument('--extcap-config', action='store_true', help='List configuration options')
        parser.add_argument('--extcap-capture-filter', help='Capture filter')
        parser.add_argument('--capture', action='store_true', help='Start capture')
        parser.add_argument('--fifo', help='Path to the FIFO file or Named Pipe')
        parser.add_argument('--extcap-control-in', help='Path to the control input pipe')
        parser.add_argument('--extcap-control-out', help='Path to the control output pipe')
        
        # VPP-specific arguments
        parser.add_argument('--vpp-host', default='localhost', help='VPP host')
        parser.add_argument('--vpp-port', type=int, default=8080, help='VPP port')
        parser.add_argument('--wireshark-ip', help='Wireshark IP address to use for packet capture bridge')
        parser.add_argument('--wireshark-port', type=int, help='Wireshark port to use for packet capture bridge')
        parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        
        self.args = parser.parse_args()
        
        # Set up debug logging if requested
        self.debug = self.args.debug
        
        # Initialize logging with debug setting
        global logger
        logger = setup_logging(self.debug)
        
        # Log script startup and command line parameters
        logger.info("VPP Extcap Bridge started")
        logger.info(f"Raw command line parameters: {sys.argv}")
        logger.info(f"Parsed arguments: {vars(self.args)}")
    
    def run(self) -> int:
        """Run the VPP Extcap Bridge.
        
        Returns:
            int: Exit code
        """
        # Parse command line arguments
        self.parse_args()
        
        # Process Wireshark extcap commands
        if self.args.extcap_interfaces:
            return self._handle_list_interfaces()
        elif self.args.extcap_dlts:
            return self._handle_list_dlts()
        elif self.args.extcap_config:
            return self._handle_config()
        elif self.args.capture:
            return self._handle_capture()
        
        # If no command was recognized, print help
        print("No valid command specified. Use --help for options.", file=sys.stderr)
        return 1
    
    def _handle_list_interfaces(self) -> int:
        """Handle listing interfaces command.
        
        Returns:
            int: Exit code
        """
        try:
            # Create VPP agent connection
            self.vpp_agent = VppAgent(
                self.args.vpp_host, 
                self.args.vpp_port, 
                self.debug
            )
            
            # Get interfaces
            interfaces = self.vpp_agent.fetch_interfaces()
            
            # Print interfaces to stdout for Wireshark
            ExtcapFormatter.print_interfaces(interfaces, self.args.vpp_host)
            return 0
            
        except Exception as e:
            logger.error(f"Error listing interfaces: {e}")
            return 1
    
    def _handle_list_dlts(self) -> int:
        """Handle listing DLTs command.
        
        Returns:
            int: Exit code
        """
        ExtcapFormatter.print_dlts()
        return 0
    
    def _handle_config(self) -> int:
        """Handle configuration command.
        
        Returns:
            int: Exit code
        """
        ExtcapFormatter.print_config()
        return 0
    
    def _handle_capture(self) -> int:
        """Handle packet capture command.
        
        Returns:
            int: Exit code
        """
        # Validate required parameters
        if not self.args.fifo:
            logger.error("Pipe/FIFO path not specified")
            return 1
        
        if not self.args.extcap_interface:
            logger.error("Interface not specified")
            return 1
        
        # Normalize the FIFO/pipe path for the current platform
        fifo_path = normalize_path(self.args.fifo)
        
        # Parse interface index from 'vpp_X' format
        try:
            interface_index = int(self.args.extcap_interface.replace('vpp_', ''))
        except ValueError:
            logger.error(f"Invalid interface name: {self.args.extcap_interface}")
            return 1
        
        # Initialize components
        self.packet_processor = PacketProcessor(self.debug)
        self.vpp_agent = VppAgent(
            self.args.vpp_host, 
            self.args.vpp_port, 
            self.debug
        )
        
        # Get interface information to find real interface name from index
        interfaces = self.vpp_agent.fetch_interfaces()
        interface_name = None
        for interface in interfaces:
            if interface.sw_if_index == interface_index:
                interface_name = interface.name
                break
        
        if not interface_name:
            logger.error(f"Interface with index {interface_index} not found")
            return 1
            
        if self.debug:
            logger.debug(f"Found interface name {interface_name} for index {interface_index}")
        
        # Start packet processor server
        if self.args.wireshark_port:
            wireshark_port = self.packet_processor.start_packet_server(self.args.wireshark_port)
        else:
            wireshark_port = self.packet_processor.start_packet_server()
        
        if wireshark_port == 0:
            logger.error("Failed to start packet server")
            return 1
        
        # Enable bridge in VPP using real interface name
        wireshark_ip = self.args.wireshark_ip or NetworkUtils.get_local_ip()
        bridge_address = f"{wireshark_ip}:{wireshark_port}"
        
        if not self.vpp_agent.enable_bridge(interface_name, bridge_address):
            logger.error(f"Failed to enable bridge for interface {interface_name}")
            self.packet_processor.stop()
            return 1
        
        if self.debug:
            logger.debug(f"Bridge enabled for interface {interface_name} to {bridge_address}")
        
        # Start capture thread (still using interface_index for packet filtering)
        self.packet_processor.running = True
        self.capture_thread = threading.Thread(
            target=self.packet_processor.capture_packets,
            args=(interface_index, fifo_path),
            daemon=True
        )
        self.capture_thread.start()
        
        if self.debug:
            logger.debug(f"Capture started for interface {interface_name}")
        
        # Wait for capture thread to finish (should run until signal received)
        try:
            while self.running and self.capture_thread.is_alive():
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            self.running = False
        finally:
            # Clean up
            if self.packet_processor:
                self.packet_processor.stop()
            
            # Disable bridge in VPP using real interface name
            try:
                self.vpp_agent.disable_bridge(interface_name)
                if self.debug:
                    logger.debug(f"Bridge disabled for interface {interface_name}")
            except Exception as e:
                logger.error(f"Error disabling bridge: {e}")
            
            # Additional platform-specific cleanup
            if self.socket_path and not IS_WINDOWS and os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except Exception as e:
                    logger.error(f"Error removing socket file: {e}")
        
        return 0


def main() -> int:
    """Main entry point."""
    bridge = VppExtcapBridge()
    return bridge.run()


if __name__ == "__main__":
    sys.exit(main()) 