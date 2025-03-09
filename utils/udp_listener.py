#!/usr/bin/env python3

import socket
import time
import sys
import binascii
import argparse
import signal
from datetime import datetime

# Flag for controlling the main loop
running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C signal"""
    global running
    print("\n[*] Shutting down UDP listener...")
    running = False

def setup_udp_listener(port):
    """Create and setup a UDP socket listener."""
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Allow port reuse
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set socket to non-blocking mode for Windows compatibility
        sock.setblocking(False)
        
        # Bind to all interfaces (0.0.0.0) and specified port
        server_address = ('0.0.0.0', port)
        sock.bind(server_address)
        
        print(f"[*] UDP listener started on 0.0.0.0:{port}")
        print(f"[*] Listening for incoming packets...")
        print(f"[*] Press Ctrl+C to stop the listener")
        return sock
    except Exception as e:
        print(f"[!] Socket setup error: {e}")
        sys.exit(1)

def hex_dump(data):
    """Generate a hexdump of the packet data."""
    hex_lines = []
    hex_values = binascii.hexlify(data).decode('utf-8')
    
    # Format hex dump in groups of 16 bytes
    for i in range(0, len(hex_values), 32):
        chunk = hex_values[i:i+32]
        hex_line = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
        
        # Corresponding ASCII representation
        byte_chunk = data[i//2:(i//2)+16]
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_chunk)
        
        offset = i // 2
        hex_lines.append(f"{offset:04x}:  {hex_line:<48}  |{ascii_repr}|")
    
    return '\n'.join(hex_lines)

def listen_for_packets(sock, buffer_size=4096):
    """Listen for incoming UDP packets and print debug information."""
    global running
    
    try:
        while running:
            try:
                # Receive data with timeout to allow checking the running flag
                data, address = sock.recvfrom(buffer_size)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                print("\n" + "="*80)
                print(f"[{timestamp}] Received packet from {address[0]}:{address[1]}")
                print(f"[*] Source IP: {address[0]}")
                print(f"[*] Source Port: {address[1]}")
                print(f"[*] Packet Size: {len(data)} bytes")
                
                # Print hexdump of the packet
                print("\n[*] Packet Hexdump:")
                print(hex_dump(data))
                
                # Try to decode as ASCII/UTF-8
                try:
                    decoded = data.decode('utf-8')
                    print("\n[*] Packet Content (UTF-8):")
                    print(f'    "{decoded}"')
                except UnicodeDecodeError:
                    print("\n[*] Packet Content: [Binary data - cannot be displayed as UTF-8]")
                
                print("="*80)
                sys.stdout.flush()  # Ensure output is displayed immediately
            except BlockingIOError:
                # No data available yet, sleep briefly to prevent CPU hogging
                time.sleep(0.1)
            except ConnectionResetError:
                # Handle connection reset errors that can occur on Windows
                print("\n[!] Connection reset by peer")
            except OSError as e:
                if e.winerror == 10054:  # Windows-specific connection reset
                    print("\n[!] Connection reset by peer")
                else:
                    print(f"\n[!] Socket error: {e}")
    except KeyboardInterrupt:
        # Backup handler for KeyboardInterrupt
        print("\n[*] Shutting down UDP listener...")
    except Exception as e:
        print(f"\n[!] Error in listener: {e}")
    finally:
        sock.close()
        print("[*] UDP listener stopped")

def main():
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='Simple UDP packet listener with debug output')
    parser.add_argument('-p', '--port', type=int, required=True, help='Port to listen on')
    parser.add_argument('-b', '--buffer-size', type=int, default=4096, 
                        help='Buffer size for receiving packets (default: 4096)')
    
    args = parser.parse_args()
    
    sock = setup_udp_listener(args.port)
    listen_for_packets(sock, args.buffer_size)

if __name__ == "__main__":
    main() 