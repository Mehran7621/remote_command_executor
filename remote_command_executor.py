
# Programmed by Mehran Abdollahzadeh

# (Remote Command Executor) Remote Control Server
#General Description:
# This project is a real-time and stable remote control system based on TCP sockets and asyncio.
# The client connects to the server, authenticates, and can execute any system command on the server and receive the output instantly.
# Key Features:
# • Authentication with username and password
# • Secure message structure with 4-byte prefix
# • Two-way heartbeat for fast disconnection detection
# • Only one client at a time


import asyncio                      # Asynchronous programming — the ability to send/receive simultaneously and execute commands without blocking
import platform                     # Get operating system information and computer name
import getpass                      # Get the current user name without displaying it in the terminal
from datetime import datetime       # Record the exact time for messages and logs
import struct                       # Pack/unpack 4 bytes of message length
import json                         # Convert dictionary to JSON and vice versa (supports Unicode)
import socket                       # Set TCP_NODELAY and fallback for hostname


# Main project settings

HOST = "127.0.0.1"              # localhost address — only on this computer
PORT = 65432                    # communication port — arbitrary and free
VALID_USERNAME = "m"            # valid username
VALID_PASSWORD = "12345678"     # valid password — be sure to change it!
HEARTBEAT_INTERVAL = 8.0        # ping interval from client (seconds)
HEARTBEAT_TIMEOUT = 25.0        # maximum silence time before assuming disconnection
current_client = None           # global variable — store active client writer (only one client allowed)

# Helper functions for packing and unpacking JSON messages
def pack_json(data: dict) -> bytes:
    """
    Function purpose: Convert dictionary to byte format ready to send over socket
    Input: data (dict) — e.g. {"type": "result", "output": "..."}
    Output: bytes — 4 bytes length + JSON bytes
    Operation: Dictionary → JSON → bytes → Add length prefix to prevent messages from sticking
    """
    json_str = json.dumps(data, ensure_ascii=False) # JSON with Persian support
    json_bytes = json_str.encode("utf-8")
    return struct.pack("!I", len(json_bytes)) + json_bytes



def unpack_json_length(length_bytes: bytes) -> int:
    """
    Function purpose: Extract the length of the JSON message from the first 4 bytes
    Input: length_bytes (bytes) — exactly the first 4 bytes received
    Output: int — length of the next JSON bytes
    Functionality: Complementary to pack_json — lets the receiver know exactly how many bytes to read
    """
    return struct.unpack("!I", length_bytes)[0]


# Command execution function — asynchronous (key to project stability)
async def execute_command_async(command: str) -> str:
    """
    Function purpose: execute system commands without blocking the server (heartbeat continues)
    Input: command (str) — full command like "ping 127.0.0.1 -n 70"
    Output: str — full command output or error message
    Functionality:
    • Prevent dangerous commands
    • Create asynchronous process with asyncio
    • Timeout 60 seconds
    • Decode with cp1256 for correct Persian in cmd
    • Truncate very long outputs
    """
    try:
        forbidden = ["rm ", "del ", "format", "mkfs", "shutdown", "reboot", "rd /s", ":(){ :|:& };:", "del /f"]
        if any(command.lower().startswith(f) for f in forbidden):
            return "❌ Forbidden command! Access denied.❌"
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return "⏰ The command took more than 60 seconds and was stopped.⏰"
        output = ""
        if stdout:
            output += stdout.decode('cp1256', errors='replace').rstrip()
        if stderr:
            error_text = stderr.decode('cp1256', errors='replace').rstrip()
            output += ("\n" if output else "") + f"❌ eror:\n{error_text}❌"
        if not output.strip():
            output = "✅ Command executed (no output)✅"
        if len(output) > 15000:
            output = output[:15000] + "\n\n... (output truncated)"
        return output
    except Exception as e:
        return f"Error executing: {str(e)}"
    
    
# Client management on the server
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Function Purpose: Complete management of a client from connection to disconnection
    Input: reader (StreamReader) — read from socket | writer (StreamWriter) — write to socket
    Output: None
    Functionality: authenticate, receive commands/ping, execute commands, send results, secure cleanup
    """
    global current_client
    addr = writer.get_extra_info("peername")
    print(f"\nNew connection from: {addr}")
    if current_client is not None:
        try:
            writer.write(pack_json({"type": "error", "message": "Server is busy!"}))
            await writer.drain()
        except:
            pass
        writer.close()
        return
    try:
        sock = writer.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except:
        pass
    authenticated = False
    try:
        writer.write(pack_json({"type": "auth_request"}))
        await writer.drain()
        try:
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=20)
            length = unpack_json_length(length_bytes)
            data = json.loads((await reader.readexactly(length)).decode("utf-8"))
        except:
            writer.close()
            return
        if (data.get("type") == "auth" and
                data.get("username") == VALID_USERNAME and
                data.get("password") == VALID_PASSWORD):
            authenticated = True

            system_info = platform.system() or "Windows"
            node_name = platform.node() or socket.gethostname()
            try:
                writer.write(pack_json({
                    "type": "auth_success",
                    "message": f"Welcome {VALID_USERNAME}!",
                    "system": system_info,
                    "node": node_name,
                    "user": getpass.getuser(),
                    "time": datetime.now().isoformat()
                }))
                await writer.drain()
            except:
                writer.close()
                return
            print(f"✅ Successful authentication: {addr}✅")
        else:
            try:
                writer.write(pack_json({"type": "auth_failed", "message": "Incorrect username or password!"}))
                await writer.drain()
            except:
                pass
            print(f"❌ Login failed from {addr}❌")
            writer.close()
            return
        current_client = writer
        while authenticated:
            try:
                length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=HEARTBEAT_TIMEOUT)
            except asyncio.TimeoutError:
                print("⏰ Client was silent → assumed disconnected⏰")
                break
            except:
                break
            try:
                length = unpack_json_length(length_bytes)
                json_bytes = await reader.readexactly(length)
                data = json.loads(json_bytes.decode("utf-8"))
            except:
                continue
            if data.get("type") == "command":
                cmd = data.get("command", "").strip()
                if not cmd:
                    continue
                print(f"order: {cmd}")
                if cmd.lower() in ["exit", "quit", "bye"]:
                    try:
                        writer.write(pack_json({"type": "goodbye"}))
                        await writer.drain()
                    except:
                        pass
                    break
                elif cmd.lower() == "clear":
                    try:
                        writer.write(pack_json({"type": "clear"}))
                        await writer.drain()
                    except:
                        pass
                    continue
                output = await execute_command_async(cmd)
                try:
                    writer.write(pack_json({
                        "type": "result",
                        "output": output,
                        "timestamp": datetime.now().isoformat()
                    }))
                    await writer.drain()
                except Exception as e:
                    print(f"Error sending result: {e}")
                    break
            elif data.get("type") == "ping":
                try:
                    writer.write(pack_json({"type": "pong"}))
                    await writer.drain()
                except:
                    break
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        if current_client == writer:
            current_client = None
        print(f"Client {addr} disconnected")
        writer.close()
        
        
# Server startup
async def start_server():
    """
    Function purpose: Start a TCP server and wait for a client to connect
    Input: None
    Output: None (runs forever)
    Function: Create server, set TCP_NODELAY, display information, serve_forever
    """
    server = await asyncio.start_server(handle_client, HOST, PORT, reuse_address=True)
    try:
        server.sockets[0].setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except:
        pass
    addr = server.sockets[0].getsockname()
    print("=" * 70)
    print(" Remote control server activated!")
    print(f" Address: {addr[0]}:{addr[1]}")
    print(f" Username: {VALID_USERNAME}")
    print(f" Password: {VALID_PASSWORD}")
    print(" Waiting for client connection...")
    print("=" * 70)
    async with server:
        await server.serve_forever()
        
        
# client heartbeat
async def heartbeat_task(writer: asyncio.StreamWriter):
    """
    Function Purpose: Send periodic pings from client to server
    Input: writer (StreamWriter) — object to write to socket
    Output: None
    Function: Sends a ping every HEARTBEAT_INTERVAL seconds to keep the connection alive
    """
    while not writer.is_closing():
        try:
            writer.write(pack_json({"type": "ping"}))
            await writer.drain()
            await asyncio.sleep(HEARTBEAT_INTERVAL)
        except:
            break
        
        
# Client — User Interface
async def run_client():
    """
    Function Purpose: Connect to server, authenticate, send commands and receive results
    Input: None
    Output: None
    Functionality: Connect, heartbeat, authenticate, command loop, error handling, safe shutdown
    """
    reader = None
    writer = None
    try:
        try:
            reader, writer = await asyncio.open_connection(HOST, PORT)
        except Exception as e:
            print(f"❌ Connection failed: {e}❌")
            return
        try:
            writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except:
            pass
        asyncio.create_task(heartbeat_task(writer))
        username = input("Username: ").strip() or "m"
        password = input("Password: ").strip() or "12345678"
        try:
            writer.write(pack_json({"type": "auth", "username": username, "password": password}))
            await writer.drain()
        except:
            print("❌ Authentication failed❌")
            return
        try:
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            length = unpack_json_length(length_bytes)
            data = json.loads((await reader.readexactly(length)).decode("utf-8"))
            if data.get("type") == "auth_failed":
                print(f"❌ {data.get('message', 'Login failed')}❌")
                return

            print(f"✅ {data.get('message', 'login successful')}")
            print(f" System: {data.get('system')} | Computer: {data.get('node')}")
        except:
            print("❌ Error in server response❌")
            return
        print("\nEnter commands (exit to exit):\n")
        while True:
            try:
                cmd = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\Exit...")
                break
            if cmd.lower() in ["exit", "quit", "bye"]:
                break
            if not cmd:
                continue
            try:
                writer.write(pack_json({"type": "command", "command": cmd}))
                await writer.drain()
            except:
                print("\n❌ Connection lost.❌")
                break
            # timeout 80 seconds — for very long commands like ping -n 70
            try:
                length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=80)
                length = unpack_json_length(length_bytes)
                result = json.loads((await reader.readexactly(length)).decode("utf-8"))
                if result.get("type") == "result":
                    print(f"\n{result['output']}\n")
                elif result.get("type") == "clear":
                    print("\033c", end="")
                elif result.get("type") == "goodbye":
                    print("Goodbye!")
                    
                    break
            except asyncio.TimeoutError:
                print("\n⏰ The server did not respond for more than 80 seconds (the command was too long)⏰")
                break
            except:
                print("\n❌ Connection lost.❌")
                break
    finally:
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except:
                pass
        print("Client closed.")
        
        
# Main menu
async def main():
    """
    Purpose of the function: Display menu and select execution mode
    Input: None
    Output: None
    Function: Receive user selection and execute server or client
    """
    print("Remote Control Server (Remote Command Executor)")
    choice = input("\n[s] Server startup\n[c] Client connection\n\n→ ").lower().strip()
    if choice == "s":
        await start_server()
    elif choice == "c":
        await run_client()
    else:
        print("Invalid selection!")
        
        
# Run the program
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram stopped with Ctrl+C.")