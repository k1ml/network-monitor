"""
Simple graphical network status monitor (pinger).

This is the main script (runnable application).
"""

import asyncio
import errno
import ipaddress
import logging
import os
import platform
import re
import socket
import struct
import threading
import time
import zlib
from abc import ABC, abstractmethod
from enum import Enum, auto

import aiodns
import aiomonitor
import attrs
import jinja2
import pandas
import ping3
import pingparsing
import type_enforced
from aiohttp import ClientConnectionResetError, web
from aiojobs.aiohttp import setup
from ping3 import errors
from pycares import ARecordData, DNSResult

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger('network_monitor')
routes = web.RouteTableDef()
enforce_types = type_enforced.Enforcer()
ping3.EXCEPTIONS = True

class TargetStatus(Enum):
    GREEN = auto()
    YELLOW = auto()
    RED = auto()


@attrs.define
class TargetTestResult:
    status: TargetStatus
    details: dict | Exception | None


class Probe(ABC):
    @abstractmethod
    async def probe(self, target: Target,
                    ip_addresses: list[str]) -> TargetTestResult:
        """Probe the supplied target once, and return a TargetTestResult."""


@attrs.define(eq=False)  # make it hashable
class Target:
    name: str
    host: str
    address: str
    probe: Probe
    description: str


_IPV4_ADDRESS = re.compile(r'\d+\.\d+\.\d+\.\d+')
_HIDDEN_FIELD = attrs.field(
    default=None, repr=False, init=False,
)


@attrs.define
class PingParserProbe(Probe):
    interval: int = attrs.field(default=2)
    ping_count: int = attrs.field(default=1)
    ping_loss_threshold: float = attrs.field(default=0.5)
    ping_latency_threshold_ms: int = attrs.field(default=100)

    ping_parser: pingparsing.PingParsing = _HIDDEN_FIELD

    def __attrs_post_init__(self):
        self.ping_parser = pingparsing.PingParsing()

    async def probe(self, target: Target,
                    ip_addresses: list[str]) -> TargetTestResult:
        transmitter = pingparsing.PingTransmitter()

        if re.match(_IPV4_ADDRESS, target.host):
            transmitter.destination = target.host
        else:
            transmitter.destination = ip_addresses[0]

        transmitter.count = self.ping_count
        result = transmitter.ping()
        parsed = self.ping_parser.parse(result)

        if (parsed.packet_loss_rate is None or
            parsed.packet_loss_rate >= self.ping_loss_threshold
        ):
            status = TargetStatus.RED
        elif result['rtt_max'] > self.ping_latency_threshold_ms:
            status = TargetStatus.YELLOW
        else:
            status = TargetStatus.GREEN

        return TargetTestResult(status, result)


async def cancel_task(task: asyncio.Task):
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def watch(sock, timeout):
    """
    Async replacement for select().

    https://stackoverflow.com/a/48250808/648162
    """
    future = asyncio.Future()
    loop = asyncio.get_event_loop()
    loop.add_reader(sock, future.set_result, None)
    future.add_done_callback(lambda f: loop.remove_reader(sock))
    try:
        await asyncio.wait_for(future, timeout)
    except TimeoutError:
        return []  # nothing to read
    else:
        return [sock]  # sock is readable
    finally:
        try:
            future.result()
        except asyncio.CancelledError:
            pass


async def recv_raw_packet(sock, timeout):
    """
    Async replacement for sock.recvfrom(), with a timeout.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def reader_callback():
        try:
            data, addr = sock.recvfrom(65535)
            if not future.done():
                future.set_result((data, addr))
        except Exception as e:  # noqa: BLE001
            if not future.done():
                future.set_exception(e)

    # Register reader callback on the event loop
    loop.add_reader(sock.fileno(), reader_callback)
    try:
        data, addr = await asyncio.wait_for(future, timeout)
        return data, addr
    except TimeoutError:
        return None, None
    finally:
        # Clean up reader registration
        loop.remove_reader(sock.fileno())

        # Fix "unhandled CancelledError" on shutdown:
        try:
            future.result()
        except asyncio.CancelledError:
            pass


class LogPrefixAdapter(logging.LoggerAdapter):
    """
    Add a prefix to logged messages.
    
    See <https://stackoverflow.com/a/70397050/648162>.
    """
    def __init__(self, logger: logging.Logger, prefix: str, extra=None,
                 merge_extra=False):
        super().__init__(logger, extra, merge_extra)
        self.prefix = prefix

    def process(self, msg, kwargs):
        return (f"{self.prefix}{msg}", kwargs)


@ping3._func_logger
async def receive_one_ping(sock: socket.socket, icmp_id: int, seq: int,
                           timeout: float, dest_addr: str):
    """Receives the ping from the socket.

    IP Header (bits): version (8), type of service (8), length (16), id (16), flags (16), time to live (8), protocol (8), checksum (16), source ip (32), destination ip (32).
    ICMP Packet (bytes): IP Header (20), ICMP Header (8), ICMP Payload (*).
    Ping Wikipedia: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    ToS (Type of Service) in IP header for ICMP is 0. Protocol in IP header for ICMP is 1.

    Copied from ping3 and adapted to run async.

    Args:
        sock (socket.socket): The same socket used for send the ping.
        icmp_id (int): ICMP packet id. Sent packet id should be identical with received packet id.
        seq (int): ICMP packet sequence. Sent packet sequence should be identical with received packet sequence.
        timeout (int): Timeout in seconds.

    Returns:
        float | None: The delay in seconds or None on timeout.

    Raises:
        TimeToLiveExpired: If the Time-To-Live in IP Header is not large enough for destination.
        TimeExceeded: If time exceeded but Time-To-Live does not expired.
        DestinationHostUnreachable: If the destination host is unreachable.
        DestinationUnreachable: If the destination is unreachable.
    """
    custom_logger = LogPrefixAdapter(logger, f"{dest_addr}: ")

    def detect_ip_header(sock, recv_data):
        """Detect if the received data has an IP header.

        IPv4 header first 4 bits is 4 (0b0100). ICMPv4 Type starts with 4 (64~79) is unassigned. See https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
        IPv6 header first 4 bits is 6 (0b0110). ICMPv6 Type starts with 6 (96~111) is unassigned. See https://en.wikipedia.org/wiki/ICMPv6#Types

        Args:
            sock (socket.socket): The socket used to receive the data.
            recv_data (bytes): The received data.

        Returns:
            bool: True if the received data has an IP header, False otherwise.
        """
        first_field = recv_data[0] >> 4  # The first 4 bits of the first byte is the version field of IP Header.
        ping3._debug("Detecting if received data has IP header. First 4 bits: {}".format(first_field))
        return first_field == (4 if ping3.is_ipv4(sock) else 6)

    icmp_type = ping3.IcmpV4Type if ping3.is_ipv4(sock) else ping3.IcmpV6Type
    timeout_time = time.time() + timeout  # Exactly time when timeout.
    ping3._debug("Timeout time: {} ({})".format(time.ctime(timeout_time), timeout_time))
    while True:
        timeout_left = timeout_time - time.time()  # How many seconds left until timeout.
        timeout_left = timeout_left if timeout_left > 0 else 0  # Timeout must be non-negative
        ping3._debug("Timeout left: {:.2f}s".format(timeout_left))

        watch_start = time.time()
        # selected = await watch(sock, timeout_left)  # Wait until sock is ready to read or time is out.
        recv_data, _ = await recv_raw_packet(sock, timeout_left)
        time_recv = time.time()

        if recv_data is None:
            custom_logger.debug(f"{time_recv - watch_start:.2f}: timed out")
            raise errors.Timeout(timeout=timeout)
        
        custom_logger.debug(f"{time_recv - watch_start:.2f}: read")
        ping3._debug("Received time: {} ({}))".format(time.ctime(time_recv), time_recv))
        # recv_data, addr = sock.recvfrom(1500)  # Single packet size limit is 65535 bytes, but usually the network packet limit is 1500 bytes.
        # print(f"{time.time() - time_recv:.2f}")
        # time_read = time.time()
        # custom_logger.debug(f"{time_read - watch_start:.2f}: read")

        if ping3.is_ipv4(sock):
            has_ip_header = (os.name != "posix") or (platform.system() == "Darwin") or (sock.type == socket.SOCK_RAW)  # No IP Header when unprivileged on Linux.
        else:
            has_ip_header = detect_ip_header(sock, recv_data)
        if has_ip_header:
            ping3._debug("Has IP header: True")
            ip_header_slice = slice(0, struct.calcsize(ping3.IPV4_HEADER_FORMAT if ping3.is_ipv4(sock) else ping3.IPV6_HEADER_FORMAT))  # [0:20]
            icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ping3.ICMP_HEADER_FORMAT))  # [20:28]
            ip_header_raw = recv_data[ip_header_slice]
            ip_header = ping3.read_ipv4_header(ip_header_raw) if ping3.is_ipv4(sock) else ping3.read_ipv6_header(ip_header_raw)
            ping3._debug("Received IP header:", ip_header)
        else:
            ping3._debug("Has IP header: False")
            ip_header = None
            icmp_header_slice = slice(0, struct.calcsize(ping3.ICMP_HEADER_FORMAT))  # [0:8]
        icmp_header_raw, icmp_payload_raw = recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
        icmp_header = ping3.read_icmp_header(icmp_header_raw)
        ping3._debug("Received ICMP header:", icmp_header)
        ping3._debug("Received ICMP payload:", icmp_payload_raw)
        if icmp_header["type"] == icmp_type.TIME_EXCEEDED:  # TIME_EXCEEDED has no icmp_id and icmp_seq. Usually they are 0.
            if icmp_header["code"] == ping3.IcmpTimeExceededCode.TTL_EXPIRED:  # Windows raw socket cannot get TTL_EXPIRED. See https://stackoverflow.com/questions/43239862/socket-sock-raw-ipproto-icmp-cant-read-ttl-response.
                raise errors.TimeToLiveExpired(ip_header=ip_header, icmp_header=icmp_header)  # Some router does not report TTL expired and then timeout shows.
            raise errors.TimeExceeded()
        if icmp_header["type"] == icmp_type.DESTINATION_UNREACHABLE:  # DESTINATION_UNREACHABLE has no icmp_id and icmp_seq. Usually they are 0.
            if ping3.is_ipv4(sock):
                if icmp_header["code"] == ping3.IcmpV4DestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                    raise errors.DestinationHostUnreachable(ip_header=ip_header, icmp_header=icmp_header)
            else:
                if icmp_header["code"] == ping3.IcmpV6DestinationUnreachableCode.ADDRESS_UNREACHABLE:
                    raise errors.AddressUnreachable(ip_header=ip_header, icmp_header=icmp_header)
                elif icmp_header["code"] == ping3.IcmpV6DestinationUnreachableCode.PORT_UNREACHABLE:
                    raise errors.PortUnreachable(ip_header=ip_header, icmp_header=icmp_header)
            raise errors.DestinationUnreachable(
                ip_header=ip_header, icmp_header=icmp_header
            )
        if icmp_header["id"]:
            if icmp_header["type"] == icmp_type.ECHO_REQUEST:  # filters out the ECHO_REQUEST itself.
                ping3._debug("ECHO_REQUEST received. Packet filtered out.")
                continue
            ping3._debug("ICMP ID:", icmp_header["id"], ",", "Expected:", icmp_id)
            is_icmp_id_matched = icmp_header["id"] == icmp_id  # ECHO_REPLY should match the ICMP ID
            if not is_icmp_id_matched and not has_ip_header:  # When unprivileged on Linux, ICMP ID is rewrited by kernel.field.
                icmp_id = sock.getsockname()[1]  # According to https://stackoverflow.com/a/14023878/4528364, icmp_id is the port number of the socket.
                is_icmp_id_matched = icmp_header["id"] == icmp_id
                if is_icmp_id_matched:
                    ping3._debug("ICMP ID rewrited by kernel: {}".format(icmp_id))
            if not is_icmp_id_matched:
                ping3._debug("ICMP ID dismatch. Packet filtered out.")
                custom_logger.debug("ICMP ID dismatch. Packet filtered out.")
                continue
            if icmp_header["seq"] != seq:  # ECHO_REPLY should match the ICMP SEQ field.
                ping3._debug("ICMP SEQ dismatch. Packet filtered out.")
                custom_logger.debug("ICMP SEQ dismatch. Packet filtered out.")
                continue
            if icmp_header["type"] == icmp_type.ECHO_REPLY:
                time_sent = struct.unpack(ping3.ICMP_TIME_FORMAT, icmp_payload_raw[0 : struct.calcsize(ping3.ICMP_TIME_FORMAT)])[0]
                ping3._debug("Received sent time: {} ({})".format(time.ctime(time_sent), time_sent))
                custom_logger.debug(f"{time_recv - time_sent:.2f}: reply received")
                return time_recv - time_sent
        ping3._debug("Uncatched ICMP packet:", icmp_header)


@ping3._func_logger
async def async_ping(dest_addr: str, timeout: float = 4.0, unit: str = "s",
                     src_addr: str = "", ttl=None, seq: int = 0, size: int = 56,
                     interface: str = "", version=None):
    """
    Send one ping to destination address with the given timeout.

    Copied from ping3 and adapted to run async.

    Args:
        dest_addr (str): The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"/“fd00::1“
        timeout (int): Time to wait for a response, in seconds. Default is 4s, same as Windows CMD. (default 4)
        unit (str): The unit of returned value. "s" for seconds, "ms" for milliseconds. (default "s")
        src_addr (str): The IP address to ping from. This is for multiple network interfaces. Ex. "192.168.1.20". (default "")
        ttl (int | None): The Time-To-Live of the outgoing packet. Default is None, which means using OS default ttl -- 64 onLinux and macOS, and 128 on Windows. (default None)
        seq (int): ICMP packet sequence, usually increases from 0 in the same process. (default 0)
        size (int): The ICMP packet payload size in bytes. If the input of this is less than the bytes of a double format (usually 8), the size of ICMP packet payload is 8 bytes to hold a time. The max should be the router_MTU(Usually 1480) - IP_Header(20) - ICMP_Header(8). Default is 56, same as in macOS. (default 56)
        interface (str): LINUX ONLY. The gateway network interface to ping from. Ex. "wlan0". (default "")
        ip_v (int | None): The IP version to use. 4 for IPv4, 6 for IPv6. If None, the function will try to determine the IP version from `dest_addr`. (default None)

    Returns:
        float | None | False: The delay in seconds/milliseconds, False on error and None on timeout.

    Raises:
        PingError: Any PingError will raise again if `ping3.EXCEPTIONS` is True.
    """
    if version is None:  # Auto detect IP version if not specified.
        try:
            ip = ipaddress.ip_address(dest_addr)
            version = ip.version
        except ValueError:
            version = 4  # Default to IPv4 if the address is not a valid IP address.

    ping3._debug(f"Ping IPv{version}:", dest_addr)
    if version == 4:
        socket_family = socket.AF_INET
        socket_protocol = socket.IPPROTO_ICMP
    elif version == 6:
        socket_family = socket.AF_INET6
        socket_protocol = socket.IPPROTO_ICMPV6
    else:
        raise ValueError(f"Unsupported IP version: {version}")

    try:
        sock = socket.socket(socket_family, socket.SOCK_RAW, socket_protocol)
    except PermissionError as err:
        if err.errno == errno.EPERM:  # [Errno 1] Operation not permitted
            ping3._debug(f"`{err}` when create socket.SOCK_RAW, using socket.SOCK_DGRAM instead.")
            sock = socket.socket(socket_family, socket.SOCK_DGRAM, socket_protocol)  # TBC: On Linux, using SOCK_DGRAM with IPPROTO_ICMPV6 will not work as expected. It will not send ICMP packets, but will send UDP packets instead.
        else:
            raise

    with sock:
        if ttl:
            if ping3.is_ipv4(sock):  # socket.IP_TTL and socket.SOL_IP are for IPv4.
                try:  # IPPROTO_IP is for Windows and BSD Linux.
                    if sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL):  # TTL is a IPPROTO_IP option, not IPPROTO_ICMP. See: https://datatracker.ietf.org/doc/html/rfc1122#page-34
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                except OSError as err:
                    ping3._debug(f"Set Socket Option `IP_TTL` in `IPPROTO_IP` Failed: {err}")
                try:
                    if sock.getsockopt(socket.SOL_IP, socket.IP_TTL):
                        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                except OSError as err:
                    ping3._debug(f"Set Socket Option `IP_TTL` in `SOL_IP` Failed: {err}")
            else:  # IPv6
                try:  # socket.IPV6_UNICAST_HOPS is for IPv6.
                    if sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS):  # Unicast Hop Limit should be used at the IPPROTO_IPV6 Layer, not the IPPROTO_ICMPV6 Layer. See: https://datatracker.ietf.org/doc/html/rfc3493#section-5.1
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
                except OSError as err:
                    ping3._debug(f"Set Socket Option `IPV6_UNICAST_HOPS` in `IPPROTO_IPV6` Failed: {err}")
        if interface:  # Packets will be sent from specified interface.
            sock.setsockopt(socket.SOL_SOCKET, ping3.SOCKET_SO_BINDTODEVICE, interface.encode())  # Linux only. Requires root.
            ping3._debug("Socket Interface Binded:", interface)

        if src_addr:  # noqa: SIM102
            if ping3.is_ipv4(sock):
                sock.bind((src_addr, 0))  # only packets send to src_addr are received.
                ping3._debug("Socket Source Address Binded:", src_addr)
            # TODO: Support src_addr for IPv6. Currently, the source address is determined by the OS when sending packets.
        
        # threading.get_native_id() is supported >= python3.8.
        thread_id = (threading.get_native_id() if hasattr(threading, "get_native_id")
                     else threading.current_thread().ident)  
        process_id = os.getpid()  # If ping() run under different process, thread_id may be identical.
        icmp_id = zlib.crc32(f"{process_id}{thread_id}".encode()) & 0xffff  # to avoid icmp_id collision.

        try:
            ping3.send_one_ping(sock=sock, dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, size=size)
            delay = await receive_one_ping(sock=sock, icmp_id=icmp_id,
                                           seq=seq, timeout=timeout,  # in seconds
                                           dest_addr=dest_addr)
        except errors.Timeout as err:
            ping3._debug(err)
            ping3._raise(err)
            return err
        except errors.PingError as err:
            ping3._debug(err)
            ping3._raise(err)
            return err

        if delay is None:
            return None

        if unit == "ms":
            delay *= 1000  # in milliseconds

        return delay


@attrs.define
class Ping3Probe(Probe):
    ping_latency_threshold_ms: int = attrs.field(default=100)

    @enforce_types
    async def probe(self, target: Target, resolved_ip_address: list[str]):
        destination_ip_str: str = resolved_ip_address[0]
        try:
            latency_or_exc = await async_ping(destination_ip_str)
        except errors.Timeout as exc:
            latency_or_exc = exc

        if latency_or_exc is None:
            logger.info(f"{destination_ip_str} timed out")
            return TargetTestResult(TargetStatus.YELLOW, latency_or_exc)
        
        if latency_or_exc is None or isinstance(latency_or_exc, BaseException):
            logger.info(f"{destination_ip_str} failed: {latency_or_exc}")
            return TargetTestResult(TargetStatus.RED, latency_or_exc)
        
        if latency_or_exc > self.ping_latency_threshold_ms:
            status = TargetStatus.YELLOW
        else:
            status = TargetStatus.GREEN

        return TargetTestResult(status, {'latency': latency_or_exc})


SIMPLE_PING = Ping3Probe()


TARGETS: list[Target] = [
    Target("Core virtual router", 'ch-mr-rtr-virt', 'ch-mr-rtr-virt.int.k1ml.org', SIMPLE_PING,
           "Elected by the core routers, hosted by one"),
    Target("Core router 1", 'ch-mr-rtr-01', 'ch-mr-rtr-01.int.k1ml.org', SIMPLE_PING,
           "Core router itself (master or not)"),
    Target("Core router 2", 'ch-mr-rtr-02', 'ch-mr-rtr-02.int.k1ml.org', SIMPLE_PING,
           "Core router itself (master or not)"),
    Target("WAN1 router", 'ch-mr-rtr-cf', 'ch-mr-rtr-cf.int.k1ml.org', SIMPLE_PING,
           "Cambridge Fibre ISP router"),
    Target("WAN1 test", '185.113.204.179', '185.113.204.179', SIMPLE_PING,
           "This host is always routed via WAN1 to test it"),
    Target("WAN2 router", 'ch-mr-rtr-gg', 'ch-mr-rtr-gg.int.k1ml.org', SIMPLE_PING,
           "Giffgaff 4G/LTE router (Huawei)"),
    Target("WAN2 test", '185.113.204.180', '185.113.204.180', SIMPLE_PING,
           "This host is always routed via WAN2 to test it"),
    Target("WAN3 router", 'gym-rtr-zen', 'gym-rtr-zen.int.k1ml.org', SIMPLE_PING,
           "Zen Internet ISP router"),
    Target("WAN3 test", '185.113.204.181', '185.113.204.181', SIMPLE_PING,
           "This host is always routed via WAN3 to test it"),
    Target("Gym Switch", 'gym-rep-01', 'gym-rep-01.int.k1ml.org', SIMPLE_PING,
           "For E block, West and North terraces"),
    Target("Chamber 4 Switch", "c4-rep-01", 'c4-rep-01.int.k1ml.org', SIMPLE_PING,
           "For West Terrace (underground, outside Plot 11)"),
    Target("Plot 19 Switch", "p19-rep-01", 'p19-rep-01.int.k1ml.org', SIMPLE_PING,
           "For North Terrace (in Plot 19 meter cabinet)"),
    Target("Chamber 6 Switch", "c6-sw-01", 'c6-sw-01.int.k1ml.org', SIMPLE_PING,
           "For North Terrace (underground, outside Plot 26)"),
]


@attrs.define
class Handler:
    interval: int = attrs.field(default=2)
    ping_count: int = attrs.field(default=1)
    ping_loss_threshold: float = attrs.field(default=0.5)
    ping_latency_threshold_ms: int = attrs.field(default=100)

    ping_parser: pingparsing.PingParsing = attrs.field(
        default=None, repr=False, init=False,
    )
    target_to_ips: dict[Target, list[str] | Exception] = _HIDDEN_FIELD
    target_to_last_result: dict[Target, TargetTestResult | None] = _HIDDEN_FIELD
    run_loop_task: asyncio.Task = _HIDDEN_FIELD
    jinja_env: jinja2.Environment = _HIDDEN_FIELD
    websockets: list[web.WebSocketResponse] = _HIDDEN_FIELD

    def __attrs_post_init__(self):
        self.target_to_ips = {}
        self.target_to_last_result = {}
        self.jinja_env = jinja2.Environment(
            loader=jinja2.PackageLoader("network_monitor"),
            autoescape=jinja2.select_autoescape()
        )
        self.websockets = []

    def get_template(self, name):
        return self.jinja_env.get_template(name)

    def _target_ips_or_exc(self, target: Target) -> list[str] | Exception | None:
        if re.match(_IPV4_ADDRESS, target.host):
            return [target.host]

        target_ips = self.target_to_ips.get(target)

        if target_ips is None:
            return None
        elif isinstance(target_ips, Exception):
            return target_ips
        else:
            return target_ips

    @enforce_types
    def generate_hosts_table(self) -> str:
        host_df = pandas.DataFrame(
            [[target.host,
              target.address,
              target.description,
              self._target_ips_or_exc(target),
              (last_result.status if last_result is not None else None),
              (last_result.details if last_result is not None else None),
             ]
             for target, last_result in self.target_to_last_result.items()
            ], columns=['Host', 'Short hostname', 'Description', 'IP Address',
              'Last status', 'Details']
        )
        return host_df.to_html()

    async def run_loop(self):
        # Async lookup all the hostnames at the start:
        logger.info(f"Resolving {len(TARGETS)} hostnames to IP addresses")
        resolver = aiodns.DNSResolver()

        target_to_query = {}
        for target in TARGETS:
            target_to_query[target] = resolver.query_dns(target.address, 'A')
            self.target_to_last_result[target] = None

        results: list[DNSResult | BaseException] = await asyncio.gather(
            *(target_to_query.values()),
            return_exceptions=True,
        )
        for target, result in zip(target_to_query.keys(), results, strict=True):
            if isinstance(result, Exception):
                self.target_to_ips[target] = result
            else:
                assert isinstance(result, DNSResult)
                ips: list[str] = []
                for record in result.answer:
                    assert isinstance(record.data, ARecordData)
                    ips.append(record.data.addr)
                self.target_to_ips[target] = ips

        logger.info("Starting probe loop")
        loop = asyncio.get_running_loop()
        #  breakpoint()

        try:
            loop_counter = 0
            while True:  # until cancelled
                loop_counter += 1
                logger.debug(f"Starting probes (round {loop_counter})")
                start_time = loop.time()
                results = []
                num_success = 0
                num_failed = 0
                target_to_task = {}
                target_to_result = {}

                async with asyncio.TaskGroup() as tg:
                    for target in TARGETS:
                        target_ips_or_exc = self._target_ips_or_exc(target)
                        if target_ips_or_exc is None:
                            target_to_result[target] = TargetTestResult(
                                TargetStatus.YELLOW,
                                ValueError("DNS lookup not finished yet"),
                            )
                        elif isinstance(target_ips_or_exc, Exception):
                            target_to_result[target] = TargetTestResult(
                                TargetStatus.RED,
                                target_ips_or_exc,
                            )
                        else:
                            target_to_task[target] = tg.create_task(
                                asyncio.wait_for(
                                    target.probe.probe(target, target_ips_or_exc),
                                    self.interval,
                                ),
                                name=f"{target} polling round {loop_counter}",
                            )

                # All tasks awaited by TaskGroup
                for target, task in target_to_task.items():
                    target_to_result[target] = task.result()

                for target, result in target_to_result.items():
                    if isinstance(result.details, Exception):
                        # Only log if result changes (e.g. from good to exception,
                        # or to a different exception) to avoid spamming logs:
                        if self.target_to_last_result[target] != result:
                            logger.info(f"Failed to ping {target}: {result}")
                        num_failed += 1
                    else:
                        logger.debug(f"Received ping response from {target}: "
                                     f"{result}")
                        num_success += 1

                    self.target_to_last_result[target] = result

                end_time = loop.time()
                sleep_time = max(self.interval - end_time + start_time, 0)

                logger.info(f"Probed {len(TARGETS)} targets in {end_time - start_time:.2f} seconds "
                            f"({num_failed} failed), sleeping for {sleep_time:.2f} seconds")

                updated_hosts_table = self.generate_hosts_table()
                for websocket in list(self.websockets):
                    try:
                        await websocket.send_json({'hosts_table': updated_hosts_table})
                    except ClientConnectionResetError:
                        logger.info(f"Client disconnected: {websocket}")
                        self.websockets.remove(websocket)
                await asyncio.sleep(sleep_time)
        except asyncio.CancelledError:
            logger.info("Ending probe loop (cancelled)")
            raise

    async def on_startup(self, app):
        self.run_loop_task = asyncio.create_task(self.run_loop(), name="run_loop_task")

    async def on_cleanup(self, app):
        await cancel_task(self.run_loop_task)

    @routes.get('/', name='index')
    async def handle_index(self, request):
        # name = request.match_info.get('name', "Anonymous")
        hosts_table = self.generate_hosts_table()
        return web.Response(
            body=self.get_template("index.html").render(
                body=f'<div id="hosts_table" class="col">{hosts_table}</div>',
                websocket_url=request.app.router['websocket-table'].canonical,
            ),
            content_type="text/html",
        )

    @routes.get('/ws/table', name='websocket-table')
    async def handle_websocket(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.websockets.append(ws)

        async for msg in ws:
            if msg.type == web.WSMsgType.text:
                pass # await ws.send_str("Hello, {}".format(msg.data))
            elif msg.type == web.WSMsgType.binary:
                await ws.send_bytes(msg.data)
            elif msg.type == web.WSMsgType.close:
                break

        return ws

    def add_routes(self, app: web.Application):
        app.add_routes(
            attrs.evolve(route, handler=getattr(self, route.handler.__name__))
            for route in routes
        )
        app.on_startup(self.on_startup)
        app.on_cleanup(self.on_cleanup)


def aiohttp_web_entrypoint(argv):
    app = web.Application()
    setup(app)
    handler = Handler()
    handler.add_routes(app)
    return app


def main():
    loop = asyncio.new_event_loop()
    app = aiohttp_web_entrypoint([])
    with aiomonitor.start_monitor(loop) as monitor:
        app.add_subapp('/monitor',
                       asyncio.run(aiomonitor.webui.app.init_webui(monitor)))
        web.run_app(app, loop=loop)


if __name__ == '__main__':
    main()