#!/usr/bin/env python3
# Requires installation: pip3 install aiohttp aioudp scapy
#
# Jason Cheng (jason@jason.tools)
# Jason Tools (www.jason.tools)
#
# recv_sflow_resend_gelf
# v1.0
#

import asyncio
import socket
import json
import time
import logging
import os
from datetime import datetime
from collections import deque
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import struct

# Configuration
SFLOW_PORT = 6343
GRAYLOG_HOST = "192.168.1.132"
GRAYLOG_PORT = 13515  # Standard GELF UDP port
BATCH_SIZE = 1000
BATCH_TIMEOUT = 1.0
BUFFER_SIZE = 65535
MAX_QUEUE_SIZE = 100000
WORKER_THREADS = 4
HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8080
LOG_DIR = "/var/log/sflow-to-gelf"
LOG_FILE = "sflow-to-gelf.log"
ERROR_LOG_FILE = "sflow-to-gelf-error.log"
MAX_LOG_SIZE = 100 * 1024 * 1024  # 100MB
BACKUP_COUNT = 5
SEND_COUNTER_SAMPLES = False  # 新增參數：控制是否傳送 counter samples

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
main_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, LOG_FILE),
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT
)
main_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

error_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, ERROR_LOG_FILE),
    maxBytes=MAX_LOG_SIZE,
    backupCount=BACKUP_COUNT
)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s\n%(exc_info)s'
))
error_handler.setLevel(logging.ERROR)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(main_handler)
logger.addHandler(error_handler)

class ServiceStatus:
    """Tracks service status and statistics"""
    def __init__(self, send_counter_samples=SEND_COUNTER_SAMPLES):
        self.start_time = time.time()
        self.last_received_time = None
        self.last_processed_time = None
        self.send_counter_samples = send_counter_samples
        self.stats = {
            "received_packets": 0,
            "processed_packets": 0,
            "failed_packets": 0,
            "sent_messages": 0,
            "queue_size": 0,
            "batch_buffer_size": 0,
            "flow_samples": 0,
            "counter_samples": 0
        }
        self.errors = deque(maxlen=100)

    def add_error(self, error: str):
        timestamp = datetime.now().isoformat()
        self.errors.append({"time": timestamp, "error": error})

    def get_status(self) -> Dict:
        current_time = time.time()
        uptime = int(current_time - self.start_time)
        
        healthy = True
        status = "OK"
        
        if (self.last_received_time and 
            current_time - self.last_received_time > 300):
            healthy = False
            status = "WARNING: No data received in last 5 minutes"
        
        if (self.last_processed_time and 
            current_time - self.last_processed_time > 300):
            healthy = False
            status = "WARNING: No data processed in last 5 minutes"
        
        if (self.stats["received_packets"] > 0 and 
            self.stats["failed_packets"] / self.stats["received_packets"] > 0.1):
            healthy = False
            status = "WARNING: High error rate"

        return {
            "status": status,
            "healthy": healthy,
            "uptime": uptime,
            "stats": self.stats,
            "last_errors": list(self.errors),
            "last_received": self.last_received_time,
            "last_processed": self.last_processed_time
        }

class SflowProcessor:
    """Main sFlow processing class"""
    def __init__(self, send_counter_samples=SEND_COUNTER_SAMPLES):
        self.queue = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        self.batch_buffer = deque(maxlen=BATCH_SIZE)
        self.last_batch_time = time.time()
        self.thread_pool = ThreadPoolExecutor(max_workers=WORKER_THREADS)
        self.graylog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.processing = True
        self.status = ServiceStatus()
        self.send_counter_samples = send_counter_samples

    def get_protocol_name(self, proto_num: int) -> str:
        """Convert protocol number to name"""
        protocols = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            89: "OSPF"
        }
        return protocols.get(proto_num, str(proto_num))

    def get_ip_from_bytes(self, ip_bytes: bytes) -> str:
        """Convert IP address from bytes to string"""
        return '.'.join(str(b) for b in ip_bytes)

    def parse_sflow(self, data: bytes) -> Dict[str, Any]:
        """Parse sFlow packet data"""
        try:
            # Parse header
            result = {
                'version': struct.unpack('!i', data[0:4])[0],
                'agent_address_type': struct.unpack('!i', data[4:8])[0],
                'agent_address': self.get_ip_from_bytes(data[8:12]),
                'sub_agent_id': struct.unpack('!i', data[12:16])[0],
                'sequence_number': struct.unpack('!i', data[16:20])[0],
                'uptime': struct.unpack('!i', data[20:24])[0],
                'samples': []
            }
            
            # Parse number of samples
            num_samples = struct.unpack('!i', data[24:28])[0]
            offset = 28
            
            for _ in range(num_samples):
                if offset >= len(data):
                    break
                    
                # Parse sample header
                sample_type_enterprise = struct.unpack('!i', data[offset:offset+4])[0]
                sample_type = sample_type_enterprise & 0xFFF
                enterprise = (sample_type_enterprise >> 12) & 0xFFFFF
                sample_length = struct.unpack('!i', data[offset+4:offset+8])[0]
                
                if sample_type == 1:  # Flow Sample
                    sample = {
                        'type': 'flow',
                        'sequence_number': struct.unpack('!i', data[offset+8:offset+12])[0],
                        'source_id_type': (struct.unpack('!i', data[offset+12:offset+16])[0] >> 24) & 0xFF,
                        'source_id_index': struct.unpack('!i', data[offset+12:offset+16])[0] & 0x00FFFFFF,
                        'sampling_rate': struct.unpack('!i', data[offset+16:offset+20])[0],
                        'sample_pool': struct.unpack('!i', data[offset+20:offset+24])[0],
                        'drops': struct.unpack('!i', data[offset+24:offset+28])[0],
                        'input_if': struct.unpack('!i', data[offset+28:offset+32])[0],
                        'output_if': struct.unpack('!i', data[offset+32:offset+36])[0],
                        'records': []
                    }
                    
                    # Parse flow records
                    record_offset = offset + 36
                    num_records = struct.unpack('!i', data[record_offset:record_offset+4])[0]
                    record_offset += 4

                    for _ in range(num_records):
                        record_type_enterprise = struct.unpack('!i', data[record_offset:record_offset+4])[0]
                        record_type = record_type_enterprise & 0xFFF
                        record_length = struct.unpack('!i', data[record_offset+4:record_offset+8])[0]
                        
                        if record_type == 1:  # Raw packet header
                            header_protocol = struct.unpack('!i', data[record_offset+8:record_offset+12])[0]
                            frame_length = struct.unpack('!i', data[record_offset+12:record_offset+16])[0]
                            stripped = struct.unpack('!i', data[record_offset+16:record_offset+20])[0]
                            header_length = struct.unpack('!i', data[record_offset+20:record_offset+24])[0]
                            
                            # Parse Ethernet header
                            packet_data = data[record_offset+24:record_offset+24+header_length]
                            if len(packet_data) >= 14:
                                record = {
                                    'type': 'raw_packet',
                                    'frame_length': frame_length,
                                    'stripped': stripped,
                                    'header_length': header_length,
                                    'ethernet': {
                                        'destination_mac': ':'.join(f'{b:02x}' for b in packet_data[0:6]),
                                        'source_mac': ':'.join(f'{b:02x}' for b in packet_data[6:12]),
                                        'type': struct.unpack('!H', packet_data[12:14])[0]
                                    }
                                }
                                
                                # Parse IP header if present
                                if record['ethernet']['type'] == 0x0800 and len(packet_data) >= 34:  # IPv4
                                    ip_header = packet_data[14:34]
                                    record['ip'] = {
                                        'version': (ip_header[0] >> 4),
                                        'header_length': (ip_header[0] & 0x0F) * 4,
                                        'tos': ip_header[1],
                                        'total_length': struct.unpack('!H', ip_header[2:4])[0],
                                        'identification': struct.unpack('!H', ip_header[4:6])[0],
                                        'flags': (ip_header[6] >> 5),
                                        'fragment_offset': ((struct.unpack('!H', ip_header[6:8])[0] & 0x1FFF)),
                                        'ttl': ip_header[8],
                                        'protocol': ip_header[9],
                                        'protocol_name': self.get_protocol_name(ip_header[9]),
                                        'checksum': struct.unpack('!H', ip_header[10:12])[0],
                                        'source_ip': self.get_ip_from_bytes(ip_header[12:16]),
                                        'destination_ip': self.get_ip_from_bytes(ip_header[16:20])
                                    }

                                    # Parse TCP/UDP header if present
                                    if ip_header[9] in [6, 17] and len(packet_data) >= 38:  # TCP or UDP
                                        transport_header = packet_data[34:38]
                                        record['transport'] = {
                                            'source_port': struct.unpack('!H', transport_header[0:2])[0],
                                            'destination_port': struct.unpack('!H', transport_header[2:4])[0]
                                        }
                                
                                sample['records'].append(record)
                        
                        record_offset += record_length + 8

                    result['samples'].append(sample)
                    self.status.stats["flow_samples"] += 1
                
                elif sample_type == 2:  # Counter Sample
                    sample = {
                        'type': 'counter',
                        'sequence_number': struct.unpack('!i', data[offset+8:offset+12])[0],
                        'source_id_type': (struct.unpack('!i', data[offset+12:offset+16])[0] >> 24) & 0xFF,
                        'source_id_index': struct.unpack('!i', data[offset+12:offset+16])[0] & 0x00FFFFFF,
                        'records': []
                    }
                    
                    # Parse counter records
                    record_offset = offset + 16
                    num_records = struct.unpack('!i', data[record_offset:record_offset+4])[0]
                    record_offset += 4
                    
                    for _ in range(num_records):
                        record_type_enterprise = struct.unpack('!i', data[record_offset:record_offset+4])[0]
                        record_type = record_type_enterprise & 0xFFF
                        record_length = struct.unpack('!i', data[record_offset+4:record_offset+8])[0]
                        
                        if record_type == 1:  # Generic interface counters
                            counter_data = {
                                'if_index': struct.unpack('!i', data[record_offset+8:record_offset+12])[0],
                                'if_type': struct.unpack('!i', data[record_offset+12:record_offset+16])[0],
                                'if_speed': struct.unpack('!q', data[record_offset+16:record_offset+24])[0],
                                'if_direction': struct.unpack('!i', data[record_offset+24:record_offset+28])[0],
                                'if_status': struct.unpack('!i', data[record_offset+28:record_offset+32])[0] & 0x3,
                                'in_octets': struct.unpack('!q', data[record_offset+32:record_offset+40])[0],
                                'in_packets': struct.unpack('!i', data[record_offset+40:record_offset+44])[0],
                                'in_multicast': struct.unpack('!i', data[record_offset+44:record_offset+48])[0],
                                'in_broadcast': struct.unpack('!i', data[record_offset+48:record_offset+52])[0],
                                'in_discards': struct.unpack('!i', data[record_offset+52:record_offset+56])[0],
                                'in_errors': struct.unpack('!i', data[record_offset+56:record_offset+60])[0],
                                'in_unknown_protos': struct.unpack('!i', data[record_offset+60:record_offset+64])[0],
                                'out_octets': struct.unpack('!q', data[record_offset+64:record_offset+72])[0],
                                'out_packets': struct.unpack('!i', data[record_offset+72:record_offset+76])[0],
                                'out_multicast': struct.unpack('!i', data[record_offset+76:record_offset+80])[0],
                                'out_broadcast': struct.unpack('!i', data[record_offset+80:record_offset+84])[0],
                                'out_discards': struct.unpack('!i', data[record_offset+84:record_offset+88])[0],
                                'out_errors': struct.unpack('!i', data[record_offset+88:record_offset+92])[0],
                                'promiscuous_mode': struct.unpack('!i', data[record_offset+92:record_offset+96])[0]
                            }
                            sample['records'].append(counter_data)
                        
                        record_offset += record_length + 8

                    result['samples'].append(sample)
                    self.status.stats["counter_samples"] += 1

                offset += sample_length + 8
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse sFlow data: {str(e)}", exc_info=True)
            self.status.add_error(f"Parse error: {str(e)}")
            self.status.stats["failed_packets"] += 1
            return None

    def convert_to_gelf(self, sflow_data: Dict[str, Any]) -> List[bytes]:
        """Convert sFlow data to GELF format messages"""
        try:
            messages = []
            timestamp = time.time()
            
            for sample in sflow_data.get('samples', []):
                if sample['type'] == 'flow':
                    # Handle Flow Sample
                    for record in sample.get('records', []):
                        if record['type'] == 'raw_packet' and 'ip' in record:
                            message = {
                                "version": "1.1",
                                "host": sflow_data['agent_address'],
                                "short_message": f"sFlow Flow from {sflow_data['agent_address']} if:{sample['input_if']}",
                                "timestamp": timestamp,
                                "level": 6,
                                "_collector": "sflow",
                                "_type": "flow",
                                "_sequence_number": sample['sequence_number'],
                                "_agent_address": sflow_data['agent_address'],
                                "_sub_agent_id": sflow_data['sub_agent_id'],
                                "_uptime": sflow_data['uptime'],
                                "_sampling_rate": sample['sampling_rate'],
                                "_sample_pool": sample['sample_pool'],
                                "_source_id_index": sample['source_id_index'],
                                "_input_if": sample['input_if'],
                                "_output_if": sample['output_if'],
                                "_frame_length": record['frame_length'],
                                "_source_mac": record['ethernet']['source_mac'],
                                "_dest_mac": record['ethernet']['destination_mac'],
                                "_ether_type": f"0x{record['ethernet']['type']:04x}",
                                "_ip_version": record['ip']['version'],
                                "_ip_protocol": record['ip']['protocol'],
                                "_ip_protocol_name": record['ip']['protocol_name'],
                                "_source_ip": record['ip']['source_ip'],
                                "_dest_ip": record['ip']['destination_ip'],
                                "_ip_tos": record['ip']['tos'],
                                "_ip_ttl": record['ip']['ttl']
                            }
                            
                            # Add transport layer info if available
                            if 'transport' in record:
                                message.update({
                                    "_source_port": record['transport']['source_port'],
                                    "_dest_port": record['transport']['destination_port']
                                })
                                
                                # Add protocol-specific descriptions
                                if record['ip']['protocol'] == 6:  # TCP
                                    message["_protocol_detail"] = f"TCP {record['transport']['source_port']} -> {record['transport']['destination_port']}"
                                elif record['ip']['protocol'] == 17:  # UDP
                                    message["_protocol_detail"] = f"UDP {record['transport']['source_port']} -> {record['transport']['destination_port']}"
                            
                            messages.append(json.dumps(message).encode('utf-8'))
                
                elif sample['type'] == 'counter' and self.send_counter_samples:  # 加入條件檢查
                    # Handle Counter Sample
                    for record in sample.get('records', []):
                        # Handle potential negative values due to counter overflow
                        in_packets = record['in_packets']
                        if in_packets < 0:
                            in_packets = in_packets + 2**32
                        out_packets = record['out_packets']
                        if out_packets < 0:
                            out_packets = out_packets + 2**32

                        message = {
                            "version": "1.1",
                            "host": sflow_data['agent_address'],
                            "short_message": f"sFlow Counter from {sflow_data['agent_address']} if:{record['if_index']}",
                            "timestamp": timestamp,
                            "level": 6,
                            "_collector": "sflow",
                            "_type": "counter",
                            "_sequence_number": sample['sequence_number'],
                            "_agent_address": sflow_data['agent_address'],
                            "_sub_agent_id": sflow_data['sub_agent_id'],
                            "_uptime": sflow_data['uptime'],
                            "_source_id_index": sample['source_id_index'],
                            "_if_index": record['if_index'],
                            "_if_type": record['if_type'],
                            "_if_speed": str(record['if_speed']),
                            "_if_direction": record['if_direction'],
                            "_if_status": record['if_status'],
                            "_in_octets": str(record['in_octets']),
                            "_in_packets": str(in_packets),
                            "_in_multicast": record['in_multicast'],
                            "_in_broadcast": record['in_broadcast'],
                            "_in_discards": record['in_discards'],
                            "_in_errors": record['in_errors'],
                            "_in_unknown_protos": record['in_unknown_protos'],
                            "_out_octets": str(record['out_octets']),
                            "_out_packets": str(out_packets),
                            "_out_multicast": record['out_multicast'],
                            "_out_broadcast": record['out_broadcast'],
                            "_out_discards": record['out_discards'],
                            "_out_errors": record['out_errors'],
                            "_promiscuous_mode": record['promiscuous_mode']
                        }
                        messages.append(json.dumps(message).encode('utf-8'))
            
            if messages:
                #logger.info(f"Converting {len(messages)} messages to GELF format")
                return messages
            else:
                #logger.warning("No messages generated from sFlow data")
                return []

        except Exception as e:
            logger.error(f"Failed to convert to GELF: {str(e)}", exc_info=True)
            self.status.add_error(f"GELF conversion error: {str(e)}")
            return []

    async def receive_sflow(self):
        """Receive sFlow packets and process them"""
        logger.info(f"Starting sFlow collector on UDP port {SFLOW_PORT}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', SFLOW_PORT))
        sock.setblocking(False)
        
        while self.processing:
            try:
                ready = await asyncio.get_event_loop().sock_recv(sock, BUFFER_SIZE)
                if ready:
                    data = ready
                    self.status.stats["received_packets"] += 1
                    self.status.last_received_time = time.time()
                    
                    # Parse sFlow data
                    parsed_data = self.parse_sflow(data)
                    if parsed_data:
                        #print(f"Parsed sFlow: {json.dumps(parsed_data, indent=2)}")
                        self.status.stats["processed_packets"] += 1
                        
                        # Convert to GELF and send
                        gelf_messages = self.convert_to_gelf(parsed_data)
                        for message in gelf_messages:
                            if message:  # 確保不是空消息
                                try:
                                    #print(f"Sending GELF message: {message.decode('utf-8')}")
                                    sent = self.graylog_socket.sendto(message, (GRAYLOG_HOST, GRAYLOG_PORT))
                                    #logger.info(f"Sent {sent} bytes to Graylog")
                                    self.status.stats["sent_messages"] += 1
                                    self.status.last_processed_time = time.time()
                                except Exception as e:
                                    logger.error(f"Failed to send to Graylog: {str(e)}", exc_info=True)
                                    self.status.add_error(f"Send error: {str(e)}")

            except Exception as e:
                logger.error(f"Error receiving data: {str(e)}", exc_info=True)
                self.status.add_error(f"Receive error: {str(e)}")
                await asyncio.sleep(1)

    async def run(self):
        """Run the sFlow processor"""
        logger.info("Starting sFlow processing service...")
        try:
            await self.receive_sflow()
        except Exception as e:
            logger.error(f"Service runtime error: {str(e)}", exc_info=True)
            self.status.add_error(f"Runtime error: {str(e)}")
        finally:
            self.processing = False
            self.thread_pool.shutdown()
            self.graylog_socket.close()

async def main():
    # 可以從命令列參數或環境變數讀取設定
    send_counter_samples = SEND_COUNTER_SAMPLES  # 預設值
    processor = SflowProcessor(send_counter_samples=send_counter_samples)
    await processor.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
    except Exception as e:
        logger.error(f"Service stopped with error: {str(e)}", exc_info=True)
