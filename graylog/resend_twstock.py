#!/usr/bin/env python3
#
# Real-time stock information retrieval and sending to Graylog
# This script fetches real-time trading information for the top 36 stocks by market value from the Taiwan Stock Exchange
# It then formats the data into GELF messages and sends them to a specified Graylog server
#
# Jason Tools (www.jason.tools) - Jason Cheng (jason@jason.tools)
#
# Required Python packages:
# pip3 install twstock
# pip3 install lxml
# Note: 'json' and 'socket' are part of the standard Python library and do not require installation via pip.

import json
import socket
import twstock
import time

# Information for Graylog
GRAYLOG_IP = '192.168.1.83'
GELF_PORT = 32201  # Updated port number

def fetch_top_stocks():
    # Simulating the retrieval of the top 36 stock codes, actual data should be fetched from a reliable source
    return ['2330', '2317', '6505', '2454', '2412', '1301', '3008', '2303', '2308', '2882', '1303', '1326',
            '2881', '2886', '2891', '2884', '2885', '2882', '2883', '2890', '2887', '2888', '2889', '2892',
            '2301', '2302', '2305', '3008', '2912', '2454', '2382', '2207', '2357', '2354', '2615', '2633']

def send_to_graylog(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Using UDP
    batch_size = 3  # Each batch processes 3 stock codes
    interval = 5  # 5 second interval between batches

    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        for stock_code in batch:
            try:
                stock = twstock.Stock(stock_code)  # Initialize stock object
                stock_info = twstock.realtime.get(stock_code)
                if stock_info['success']:
                    stock_name = stock_info['info']['name']
                    stock_price = float(stock_info['realtime']['latest_trade_price'])  # Convert price to float
                    message = {
                        "version": "1.1",
                        "host": "stock-fetcher",
                        "short_message": f"{stock_code} {stock_name} ({stock.sid}) - {stock_price}",
                        "level": 6,  # Informational
                        "_stock_code": stock_code,
                        "_stock_name": stock_name,
                        "_stock_price": stock_price
                    }
                    json_data = json.dumps(message).encode('utf-8')
                    print("Sending GELF message to Graylog:", json_data)  # Print GELF raw content
                    sock.sendto(json_data, (GRAYLOG_IP, GELF_PORT))
                else:
                    print(f"Failed to fetch data for stock {stock_code}: {stock_info['rtmessage']}")
            except KeyError as e:
                print(f"Stock code {stock_code} is not found in twstock codes: {e}")
            except Exception as e:
                print(f"An error occurred while processing stock {stock_code}: {e}")
        time.sleep(interval)  # Wait to comply with request limits

top_stocks = fetch_top_stocks()
send_to_graylog(top_stocks)

