#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
import json
import subprocess

app = Flask(__name__)

@app.route("/")
def home():
    return "Graylog to CEF"

@app.route("/graylog", methods=['POST'])
def graylog():

    logfile = '/tmp/rscef-srv.log'

    #f = open(logfile, 'a')

    data = request.get_data()
    jdata = json.loads(data)

    arg1 = "GrayLog"
    arg2 = ""

    # 取得 backlog 筆數
    # Graylog 的 alert Notification 至少 backlog 要有 1，否則無法顯示 message
    backlog_len = len(jdata['backlog'])

    # 取得是否有 full_message
    #if 'full_message' in jdata['backlog'][0]['fields'].keys():
    #  print("has full_message\n")

    # 取得定義事件顯示類型 (預設取 message)
    messagetype = 'message'
    if 'to_lnms_type' in jdata['event']['fields'].keys():
      messagetype = str(jdata['event']['fields']['to_lnms_type'])

    # 列舉
    if backlog_len > 0:
        arg2 += ""
        arg2 += ""
        for i in range(backlog_len):
            try:
                if messagetype == "windows_login":
                  # 如要單獨處理 windows login 事件，請：
                  # 在處理事件類型 (graylog > fields > add custom fields)
                  # name 填入 to_lnms_type
                  # set value from 選擇 template
                  # template 填入 windows_login
                  # 以下輸出格式與內容可自行修改
                  arg2 += " [ "
                  arg2 += "WorkstationName=" + jdata['backlog'][i]['fields']['WorkstationName'] + " | "
                  arg2 += "TargetUserName=" + jdata['backlog'][i]['fields']['TargetUserName'] + " | "
                  arg2 += "IpAddress=" + jdata['backlog'][i]['fields']['IpAddress'] + " "
                  arg2 += "] "
                else:
                  # 其它類型事件
                  arg2 += " [ " + jdata['backlog'][i][messagetype] + " ] "
                arg2 += ";"
            except:
                print("i=" + str(i))


    #f.write("arg2=" + str(arg2) + "\n")
    #f.close()

    # 去掉所有 \r \n \t 字元
    arg2 = arg2.replace("\n", " | ")
    arg2 = arg2.replace("\r", "")
    arg2 = arg2.replace("\t", "  ")

    subprocess.check_call("/opt/rscef.py '%s' " % (str(arg2)), shell=True)
    return "Success"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=38101)
