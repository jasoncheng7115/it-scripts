#!/usr/bin/env python3

"""
說明：

  這個程式會從 git log 中擷取最近一週內的提交，並將每個提交的詳細資訊轉換為 HTML 格式。
  然後根據設定，它會將郵件本文保存到一個暫存檔，或者使用 smtplib 工具將結果以郵件的形式發送出去。
  如果 git show 沒有任何記錄，則不會發送郵件。

jason@jason.tools
Jason Tools Co., Ltd.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from git import Repo
from ansi2html import Ansi2HTMLConverter
from datetime import datetime, timedelta

# 設定時間範圍
# 若要篩選最近 24 小時的提交，設定為 '24 hours ago'
# 若要篩選最近 2 天的提交，設定為 '2 days ago'
# 若要篩選最近一週的提交，設定為 '1 week ago'
TIME_RANGE = '24 hours ago'

# 設定要檢視的路徑
# 如果有多個路徑要檢視，格式如 "192.168.1.110", "192.168.1.111"
# 如果設定為 "*" 表示擷取所有路徑，也就是裝置的意思
#FILES = ["192.168.1.114", "192.168.1.110"]
FILES = ["*"]

# 設定變數
DIRECTORY = "/home/oxidized/devices_git/"
SUBJECT = "最近 {} 組態變更記錄".format(TIME_RANGE)  # 將時間範圍的內容放到郵件主旨中
TO = "jason@domain.local"
FROM = "librenms@domain.local"
SMTP_SERVER = "192.168.0.222"
SMTP_PORT = 587
SMTP_USER = "librenms"
SMTP_PASSWORD = "yourpassword"
USE_TLS = True  # 如果使用 STARTTLS，設定為 True，否則設定為 False
USE_AUTHENTICATION = 'Y'  # 如果設定為 'Y'，則使用驗證，否則不使用驗證
SAVE_TO_FILE = 'N'  # 如果設定為 'Y'，則將郵件本文保存到一個暫存檔，否則發送郵件



# 切換到指定的目錄並執行 git log
os.chdir(DIRECTORY)
repo = Repo(DIRECTORY)
commits = list(repo.iter_commits('master', since=TIME_RANGE))

# 將每個提交的詳細資訊轉換為 HTML 格式
HTML_RESULT = "<style>body { font-family: 'Courier New'; }</style>"
HTML_RESULT += "<p>本次擷取裝置為：</p><ul>"
if "*" in FILES:
    for commit in commits:
        GIT_SHOW_RESULT = repo.git.execute(["git", "--no-pager", "show", "--color=always", "--name-only", str(commit)])
        changed_files = GIT_SHOW_RESULT.split('\n')[6:]
        for file in changed_files:
            if file != "" and file != ".git":
                HTML_RESULT += "<li>{}</li>".format(file)
else:
    for file in FILES:
        HTML_RESULT += "<li>{}</li>".format(file)
HTML_RESULT += "</ul><hr>"

conv = Ansi2HTMLConverter(inline=True, scheme='solarized')
for commit in commits:
    if "*" in FILES:
        GIT_SHOW_RESULT = repo.git.execute(["git", "--no-pager", "show", "--color=always", str(commit)])
    else:
        GIT_SHOW_RESULT = repo.git.execute(["git", "--no-pager", "show", "--color=always", str(commit), "--"] + FILES)
    HTML_GIT_SHOW_RESULT = conv.convert(GIT_SHOW_RESULT, full=False)
    HTML_GIT_SHOW_RESULT = HTML_GIT_SHOW_RESULT.replace('\n', '<br>\n')  # 在每一行的結尾加上 <br>
    HTML_RESULT += HTML_GIT_SHOW_RESULT
    HTML_RESULT += "<hr><br><br>"

if HTML_RESULT.strip() == "<style>body { font-family: 'Courier New'; }</style>":
    print('git show 沒有任何記錄，不寄送郵件')
elif SAVE_TO_FILE == 'Y':
    # 將郵件本文存入暫存檔
    with open('/tmp/email_content.html', 'w') as f:
        f.write(HTML_RESULT)
    print('郵件本文已儲存至 /tmp/email_content.html')
else:
    # 建立郵件內容
    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = FROM
    msg['To'] = TO
    part = MIMEText(HTML_RESULT, 'html', 'utf-8')  # 指定 charset 為 UTF-8
    msg.attach(part)

    # 使用 smtplib 工具發送郵件
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.ehlo()
    if USE_TLS:
        server.starttls()
    if USE_AUTHENTICATION == 'Y':
        server.login(SMTP_USER, SMTP_PASSWORD)    
    server.sendmail(FROM, TO, msg.as_string())
    server.quit()
