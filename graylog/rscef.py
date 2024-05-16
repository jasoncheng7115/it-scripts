#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import logging.handlers
from cefevent import CEFEvent
c = CEFEvent()

# header field
c.set_field('name', 'Graylog Alert Forward')
c.set_field('deviceVendor', 'JT')
c.set_field('deviceProduct', 'graylog_cef_forward')

# get graylog alert json
# add source event timestamp
# add source ip
# add message

getmessage = sys.argv[0]
#c.set_field('message', getmessage)
#c.set_field('message', 'This is a test event (Answer 42)')

# custom field & value
#c.set_field('sourceAddress', '192.168.1.68')
#c.set_field('sourcePort', 12345)

# Finally, generate the CEF line
cefmsg = c.build_cef()
print(cefmsg)

# send to remote server
jsLogger = logging.getLogger('jsLogForward')
#jsLogger.setLevel(logging.WARNING)

# usr nc -u -l 2115  to listen
#ce = logging.handlers.SysLogHandler(address = ('192.168.1.127',2115))
#ce = logging.handlers.SysLogHandler(address = ('192.168.1.127',9556))
ce = logging.handlers.SysLogHandler(address = ('192.168.1.127',25555))

# set format
formatter = logging.Formatter(' %(host)s %(message)s')
ce.setFormatter(formatter)

jsLogger.addHandler(ce)
jsLogger2 = logging.LoggerAdapter(jsLogger, {'host': '192.168.1.68'})
jsLogger2.warning(cefmsg)
