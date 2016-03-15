#!/usr/bin/env python
#coding=utf-8

import logging
logging.getLogger("scrapy").setLevel(1)

from scapy.all import *

class qq(Packet):
    name = "qq"
    fields_desc = [
            XByteField("header",1),
            ShortField("version",1),
            ShortField("command",1),

                    
            ]

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="qq add-ones")
