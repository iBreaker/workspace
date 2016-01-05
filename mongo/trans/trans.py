#!/usr/bin/env python
# -*- coding: utf-8 -*-
###############
# Date    : 2015-12-23 16:38:49
# Author  : Victor Lin
# Email    : linxianwusx@gmail.com
###############
import sqlite3
from pymongo import MongoClient
from common2word import segmentation_common2word_split
import os
import json
import zlib
import binascii
import logging
class Pcap():
    def __init__(self,microThreadId = None,sessionId = None,s2cIp = None,
                  s2cPort = None, c2sIp = None, c2sPort = None, filename = None):
        self.microThreadId = microThreadId
        self.sessionId = sessionId
        self.s2cIp = s2cIp
        self.s2cPort = s2cPort
        self.c2sIp = c2sIp
        self.c2sPort = c2sPort
        self.filename = filename

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def part(self, data):
        return segmentation_common2word_split(data)

    def setf(self, fid, data):
        if isinstance(data,int) or isinstance(data,long):
            key = "fid_%d" % fid
            setattr(self, key, data)
        else:
            key_part = "fid_%d_part" % fid
            key = "fid_%d" % fid
            setattr(self, key, data)
            setattr(self, key_part, self.part(data))

    def get_json(self):
        return self.__dict__


class Db():
    def __init__(self):
        self.client = MongoClient("127.0.0.1",27017)

    def insert_db(self,pacp):
        self.collection = self.client.get_database("bps_source").get_collection("good_samples")
        self.collection.insert(vars(pacp))


def get_sqlite_files(folder_path):
    file_path_list = []
    for root, dirs, files in os.walk( folder_path ):
        for fn in files:
            file_path = os.path.join(root, fn)
            file_path_list.append([fn, file_path])

    return file_path_list


db = Db()
def main():
    num = 0
    for filename, path in get_sqlite_files("../sqlite"):
        try:
            cx = sqlite3.connect(path)
            cx.text_factory = str
            cu=cx.cursor()

            cu.execute("select microThreadId, sessionId, s2cIp, s2cPort, c2sIp, c2sPort from ZealotMicroThread")
            for i in cu.fetchall():
                microThreadId, sessionId, s2cIp, s2cPort, c2sIp, c2sPort = i

            pacp = Pcap(microThreadId,sessionId,s2cIp,s2cPort,c2sIp,c2sPort,filename)
            cu.execute("select fid,data from ZealotNumericData")
            for i in cu.fetchall():
                fid,data = i
                pacp.setf(fid,data)

            cu.execute("select data from ZealotFieldData")
            data = []
            part= []
            for i in cu.fetchall():
                if i == (None,):
                    print "fail"
                    continue
                print i
                temp = binascii.b2a_qp(i[0]).strip().strip('"').strip()
                data.append(temp)
                part.append(segmentation_common2word_split(temp))

            pacp.coarse_part = "||".join(data)
            pacp.fine_part = " | | ".join(part)

            db.insert_db(pacp)
            num += 1
            print num
        except Exception as e:
            import traceback
            logging.error(traceback.format_exc())
            num += 1
            raise Exception(e)


if __name__ == "__main__":
    os.chdir(os.path.split(os.path.realpath(__file__))[0])
    main()
