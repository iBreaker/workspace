#!/usr/bin/env python
#coding:utf-8

import xlrd
import argparse
import os
import sys
import re



class makedb(object):
    def __init__(self, path, dir):
        self.path = path
        self.dir = dir 
        self.data = []

    def Readxlsx(self):

        data = xlrd.open_workbook(self.path)
        index = -1
        for table in data.sheets():
            index += 1 
            for i in range(table.nrows):
                try:
                    name = ""
                    iplist = []
                    if (re.match(r"(UDP|TCP|IP)" ,table.row_values(i)[7]) != None):
                        iplist = re.findall(r"\w{2,3}\s\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+", table.row_values(i)[7]) 
                        name = table.row_values(i)[1][:table.row_values(i)[1].find("(https")-1]
                        #print name
                        #iprint iplist
                        for ips in iplist:
                            session = []
                            proto = ips.split(" ")[0]
                            ip1 = re.findall(r"\d+\.\d+\.\d+\.\d+", ips)[0]
                            ip2 = re.findall(r"\d+\.\d+\.\d+\.\d+", ips)[1]
                            port1 = re.findall(r":\d+", ips)[0][1:]
                            port2 = re.findall(r":\d+", ips)[1][1:]

                            if ip1 > ip2:
                                ip1, ip2 = ip2, ip1
                                port1, port2 = port2, port1

                            session.append(proto)
                            session.append(ip1)
                            session.append(port1)
                            session.append(ip2)
                            session.append(port2)
                            session.append(name)
                            classifiName = self.Classifi(session) 
                            session.append(classifiName)
                            
                            print "add:sheet:", index, "line:", i + 1, "|" + classifiName + "|", name
                            self.data.append(session)
                            #print "\n"
                            #print ips
                            #print session
                except:
                    #print "error: sheet:", index, " line:", i + 1
                    pass




                #if(re.match(r"TCP|UDP|IP", row) != None):
                #    print row
                    

        #print len(data.sheets())


    def Classifi(self, session):
        cmd = "grep \"" + session[5] + "\" ./" + self.dir + "/* -l"
        try:
            result = os.popen(cmd)
            string = result.read()
            if string == "":
                return "etc"
            string = string.split("/")[-1]
            string = string.split(".")[0]
        except:
            print "未找到分类"
            return "etc"

        return string

    def Run(self):
        if False == os.path.exists(self.path) or  False == os.path.exists(self.dir):
            print "文件或者文件夹不存在"
            sys.exit(1)

        self.Readxlsx()
        print "total", len(self.data)
        self.WritetoFile()
        pass
    
    def WritetoFile(self):
        self.data = sorted(self.data, key=lambda list:list[5])
        f = open("db.txt", "w")

        lastname = ""
        order = 1
        for session in self.data:
            for i in range(7):
                if 5 == i :
                    if lastname == session[5]:
                        f.write(session[i] + str(order) + "#")
                        order += 1
                    else:
                        order = 1
                        f.write(session[i] + "#")
                else:
                    f.write(session[i] + "#")
            f.write("\n")
            #print session
            lastname = session[5]
        
        f.close()

def main(arg):
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-x", dest="xlsx", help="xlsx文件")
    argParser.add_argument("-d", dest="dir", help="分类目录")
    args = argParser.parse_args(arg)

    if args.xlsx == None or args.dir == None:
        print "参数错误"
        sys.exit(1)
    
    db = makedb(args.xlsx, args.dir)
    db.Run()

if __name__ == "__main__":
    main(sys.argv[1:])
