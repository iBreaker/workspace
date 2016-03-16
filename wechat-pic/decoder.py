#!/usr/bin/env python
#coding=utf-8


import argparse
import os

path = "dat.dat"
out_path = "out.bmp"


def get_ofile(ifile, output):
    basename = os.path.basename(ifile)
    tmp_file = "out_" + os.path.splitext(basename)[0] + ".jpg"
    return os.path.join(output, tmp_file)

def parse_file(input, output):
    if not os.path.exists(input):
        print "文件或文件夹不存在"
        exit()
         
    if not  os.path.exists(output):
        try:
            os.makedirs(output)
        except Exception, e:
            print "error " , e
            exit()

    if os.path.isdir(input):
        for i in os.listdir(input):
            if os.path.isfile(os.path.join(input, i)):
                decoder(os.path.join(input, i), get_ofile(os.path.join(input, i), output ))
    else:
        decoder(input, get_ofile(input, output))



def decoder(ifile, ofile):
    ifile = open(ifile, "rb")
    ofile = open(ofile, "w")
    for i in ifile.read():
        tmp = chr(ord(i)^0x37)
        ofile.write(tmp)
    ifile.close()
    ofile.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="加密文件或者文件夹", type =str)
    parser.add_argument("-o", "--output", help="解密后保存文件夹", type = str )
    args = parser.parse_args()
    
    parse_file(args.input, args.output)


if __name__ == "__main__":
    main()
