#!/usr/bin/env python
#coding:utf-8

import urllib
import urllib2

domain = "www.bjguahao.gov.cn"
login_path = "quicklogin.htm"

def login(mobileNo, password):
    
    url = "http://" + domain + "/" + login_path
    post_data = dict(mobileNo = mobileNo, password = password, yzm = '', isAjax='true')
    data = urllib.urlencode(post_data)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    the_page = response.read()
    print the_page


if __name__ == "__main__":
    login("18510343389", "guahaowwc110")
    pass


