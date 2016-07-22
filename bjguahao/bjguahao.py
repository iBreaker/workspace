#!/usr/bin/env python
#coding:utf-8

import urllib
import urllib2
import cookielib

USER_AGENT = (
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/45.0.2454.93 Safari/537.36'
)

class APIError(Exception):
    pass
class MergeRequest(object):
    DEFAULT_TITLE = 'Merge Request'
    DEFAULT_CONTENT = ''
    def __init__(self, src_branch, dst_branch):
        self.src_branch = src_branch
        self.dst_branch = dst_branch
        self.title = MergeRequest.DEFAULT_TITLE
        self.content = MergeRequest.DEFAULT_CONTENT

class Client(object):

    def __init__(self):
        self.domain = "www.bjguahao.gov.cn"
        self.login_path = "quicklogin.htm"

        self.cookie = cookielib.CookieJar();
        self.opener = urllib2.build_opener(
                             urllib2.HTTPCookieProcessor(self.cookie),
                        )

        self.opener.addheaders = [
            ('User-Agent', USER_AGENT),
        ]

    def request(self, method, url, data=None):
        payload = urllib.urlencode(data) if data else None
        request = urllib2.Request(url, payload)
        request.get_method = lambda: method
        try:
            response = self.opener.open(request)
            return response
        except Exception:
            raise APIError("unknow error")

       
    def login(self, mobileNo, password):
        url = "http://" + self.domain + "/" + self.login_path
        post_data = dict(mobileNo = mobileNo, password = password, yzm = '', isAjax='true')
        page = self.request('POST', url, data=post_data)
        if(page.read() == '{"data":[],"hasError":false,"code":200,"msg":"OK"}'):
            return True
        else:
            return False

    def getOrder(self):
        url = "http://" + self.domain + "/" + "/v/sendorder.htm"
        page = self.request('POST', url)
        if(page.read() == '{"code":200,"msg":"OK."}'):
            return True
        else:
            return False

    def getDutySourceId(self):
        url = "http://" + self.domain + "/dpt/partduty.htm"
        post_data = dict(hospitalId=142, departmentId='200039602', dutyCode=2, dutyDate='2016-07-29', isAjax='true')
        page = self.request('POST', url, post_data)
        print page.read()
         

if __name__ == "__main__":
    client = Client()
    client.login("18510343389", "guahaowwc110")
    client.request("GET", "http://www.bjguahao.gov.cn/index.htm")
    client.getDutySourceId()
    #print client.getOrder() 
    pass


