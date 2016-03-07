#!/usr/bin/python
#encoding=utf-8

from __future__ import unicode_literals

import cookielib
import datetime
import hashlib
import json
import os
import sys
import urllib
import urllib2
import time

USER_AGENT = (
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/45.0.2454.93 Safari/537.36'
)

#所有账号总码币数
#你问我为什么要用全局变量
#因为懒(╯﹏╰)
TOTALCOUNT = 0
TOTALGET = 0
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
        self.cookiejar = cookielib.LWPCookieJar()
        self.opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookiejar),
        )
        self.opener.addheaders = [
            ('User-Agent', USER_AGENT),
        ]
        self.global_key = None

    def load_cookies(self, path):
        self.cookiejar.load(path)

    def save_cookies(self, path):
        self.cookiejar.save(path)

    def request(self, method, url, data=None):
        payload = urllib.urlencode(data) if data else None
        request = urllib2.Request(url, payload)
        request.get_method = lambda: method
        #网络错误自动重试
        for i in range(0,3):
            try:
                response = self.opener.open(request)
                break
            except Exception as e:
                if i == 2 :
                    print '网络错误，重试次数过多，跳过该操作'
                    return ''
                else :
                    print "网络错误，正在进行第{}次重试".format(i + 1)
                    time.sleep(1)
        try:
            data = json.loads(response.read())
            if data['code'] == 0:#操作成功
                try:
                    return data['data']
                except KeyError:
                    return ''
            else:#操作失败
                try:
                    raise APIError(data['msg'])
                except KeyError:
                    raise APIError("unknow error")
        except Exception:
            raise APIError("unknow error")

    def login(self, username, password):
        page = self.request('GET', 'https://coding.net/api/captcha/login')

        if len(password) == 40 :
            password_hash = password
        else :
            password_hash = hashlib.sha1(password).hexdigest()

        payload = {
            'email': username,
            'password': password_hash,
            'remember_me': True,
        }
        page = self.request('POST', 'https://coding.net/api/login', data=payload)
        self.global_key = page['global_key']
        self.id = page['id']

    def get_account_info(self):
        return self.request('GET', 'https://coding.net/api/account/current_user')

    def create_task(self, project, content):
        payload = {
            'content': content,
            'owner_id': self.id,
        }
        page = self.request(
            'POST',
            'https://coding.net/api/user/{}/project/{}/task'.format(
                self.global_key,
                project,
            ),
            data=payload,
        )
        return page['id']

    def delete_task(self, project, task_id):
        self.request(
            'DELETE',
            'https://coding.net/api/user/{}/project/{}/task/{}'.format(
                self.global_key,
                project,
                task_id,
            )
        )

    def create_merge_request(self, project, request):
        payload = {
            'srcBranch': request.src_branch,
            'desBranch': request.dst_branch,
            'title': request.title,
            'content': request.content,
        }
        page = self.request(
            'POST',
            'https://coding.net/api/user/{}/project/{}/git/merge'.format(
                self.global_key,
                project,
            ),
            data=payload,
        )
        return page['merge_request']['iid']

    def delete_merge_request(self, project, mr_id):
        self.request(
            'POST',
            'https://coding.net/api/user/{}/project/{}/git/merge/{}/cancel'.format(
                self.global_key,
                project,
                mr_id,
            )
        )

    def create_ide_request(self, project, spaceKey):
        payload = {
            'ownerName': self.global_key,
            'projectName': project,
            'host': '',
            'spaceKey': spaceKey,
            'memory': '256'
        }
        resp = self.request('POST', 'https://ide.coding.net/backend/ws/create', data=payload)
        return resp

    def create_project_request(self,project):
        payload = {
            'type': 2,
            'gitEnabled': 'true',
            'gitReadmeEnabled': 'true',
            'gitIgnore': 'no',
            'gitLicense': 'no',
            'vcsType': 'git',
            'name': project,
            'importFrom': '',
            'members': '',
        }
        resp = self.request('POST', 'https://coding.net/api/project', data=payload)
        return resp

    def delete_project_request(self,project,proj_id,password):
        if len(password) == 40 :
            password_hash = password
        else :
            password_hash = hashlib.sha1(password).hexdigest()

        resp = self.request('DELETE', 'https://coding.net/api/project/{}?name={}&two_factor_code={}'.format(
                proj_id,
                project,
                password_hash
            )
        )

    def create_branch_request(self, project, branch):
        '''
        #请求所有分支列表
        resp = self.request('GET', '/user/{}/project/{}/git/list_branches'.format(
                self.global_key,
                project
            )
        )
        '''
        payload = {
            'branch_name': branch,
        }
        resp = self.request('POST', 'https://coding.net/api/user/{}/project/{}/git/branches/create'.format(
                self.global_key,
                project,
            ),
            data=payload
        )
        return resp

    def create_push_request(self, project, branch, content):
        resp = self.request('GET', 'https://coding.net/api/user/{}/project/{}/git/edit/{}%252FREADME.md'.format(
                self.global_key,
                project,
                branch
            )
        )
        lastCommitSha = resp['lastCommit']

        payload = {
            'content': content,
            'message': 'DailyPush',
            'lastCommitSha': lastCommitSha,
        }

        resp = self.request('POST', 'https://coding.net/api/user/{}/project/{}/git/edit/{}%252FREADME.md'.format(
                self.global_key,
                project,
                branch
            ),
            data=payload
        )

    def get_project_info(self,project):
        resp = self.request('GET', 'https://coding.net/api/user/{}/project/{}'.format(
                self.global_key,
                project
            )
        )
        return resp

    def get_point_left(self):
        resp = self.request('GET', 'https://coding.net/api/point/balance')
        return resp["point_left"]

    def get_records(self):
        resp = self.request('GET', 'https://coding.net/api/point/records')
        return resp["list"]

    def auto_focus_author(self, username):
        resp = self.request('POST', 'https://coding.net/api/user/follow?users={}'.format(username))
        return resp

    def get_webide_spacekey(self, project):
        resp = self.request('GET', 'https://ide.coding.net/backend/ws/list')
        ides = resp["list"]
        spaceKey = ""
        for json in ides:
            if json["projectName"] == project:
                spaceKey = json["spaceKey"]
                break
        return spaceKey

def routine(username, password, project, branch, save_cookies, to_clean = False):

    client = Client()
    cookies_path = os.path.expanduser('~/.{}.cookies'.format(username))
    
    try:
        try:
            if not save_cookies :
                raise APIError('')
            #载入缓存的cookies
            #发送请求账户信息的get请求，获取key与id
            client.load_cookies(cookies_path)
            print 'Cookies已装载'
            info = client.get_account_info()
            client.global_key = info['global_key']
            client.id = info['id']
            print '账户ID确认: "{}"'.format(client.global_key)
        except (IOError, APIError):
            #cookies无效，重新登录
            client.login(username, password)
            print '账户: "{}" 登陆成功'.format(client.global_key)
            if save_cookies :
                client.save_cookies(cookies_path)
                print 'Cookies已存储.'

        if to_clean :
            try:
                print '正在删除 "{}" 项目'.format(project)
                proj_id = client.get_project_info(project)['id']
                client.delete_project_request(project,proj_id,password)
                print '"{}" 项目删除成功'.format(project)
            except APIError as e:
                for k, v in e.message.iteritems():
                    print k, v
            return
        
        content = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        point_before = client.get_point_left()
        #创建项目
        try:
            client.create_project_request(project)
            print '首次运行，创建项目: "{}" 成功'.format(project)
        except APIError as e:
            pass

        #创建分支
        try:
            client.create_branch_request(project,branch)
            print '首次运行，创建分支: "{}" 成功'.format(branch)
            client.create_push_request(project,branch,content)
            print '首次运行，差异化分支使可合并操作完成'
        except APIError as e:
            pass

        #获取当前时间
        now = time.localtime(int(time.time()))
        year = now.tm_year
        month = now.tm_mon
        day = now.tm_mday

        #获取今日已完成任务
        today_records = []
        records = client.get_records()
        for record in records:
            created_time = time.localtime(record["created_at"] / 1000)
            created_year = created_time.tm_year
            created_month = created_time.tm_mon
            created_day = created_time.tm_mday
            if created_year == year and created_month == month and created_day == day:
                today_records.append(record["usage"])

        #推送代码
        if "推送代码" in today_records:
            print '今日已完成推送代码'
        else:
            client.create_push_request(project,branch,content)
            print '推送代码: "{}" 成功'.format(content)

        #创建任务
        if "任务操作" in today_records:
            print '今日已完成任务操作'
        else:
            task_id = client.create_task(project, content)
            client.delete_task(project, task_id)
            print '任务: "{}" 操作成功'.format(task_id)

        #创建合并请求
        if "创建合并请求" in today_records:
            print '今日已完成创建合并请求'
        else:
            mr = MergeRequest(branch, 'master')
            mr.title = content
            mr_id = client.create_merge_request(project, mr)
            client.delete_merge_request(project, mr_id)
            print '合并请求: "{}" 创建成功'.format(mr_id)

        #进入webIDE
        '''
        if "打开 WebIDE" in today_records:
            print '今日已完成打开WebIDE'
        else:
            spaceKey = client.get_webide_spacekey(project)
            client.create_ide_request(project,spaceKey)
            print 'WebIDE 打开成功'
        '''
        
        #显示余额
        global TOTALCOUNT
        global TOTALGET
        point_after = client.get_point_left()
        point_get = point_after - point_before
        TOTALCOUNT = TOTALCOUNT + point_after
        TOTALGET = TOTALGET + point_get
        print "本次收入 {}".format(point_get)
        print "码币余额 {}".format(point_after)

        #偷偷关注作者, <(￣▽￣)> 
        '''
        try:
            client.auto_focus_author("ookcode")
        except APIError as e:
            pass
        '''

    except APIError as e:
        print 'Error:'
        for k, v in e.message.iteritems():
            print k, v

def main():
    reload(sys)
    sys.setdefaultencoding("utf-8")
    #会自动创建的项目名
    project = 'MBRobot'
    #会自动创建的分支名
    branch = 'auto-merge'

    global TOTALCOUNT
    global TOTALGET

    if len(sys.argv) == 3 :
        routine(
            username = sys.argv[1],
            password = sys.argv[2],
            project = project,
            branch = branch,
            save_cookies = False,
            to_clean = False
        )
        return

    #是否执行清理工作
    to_clean = False
    if len(sys.argv) == 2 :
        if sys.argv[1] == 'clean' :
            to_clean = True

    config_path = os.path.expanduser('~/.coding.config')
    if not os.path.exists(config_path):
        print '错误：配置文件 ' + config_path + ' 未找到'
        return

    with open(config_path, 'r') as f:
        try:
            config = json.load(f)
        except Exception,e :
            print "错误：配置文件格式不正确"
            return
    count = 0
    for account in config:
        if 'username' in account and 'password' in account :
            now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()));
            print "--------------------------------------------------------"
            print '{}: {} 正在召唤 {}'.format(count,now,account['username'])
            print "--------------------------------------------------------"
            routine(
                username = account['username'],
                password = account['password'],
                project = project,
                branch = branch,
                save_cookies = True,
                to_clean = to_clean
            )
            count = count + 1
        else:
            print '错误：未能在配置文件中读取账号密码'

    if not to_clean:
        print "--------------------------------------------------------"
        print "本次共运行{}个账号".format(count)
        print "累计收入码币:{}".format(TOTALGET)
        print "所有账户总码币数:{}".format(TOTALCOUNT)
        print "--------------------------------------------------------"
    
if __name__ == '__main__':
    main()
