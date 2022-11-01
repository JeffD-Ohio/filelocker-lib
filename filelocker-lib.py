## Python 3.8.0 ##

import urllib.request
from http.cookiejar import CookieJar
import configparser
import xml.etree.ElementTree as ET
import hashlib
import sys
import os
import io


class Filelocker:

    def __init__(self, userId, directory=None, configFile=None):
        self.userId = userId
        self.directory = directory
        cookie_jar = CookieJar()
        try:
            self.installedHandler = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
            urllib.request.install_opener(self.installedHandler)
            confParser = configparser.ConfigParser()
            if configFile==None:
                configFile = os.path.join(os.getcwd(), "filelocker_cli.conf")
            if os.path.isfile(configFile)==False:
                print("Filelocker_cli.conf could not be located at: %s", configFile)
            confParser.read(configFile)
            self.serverLocation = confParser.get('filelocker_cli', 'server_url')
            CLIKey = confParser.get('filelocker_cli', 'cli_key')
            self.login(CLIKey, userId)
        except Exception as e:
            print("[Critical - Initializer]: %s", str(e))


    def login(self, CLIKey, userId):
        data = urllib.parse.urlencode({'CLIkey': CLIKey, 'userId': userId}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        response = self.send_data("/cli_interface/CLI_login", data, headers)
        if(response == 0):
            print(response)


    def show_files(self):
        data = urllib.parse.urlencode({'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        request = self.send_data("/file_interface/get_user_file_list", data, headers)
        return_list = []
        if(request != None):
            req_root = ET.fromstring(request)
            length = len(req_root[1].findall('file'))
            for files in range(length):
                return_list.append(req_root[1][files].attrib['name'])
        return return_list


    def show_files_size(self):
        data = urllib.parse.urlencode({'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        request = self.send_data("/file_interface/get_user_file_list", data, headers)
        return_list = []
        if(request != None):
            req_root = ET.fromstring(request)
            length = len(req_root[1].findall('file'))
            for files in range(length):
                return_list.append([req_root[1][files].attrib['name'],req_root[1][files].attrib['size']])
        return return_list
        

    def show_groups(self):
        data = urllib.parse.urlencode({'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        self.send_data("/group_interface/get_groups", data, headers)


    def upload(self, filePath):
        file_name = os.path.basename(filePath)
        file_size = os.path.getsize(filePath)
        check_list = self.show_files_size()
        dup_flag = False
        for pairs in check_list:
            if(set([file_name, file_size]) & set(pairs)):
                dup_flag = True
        if(dup_flag == False):
            params = {}
            params['format'] = 'cli'
            params['fileName'] = file_name
            md5_hash = self.md5(filePath)
            params['fileNotes'] = 'Uploaded via Automated Script. Contact delongj@ohio.edu for issues. MD5 Hash: %s' % md5_hash
            f = io.open(filePath, "rb")
            headers = {"Content-Type": "application/octet-stream", "Accept": "text/xml", "Content-Length": file_size, "X-File-Name": file_name}
            data = urllib.parse.urlencode(params).encode('ascii')
            self.send_data("/file_interface/upload?" + str(data), f, headers)
            f.close()


    def share(self, fileIds, targetIds, shareType):
        if shareType=="user":
            data = urllib.parse.urlencode({'fileIds': fileIds, 'targetId': targetIds, 'format': 'cli'}).encode('ascii')
        elif shareType=="group":
            data = urllib.parse.urlencode({'fileIds': fileIds, 'groupId': targetIds, 'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        self.send_data("/share_interface/create_private_share", data, headers)


    def delete(self, fileIds):
        data = urllib.parse.urlencode({'fileIds': fileIds, 'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        self.send_data("/file_interface/delete_files", data, headers)


# Helper functions

    def md5(self, file_name):
        hash_md5 = hashlib.md5()
        with open(file_name, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()


    def send_data(self, path, data, headers):
        try:
            request = urllib.request.Request(self.serverLocation + path, data, headers)
            response = self.installedHandler.open(request)
            return response.read().decode('utf-8')
        except Exception as e:
            print("[Critical - Send_Data() Method]: %s", str(e))


    def split_list_sanitized(self, cs_list):  # To be used later when multi-calls are implemented
        clean_list = []
        if cs_list is not None:
            for list_item in cs_list.split(','):
                if list_item is not None and list_item != "":
                    clean_list.append(list_item)
        return clean_list


    def get_file_id(self, fileName):
        data = urllib.parse.urlencode({'format': 'cli'}).encode('ascii')
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/xml"}
        request = self.send_data("/file_interface/get_user_file_list", data, headers)
        return_list = []
        if(request != None):
            req_root = ET.fromstring(request)
            length = len(req_root[1].findall('file'))
            for files in range(length):
                return_list.append([req_root[1][files].attrib['id'],req_root[1][files].attrib['name']])
        for item in return_list:
            if(fileName in item):
                return item[0]

