import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import math
import nacl.pwhash.argon2id
import nacl.utils
from nacl.public import PrivateKey, SealedBox
import nacl.secret
#sqlite is my script
import sqlite
import nacl.hash
import socket

class mainApi:

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def ping(self, apiKey, pubkey, prikey):
        url = "http://cs302.kiwi.land/api/ping"
        pubkey_bytes = bytes(pubkey, encoding='utf=8')
        signature = prikey.sign(pubkey_bytes,encoder=nacl.encoding.HexEncoder)

        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
        "pubkey" : pubkey,
        "signature" : signature.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    def newApiKey(self):
        url = "http://cs302.kiwi.land/api/load_new_apikey"
        credentials = ('%s:%s' % (self.username, self.password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
            JSON_object = json.loads(data.decode(encoding))
        except urllib.error.HTTPError as error:
            JSON_object = {'response' : "no"}
        
        return (JSON_object)

    def addPubkey(self,apiKey):
        url = "http://cs302.kiwi.land/api/add_pubkey"
        private_key = nacl.signing.SigningKey.generate()
        print(private_key.encode(encoder=nacl.encoding.HexEncoder))
        pubkey = private_key.verify_key
        pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
        signature = bytes(pubkey_hex.decode('utf-8') + self.username, encoding='utf-8')
        signed = private_key.sign(signature, encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
            "pubkey": pubkey_hex.decode('utf-8'),
            "username": self.username,
            "signature": signed.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode('utf-8')
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        response = [JSON_object, private_key, pubkey_hex.decode('utf-8')]
        return response

    def LoginServerRecord(self,apiKey):
        url = "http://cs302.kiwi.land/api/get_loginserver_record"
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        #print(JSON_object)
        return JSON_object["loginserver_record"]

    def Report(self,apiKey,pubkey,status):
        url = "http://cs302.kiwi.land/api/report"
        headers = {
        'X-username' : self.username,
        'X-apikey' : apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
        }
        ip = ip = "" + socket.gethostbyname(socket.gethostname()) + ":" + "10050"
        payload = {
        "connection_address" : ip,
        #"connection_address" : "127.0.0.1:1234",
        #"connection_address" : "192.168.1.19:10050",
        #"connection_address" : "192.168.1.19:8080",
        "connection_location" : 0,
        "incoming_pubkey" : str(pubkey),
        "status" : status
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        print("###################")
        print(JSON_object)
        print("###################")
        return JSON_object

    def listUsers(self,apiKey):
        url = "http://cs302.kiwi.land/api/list_users"
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() 
            encoding = response.info().get_content_charset('utf-8') 
            response.close() 
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        #username, address, location, pubkey, time, status
        return JSON_object

    def Broadcast(self, apiKey, prikey, message):
        #url = "http://cs302.kiwi.land/api/rx_broadcast"
        loginserver_record = self.LoginServerRecord(apiKey)
        print(loginserver_record)
        timestamp = str(time.time())
        signed = bytes(loginserver_record + message + timestamp, encoding='utf-8')
        signature = prikey.sign(signed,encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
            "loginserver_record" : loginserver_record,
            "message" : message,
            "sender_created_at" : timestamp,
            "signature" : signature.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")

        user = self.listUsers(apiKey)
        for i in range(len(user["users"])):
            #if(user["users"][i]["connection_location"] == 1):
            url = "http://" + user["users"][i]["connection_address"] + "/api/rx_broadcast"
            try:
                
                req = urllib.request.Request(url, data=json_payload, headers=headers)
                response = urllib.request.urlopen(req, timeout=1)
                data = response.read()
                encoding = response.info().get_content_charset('utf-8')
                print("sent" + user["users"][i]["username"])
                response.close()
                
            #except urllib.error.HTTPError as error:
            except:
                print("did not send" + user["users"][i]["username"])
            try:        
                JSON_object = json.loads(data.decode(encoding))
                print(JSON_object)
            except:
                print("soz")
         
        return str(JSON_object)
        #return 1

    def privateMessage(self, message, targetUsername, apiKey, prikey):
        #self, message, targetusername, apikey, prikey
        client_saved_at = str(time.time())
        sqlite.insertPM(self, self.username,targetUsername,self.username,targetUsername,message,client_saved_at)
        data = sqlite.getOnline(self)
        for i in range(len(data["name"])):
            if (data["name"][i] == targetUsername):
                address = data["address"][i]
        url = "http://" + address + "/api/rx_privatemessage"
        loginserver_record = self.LoginServerRecord(apiKey)
        
        target_pubkey = str(sqlite.findOnline(self, str(targetUsername)))
        print(target_pubkey)
        pubkey = nacl.signing.VerifyKey(target_pubkey, encoder=nacl.encoding.HexEncoder)
        curvedrxpubkey = pubkey.to_curve25519_public_key()
        sealed_box = SealedBox(curvedrxpubkey)
        message = bytes(message, encoding='utf-8')
        encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
        signed = bytes(loginserver_record + target_pubkey + targetUsername + encrypted.decode('utf-8') + client_saved_at, encoding='utf-8')
        signature = prikey.sign(signed,encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
            "loginserver_record" : loginserver_record,
            "target_pubkey" : target_pubkey,
            "target_username" : targetUsername,
            "encrypted_message" : encrypted.decode('utf-8'),
            "sender_created_at" : client_saved_at,
            "signature" : signature.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print("$$$$$$$$$$$$$$$$$$")
            print(error.read())
            exit()
        print("##############33")
        print(data)
        print("#################")

        JSON_object = json.loads(str(data.decode(encoding)))
        print(JSON_object)

    def decriptPrivateData(self,apiKey,password):
        enc_data = str(self.getPrivateData(apiKey)["privatedata"])
        str_pass = str(password)
        byte = bytes(str_pass, encoding='utf-8')
        key_password = str_pass*16
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        box = nacl.secret.SecretBox(key)
        try:
            plaintext = box.decrypt(str(enc_data), encoder=nacl.encoding.Base64Encoder)
            data = plaintext.decode('utf-8')
            print("***************")
            print(plaintext)
            json_acceptable_string = data.replace('"', "\"")
            d = json.loads(json_acceptable_string)
            return d
        except:
            return 0

    def addPrivateData(self,apiKey,prikey,password,newData):
        url = "http://cs302.kiwi.land/api/add_privatedata"
        loginserver_record = self.LoginServerRecord(apiKey)
        client_saved_at = str(time.time())
        str_pass = str(password)
        byte = bytes(str_pass, encoding='utf-8')
        key_password = str_pass*16
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        box = nacl.secret.SecretBox(key) #safe used to encrypt/decrypt messages
        prikeyData = prikey.encode(encoder=nacl.encoding.HexEncoder)
        private_data_dict = newData
        # a = list()
        # b = list()
        # c = list()
        # d = list()
        # e = list()
        # private_data_dict = {
        #     "prikeys" : [prikeyData.decode('utf-8')],
        #     "blocked_pubkeys" : a,
        #     "blocked_usernames" : b,
        #     "blocked_words" : c,
        #     "blocked_message_signatures" : d,
        #     "favourite_message_signatures" : e,
        #     "friends_usernames" : newData
        # }
        jsonString = json.dumps(private_data_dict)
        jsonBytes = bytes(jsonString, encoding='utf-8')
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(jsonBytes, nonce, encoder=nacl.encoding.Base64Encoder)
        private_data = encrypted.decode('utf-8')
        signed = bytes(private_data + loginserver_record + client_saved_at, encoding='utf-8')
        signature = prikey.sign(signed,encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
        "privatedata" : private_data, 
        "loginserver_record" : loginserver_record,
        "client_saved_at" : client_saved_at,
        "signature" : signature.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    def getPrivateData(self,apiKey):
        url = "http://cs302.kiwi.land/api/get_privatedata"
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        return JSON_object

    def ping_check(self, apiKey):
        #url = "http://cs302.kiwi.land/api/ping"
        address = list()
        address = sqlite.getOnline(self)['address']

        #url = "http://172.23.13.81:8080/api/ping_check"
        
        timestamp = str(time.time())
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        ip = "" + socket.gethostbyname(socket.gethostname()) + ":" + "10050"
        payload = {
            "my_time" : timestamp,
            "connection_address" : ip,
            "connection_location" : 0
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        for i in range(len(address)):
            url = "http://" + address[i] + "/api/ping_check"
            try:
                req = urllib.request.Request(url, data=json_payload, headers=headers)
                response = urllib.request.urlopen(req, timeout=0.1)
                data = response.read()
                print(data)
                encoding = response.info().get_content_charset('utf-8')
                response.close()
                print("here")
                JSON_object = json.loads(data.decode(encoding))
                print(JSON_object)
            except:
                print("nope")
                JSON_object = "{'response' : 'ok'}"
            
        
        print(JSON_object)
        return JSON_object
    
    #def previous_decryption(self, p_prikey):
        
    def decryptingPM(self, prikey, friend):
        data = sqlite.getPM(self, self.username.lower(), friend)
        print(data)
        pm = list()
        count = 0
        # try:
        for i in range(len(data['message'])):
            message = data['message'][i]
            if (data['sender'][i] == friend):
                try:
                    curvePrivateKey = prikey.to_curve25519_private_key()
                    box = SealedBox(curvePrivateKey)
                    plaintext = box.decrypt(message, encoder=nacl.encoding.HexEncoder)
                    pm.append(plaintext.decode('utf-8'))
                    print("MESSAGES")
                    print(plaintext)
                    print("MESSAGES")
                except:
                    count = 1
            elif (data['sender'][i] == self.username.lower()):
                pm.append(message)

        if (count == 1):
            pm = ["No message history found or an error occured"]
            data['receiver'] = [""]
            data['sender'] = [""]
            data['time'] = [""]
        
        for i in range(len(pm)):
            pm[i] = sqlite.strip_tags(str(pm[i]))

        data = {
            'sender' : data['sender'],
            'receiver' : data['receiver'],
            'message' : pm,
            'time' : data['time']
        }
        return data
    
    def createGroup(self, prikey, apiKey):
        url = "http://172.23.2.31:10050/api/rx_groupinvite"
        target = "misl000"
        loginserverRecord = self.LoginServerRecord(apiKey)
        str_pass = str("ikea")
        byte = bytes(str_pass, encoding='utf-8')
        key_password = str_pass*16
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        hashed = nacl.hash.sha256(key, encoder=nacl.encoding.HexEncoder)
        hashed = hashed.decode('utf-8')
        pubkey = str(sqlite.findOnline(self, str(target)))
        public = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
        curvedpubkey = public.to_curve25519_public_key()
        box = SealedBox(curvedpubkey)
        encrypted_groupkey = box.encrypt(key, encoder=nacl.encoding.HexEncoder)
        encrypted_groupkey = encrypted_groupkey.decode('utf-8')
        sender_created_at = str(time.time())
        signature = bytes(loginserverRecord + hashed + pubkey + target + encrypted_groupkey + sender_created_at, encoding='utf-8')
        signed = prikey.sign(signature, encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
            'loginserver_record' : loginserverRecord,
            'groupkey_hash' : hashed,
            'target_pubkey' : pubkey,
            'target_username' : self.username,
            'encrypted_groupkey' : encrypted_groupkey,
            'sender_created_at' : sender_created_at,
            'signature' : signed.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    def GroupMessage(self, apiKey, prikey, message=None, key=None):
        #everything for variable use
        loginserverRecord = self.LoginServerRecord(apiKey)
        str_pass = str("ikea")
        byte = bytes(str_pass, encoding='utf-8')
        key_password = str_pass*16
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        hashed = nacl.hash.sha256(key, encoder=nacl.encoding.HexEncoder)
        groupkey_hash = hashed.decode('utf-8')
        group_message = "yo guys"
        box = nacl.secret.SecretBox(key)
        jsonString = json.dumps(group_message)
        #jsonString = json.dumps(message)
        jsonBytes = bytes(jsonString, encoding='utf-8')
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(jsonBytes, nonce, encoder=nacl.encoding.Base64Encoder)
        group_message = encrypted.decode('utf-8')
        sender_createdat = str(time.time())

        signature = bytes(loginserverRecord + group_message + sender_createdat, encoding='utf-8')
        signed = prikey.sign(signature, encoder=nacl.encoding.HexEncoder)
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        payload = {
            'loginserver_record' : loginserverRecord,
            'groupkey_hash' : groupkey_hash,
            'group_message' : group_message,
            'sender_created_at' : sender_createdat,
            'signature' : signed.signature.decode('utf-8')
        }
        payload_str = json.dumps(payload)
        json_payload = payload_str.encode("utf-8")

        user = self.listUsers(apiKey)
        for i in range(len(user["users"])):
            if(user["users"][i]["connection_location"] == 1):
                url = "http://" + user["users"][i]["connection_address"] + "/api/rx_groupmessage"
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    def decryptingGroupMessage(self, enc_data, password):
        str_pass = str("ikea")
        byte = bytes(str_pass, encoding='utf-8')
        key_password = str_pass*16
        enc_data = "gzMJdwvdDpDsK7y7OMx+o56+raSFDTedxxth0G7GHN5DDVndK/O8NzHGzrRzPZ0Q12I="
        salt = bytes(key_password.encode('utf-8')[:16])
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        key = nacl.pwhash.argon2i.kdf(32,byte,salt,ops,mem)
        box = nacl.secret.SecretBox(key)
        plaintext = box.decrypt(str(enc_data), encoder=nacl.encoding.Base64Encoder)
        data = plaintext.decode('utf-8')
    


    def CheckPubkey(self, apikey, pubkey):
        headers = {
            'X-username' : self.username,
            'X-apikey' : apikey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        url = "http://cs302.kiwi.land/api/check_pubkey?pubkey=" + pubkey
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object

    def CheckMessages(self,apiKey, pubkey):
        last_report_time = self.CheckPubkey(apiKey, pubkey)["connection_updated_at"]
        user = self.listUsers(apiKey)
        for i in range(len(user["users"])):
            url = "http://10.104.131.208:10050/api/checkmessages?since=" + last_report_time
        
        headers = {
            'X-username' : self.username,
            'X-apikey' : apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print("ERROR")
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print("#######################")
        print(JSON_object)
        print("$#######################")
        return JSON_object
        
