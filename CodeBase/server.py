import cherrypy
import mainApi
import nacl.encoding
import nacl.signing
import json
import sqlite
import sqlite3
from datetime import datetime

startHTML = "<html><head><title>The Best Social Network</title><link rel='stylesheet' href='/static/example.css'/><meta http-equiv='refresh' content='35' /></head><body>"

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "<br/><H1>The Best Social Network </H1><br/>"
        try:
            Page += "<br/>"
            self.updateUsers()
            Page += "Hello " + cherrypy.session['username'] + "!<br/>" # user status doesn't mean anything if this isn't fixed
            Page += "<br/>"
            Page += "Session Key : " + cherrypy.session['pubkey']
            Page += "<br/> <H3>"
            Page += "!<a href = 'addNewPairs'> Generate </a> new key pairs (you will lose your message/broadcast history)!"
            Page += '<form action="post" method="post" enctype="multipart/form-data">'
            Page += '<br/>'
            Page += 'Tweet : <input style="height:70px";type="text" name="message"/>'
            Page += "<br/>"
            Page += '<input type="submit" value="Post"/></form>'
            Page += "<br/>"
            Page += "</H3>"
            Page += "Your default status is online </br>"
            Page += "Click here to change it </br>"
            Page += "<div class='dropdown'>"
            Page += "<button onclick='myFunction()'"
            Page += "class='dropbtn'>Status</button>"
            Page += "<div id='myDropdown' class='dropdown-content'>"
            Page += "<a href='/status?status=Online'>Online</a>"
            Page += "<a href='/status?status=Busy'>Busy</a>"
            Page += "<a href='/status?status=Away'>Away</a></div></div></br>"
            Page += "Click here to <a href='Broadcasts'>Check Broadcasts</a><br/>"
            Page += "<br/>"
            Page += "Click here to see who's "
            Page += "<a href='/list_users'> online and message them </a> them<br/></br>"
            Page += "Click here to <a href='/tx_groupmessage'>group message </a></br></br>"
            Page += "Click here to <a href='/api/checkmessages'>Check Messages</a><br/>"
            Page += "<br/>"
            Page += "Click here to view <a href='/friends'>Friends</a>.<br/>"
            Page += "<br/>"
            try:
                self.status(self,cherrypy.session['status'])
            except:
                pass
                print("no status yet")
            self.tx_ping_check()
            Page += "Click here to <a href='/ping'>Ping </a>the login server<br/>"
            Page += "<br/>"
            Page += "Click here to <a href='/tx_ping_check'>Ping_check</a> a client.<br/>"
            Page += "<br/>"
            Page += "Use this to be redirected to the "
            Page += "<a href='http://cs302.kiwi.land'> Login Server </a>"
            Page += "<H3><a href='signout'> Sign Out</a></H3><br/>"
            Page += "<br/>"
            Page += """<script>
                        function myFunction() {
                        document.getElementById("myDropdown").classList.toggle("show");
                        }
                        window.onclick = function(event) {
                            if (!event.target.matches('.dropbtn')) {
                                var dropdowns = document.getElementsByClassName("dropdown-content");
                                var i;
                                for (i = 0; i < dropdowns.length; i++) {
                                var openDropdown = dropdowns[i];
                                    if (openDropdown.classList.contains('show')) {
                                        openDropdown.classList.remove('show');
                                    }
                                }
                            }
                        }
                        </script> </br>"""
        except KeyError: #There is no username and session pubkey
            Page += "Click here to <a href='login'>Login</a>"
        return Page

    @cherrypy.expose
    def status(self, status=None):
        cherrypy.session['status'] = status
        print("############")
        print("online")
        if (status == "Online"):
            ApiApp.report(self,"online")
            cherrypy.session['status'] = status
            print("############")
            print("online")
            raise cherrypy.HTTPRedirect('/')
        elif (status == "Busy"):
            ApiApp.report(self,"busy")
            cherrypy.session['status'] = status
            print("############")
            print("busy")
            raise cherrypy.HTTPRedirect('/')
        elif (status == "Away"):
            ApiApp.report(self,"away")
            cherrypy.session['status'] = status
            print("############")
            print("away")
            raise cherrypy.HTTPRedirect('/')
        #raise cherrypy.HTTPRedirect('/')



    @cherrypy.expose
    def list_users(self):
        Page = startHTML + "<H1>Here are the online users:</H1><br/>"
        Page += "<H2> <a href='/index'> Home </a><br/>"
        try:
            testing = mainApi.mainApi(cherrypy.session['username'],cherrypy.session['password'])
            JSON_object = testing.listUsers(cherrypy.session['apiKey'])
            users_online = list()
            users_status = list()
            for i in range(len(JSON_object["users"])):
                sqlite.online(self, JSON_object["users"][i]["username"],JSON_object["users"][i]["connection_address"],JSON_object["users"][i]["connection_location"],JSON_object["users"][i]["incoming_pubkey"],JSON_object["users"][i]["connection_updated_at"],JSON_object["users"][i]["status"],)
                users_online.append(JSON_object["users"][i]["username"])
                users_status.append(JSON_object["users"][i]["status"])
            Page += "<H2> Users </br>"
            Page += " Click on the username to pm them"
            for i in range(len(users_online)):
                Page += "<H3><a href='/pm?user=" + users_online[i] + "'>" + users_online[i] + "</a> Status: "+ users_status[i] +"<br/><br/>"
        except KeyError:
            Page += "An error has occured<br/>"
            Page += "<H2> <a href='/index'> Home </a><br/>"
        return Page

    @cherrypy.expose
    def groupMessage(self):
        Page = startHTML + "<H1> Group Messaging </H1>"
        Page += "CLick here to make a new group</br>"
        Page += "Groups you are in: </br> CLick them to message the group"
        Page += "Groupppss"

    @cherrypy.expose
    def updateUsers(self):
        try:
            testing = mainApi.mainApi(cherrypy.session['username'],cherrypy.session['password'])
            JSON_object = testing.listUsers(cherrypy.session['apiKey'])
            users_online = list()
            for i in range(len(JSON_object["users"])):
                sqlite.updateUsers(self, JSON_object["users"][i]["username"],JSON_object["users"][i]["connection_address"],JSON_object["users"][i]["connection_location"],JSON_object["users"][i]["incoming_pubkey"],JSON_object["users"][i]["connection_updated_at"],JSON_object["users"][i]["status"],)
                users_online.append(JSON_object["users"][i]["username"])
        except:
            print("lol")

    @cherrypy.expose
    def pm(self, user="user"):
        cherrypy.session['targetUser'] = user
        Page = startHTML + "<H1> Private Message </H1><br/>"
        ApiApp.report(self,cherrypy.session['status'])
        Page += "<a href='/index'>Home</a></br></br>"
        Page += "Click on user's name to add them to friends list </br>"
        Page += "<H1><a href='follow'>" + user + "</a></H1> &nbsp;"
        Page += '<form action="/send" method="post" enctype="multipart/form-data">'
        Page += '<br/>'
        Page += 'Message : &nbsp <input style="height:50px"; type="text" name="pmessage"/>'
        Page += "&nbsp"
        Page += '<input type="submit" value="send"/></form>'
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        data = testing.decryptingPM(cherrypy.session['privateKey'],user)
        
        Page += "<div class='myBox'>"
        for i in range(len(data['message'])- 1, -1, -1):
            Page += data['message'][i] + "</br>"
            Page += "from &nbsp" + str(data['sender'][i]) + "&nbspat&nbsp" + str(data['time'][i]) + "</br>"
        Page += "</div>"
        # except KeyError:
        #     Page += "Something went wrong, please log in again </br>"
        #     Page += "<a href='/index'>Login</a>"
        return Page

    @cherrypy.expose
    def friends(self):
        Page = startHTML + "<H1> User Friends </H1>"
        try:
            testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
            ApiApp.report(self,cherrypy.session['status'])
            Page += "<a href='/index'>Home</a>"
            Page += "Click on friends name to block them </br>"
            response = testing.decriptPrivateData(cherrypy.session['apiKey'],cherrypy.session['key'])
            friends = response["friends_usernames"]
            for i in range(len(friends)):
                Page += "<H2><a href='/block?friend=" + friends[i] + "'>" + friends[i] + "</a></H2><br/>"
        except KeyError:
            Page += "Something went wrong, please log in again </br>"
            Page += "<a href='/index'>Login</a>"
        return Page

    @cherrypy.expose
    def block(self, friend=None):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.decriptPrivateData(cherrypy.session['apiKey'],cherrypy.session['key'])
        blocked = response["blocked_usernames"]
        friends = response["friends_usernames"]
        
        count = 0
        
        for i in range(len(blocked)):
            if (blocked[i] == friend):
                count = 1

        if (count == 0):
            blocked.append(friend)
            cherrypy.session['blocked'].append(friend)
            try:
                for i in range(len(friends)):
                    if (friends[i] == friend):
                        friends.remove(friend)
            except:
                print("done")
        
        response["blocked_usernames"] = blocked
        response["friends_usernames"] = friends
        response = testing.addPrivateData(cherrypy.session['apiKey'],cherrypy.session['privateKey'],cherrypy.session['key'],response)
        raise cherrypy.HTTPRedirect('/friends')
        return 0

    @cherrypy.expose
    def follow(self):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.decriptPrivateData(cherrypy.session['apiKey'],cherrypy.session['key'])
        friends = response["friends_usernames"]
        blocked = response["blocked_usernames"]

        count = 0

        for i in range(len(friends)):
            if(friends[i] == cherrypy.session['targetUser']):
                count = 1

        if (count == 0):
            friends.append(cherrypy.session['targetUser'])
            try:
                for i in range(len(blocked)):
                    if (blocked[i] == cherrypy.session['targetUser']):
                        blocked.remove(cherrypy.session['targetUser'])
            except:
                print("done")

        response["friends_usernames"] = friends
        response["blocked_usernames"] = blocked

        response = testing.addPrivateData(cherrypy.session['apiKey'],cherrypy.session['privateKey'],cherrypy.session['key'],response)
        raise cherrypy.HTTPRedirect('/pm?user=' + cherrypy.session['targetUser'])

    @cherrypy.expose
    def send(self, pmessage=None):
        self.tx_privateMessage(cherrypy.session['targetUser'], pmessage)
        raise cherrypy.HTTPRedirect('/pm?user=' + cherrypy.session['targetUser'])
        return 0

    @cherrypy.expose
    def ping(self):
        Page = startHTML
        try:
            testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
            response = testing.ping(cherrypy.session['apiKey'],cherrypy.session['pubkey'],cherrypy.session['privateKey'])
            response = str(response)
            Page += "<H1>Successful Ping</H1>"
            Page += "<H2>" + response + "</H2><br/>"
            Page += "<a href='/index'> Home </a>"
        except KeyError:
            Page += "Please Sign in"
            Page += "<br/>"
            Page += "<a href='/index'> Login </a>"
        return Page

    @cherrypy.expose
    def tx_privateMessage(self, target, message):
        testing = mainApi.mainApi(cherrypy.session['username'],cherrypy.session['password'])
        testing.privateMessage(message, target, cherrypy.session['apiKey'], cherrypy.session['privateKey'])
    
    @cherrypy.expose
    def check_messages(self):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.CheckMessages(cherrypy.session['apiKey'], cherrypy.session['pubkey'])
        return 0

    @cherrypy.expose
    def tx_groupmessage(self):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.createGroup(cherrypy.session['privateKey'], cherrypy.session['apiKey'])

    @cherrypy.expose
    def tx_ping_check(self):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.ping_check(cherrypy.session['apiKey'])
        print(response)

    @cherrypy.expose
    def Broadcasts(self, filter=None):
        Page = startHTML + "<H1> User Broadcasts </H1><br/>"
        try:
            ApiApp.report(self,cherrypy.session['status'])
            blocked = list()
            blocked = cherrypy.session['blocked']
            data = sqlite.get(self)
            Page += "<a href='/index'>Home</a></br>"
            Page += '<form action="/Broadcasts" method="post" enctype="multipart/form-data">'
            Page += '<br/>'
            Page += '<H2>Filter Posts by username : </H2><input style="height:50px"; type="text" name="filter"/>'
            Page += "&nbsp"
            Page += '<input type="submit" value="filter"/></form>'
            Page += "<a href='Broadcasts'> Go Back </a>" # maybe put this somewhere else
            Page += "<div class='myBox'>"
            for i in range(len(data["name"]) - 1, -1, -1):
                for j in range(len(blocked)):
                    count = 0
                    if (data["name"][i] == blocked[j]):
                        count = 1
                    
                    if (count == 0):
                        if (filter == None):
                            Page += data["name"][i]
                            Page += ":&nbsp"
                            Page += str(data["message"][i])
                            Page += "&nbspat&nbsp"
                            Page += data["time"][i]
                            Page += "</br>"
                        elif (filter != None):
                            if (data["name"][i] == filter):
                                Page += "</br>"
                                Page += data["name"][i]
                                Page += ":&nbsp"
                                Page += str(data["message"][i])
                                Page += "&nbspat&nbsp"
                                Page += data["time"][i]
                                Page += "</br>"

            Page += "</div>"
        except KeyError:
            Page += "Something went wrong, please log in again </br>"
            Page += "<a href='/index'>Login</a>"
        return Page

    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"
        try:
            Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
            Page += '<H1>Username: </H1> &nbsp;&nbsp;&nbsp;&nbsp;'
            Page += '&nbsp;&nbsp;&nbsp;&nbsp; <input style="height:50px"; type="text" name="username"/>'
            Page += "<br/>"
            Page += '<H1>Password: </H1> &nbsp;&nbsp;&nbsp;&nbsp;'
            Page += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input style="height:50px"; type="password" name="password"/>'
            Page += '<br/><br/><H1><input type="submit" value="Login"/></H1></form>'
        except KeyError:
            Page += "<font color='red'>Invalid username/password!<br/></font>"
            Page += "Click here to <a href='login'>retry</a>"
        return Page

    @cherrypy.expose
    def privateData(self):
        Page = startHTML
        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "<br/>"
            Page += "Please enter your unique password <br/>"
            Page += '<form action="/load" method="post" enctype="multipart/form-data">'
            Page += '<H1>Symmetric Key: <input style="height:50px"; type="password" name="key"/></H1><br/>'
            Page += '<H1><input type="submit" value="Load"/></H1></form>'
        except KeyError: #There is no username
            Page += "Click here to <a href='login'>Login</a>"
        return Page

    @cherrypy.expose
    def load(self, key=None):

        keys = self.get_privatedata(key)
        cherrypy.session['privateKey'] = keys[0]
        cherrypy.session['pubkey'] = keys[1]
        cherrypy.session['key'] = key
        self.keyGenerate()
        ApiApp.report(self,"online")
        cherrypy.session['status'] = "online"
        raise cherrypy.HTTPRedirect('/index')
        #self.check_messages()

        

    @cherrypy.expose
    def get_privatedata(self,key):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        if (testing != 0):
            keys = ["1","2"]
            response = testing.decriptPrivateData(cherrypy.session['apiKey'],key)
            cherrypy.session['blocked'] = response["blocked_usernames"]
            privatekey = nacl.signing.SigningKey(response["prikeys"][0],encoder=nacl.encoding.HexEncoder)
            publickey = privatekey.verify_key
            pubkey = publickey.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
            keys[0] = privatekey
            keys[1] = pubkey
            return keys
        else:
            return 0

    @cherrypy.expose
    def keyGenerate(self):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.addPubkey(cherrypy.session['apiKey'])
        if(response[0]["response"] == "ok"):
            cherrypy.session['current_prikey'] = response[1]
            cherrypy.session['current_pubkey'] = response[2]

    @cherrypy.expose
    def addNewPairs(self):
        cherrypy.session['privateKey'] = cherrypy.session['current_prikey']
        cherrypy.session['pubkey'] = cherrypy.session['current_pubkey']
        prikey = cherrypy.session['privateKey']
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        response = testing.decriptPrivateData(cherrypy.session['apiKey'],cherrypy.session['key'])
        private_key_hex = prikey.encode(encoder=nacl.encoding.HexEncoder)
        response['prikeys'][0] = prikey
        testing.addPrivateData(cherrypy.session['apiKey'],cherrypy.session['privateKey'],cherrypy.session['key'],response)
        raise cherrypy.HTTPRedirect('/index')

        #response = testing.addPrivateData(cherrypy.session['apiKey'],cherrypy.session['privateKey'],cherrypy.session['key'])


    @cherrypy.expose
    def tx_broadcast(self,message):
        testing = mainApi.mainApi(cherrypy.session['username'],cherrypy.session['password'])
        response = testing.Broadcast(cherrypy.session['apiKey'],cherrypy.session['privateKey'],message)
        json_acceptable_string = response.replace("'", "\"")
        d = json.loads(json_acceptable_string)
        return d["response"]

    @cherrypy.expose
    def post(self,message):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        Page = startHTML
        response = self.tx_broadcast(message)
        if (response == "ok"):
            Page += "Message sent successfully "
            Page += "<a href='/index'>Home</a>"
        else:
            Page += "noppe"
            Page += "<a href='/index'>Home</a>"
        return Page

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        try:
            error = authoriseUserLogin(username, password)
            if error == 0:
                cherrypy.session['username'] = username
                cherrypy.session['password'] = password
                raise cherrypy.HTTPRedirect('/privateData')
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        except KeyError:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            ApiApp.report(self,"offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

###
### Functions only after here
###
def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    try:
        testing = mainApi.mainApi(username,password)
        response = testing.newApiKey()
        #print("############")
        print(response)
        if(response["response"] == "ok"):
            print("############")
            print(response)
            cherrypy.session['apiKey'] = response["api_key"]
            print("Success")
            return 0
        else:
            print("faliure")
            return 1
    except KeyError:
        raise cherrypy.HTTPRedirect('/')

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
###########################################################################
===========================================================================
                            API APP CLASS
===========================================================================
###########################################################################
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

class ApiApp(object):
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }
    @cherrypy.expose
    def home(self):
        print("###################")
        raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def login(self):
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def report(self,status):
        testing = mainApi.mainApi(cherrypy.session['username'], cherrypy.session['password'])
        testing.Report(cherrypy.session['apiKey'],cherrypy.session['pubkey'],status)


#===========================================================================
#                           LISTENERS
#===========================================================================
    @cherrypy.expose
    def rx_groupmessage(self):
        received_Data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print(received_Data)

        response = {
            'response' : 'babra has received'
        }
        response = json.dumps(str(response))
        return (response)

    @cherrypy.expose
    def ping_check(self):
        data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print("3333333")
        print(data)
        print("##################")
        response = {
            'response' : 'not ok'
        }
        response = json.dumps(str(response))
        return response

    ##for other clients to call
    @cherrypy.expose
    def rx_broadcast(self):
        #username = json.dumps((str(cherrypy.request.body.headers.get('X-username'))))
        received_Data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        loginserver = received_Data["loginserver_record"]
        loginserver_r = list()
        loginserver_r = loginserver.split(',')
        username = loginserver_r[0]
        username = username.replace('"', '')
        broadcast = received_Data["message"]
        time = received_Data["sender_created_at"]
        sqlite.add(self, username, broadcast, time)
        response = {
            'response' : 'ok'
        }
        response = json.dumps(str(response))
        return (response)

    #for my client to talk to other client apps
    @cherrypy.expose
    def checkmessages(self, since):
        received_Data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        response = {
            'response' : 'not implemented brah',
            'broadcasts' : '[...]',
            'private_messages' : '[...]'
        }
        response = json.dumps(str(response))
        return (response)

    @cherrypy.expose
    def rx_groupinvite(self):
        received_Data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        response = {
            'response' : 'ITS AN OKAY FROM ME',
            'broadcasts' : '[...]',
            'private_messages' : '[...]'
        }
        response = json.dumps(str(response))
        return (response)

    @cherrypy.expose
    def rx_privatemessage(self):
        received_Data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        print(received_Data)
        loginserver = received_Data["loginserver_record"]
        loginserver_r = list()
        loginserver_r = loginserver.split(',')
        friend = loginserver_r[0]
        owner = received_Data['target_username']
        receiver = received_Data['target_username']
        sender = loginserver_r[0]
        message = received_Data['encrypted_message']
        time = received_Data['sender_created_at']
        try:
            sqlite.insertPM(self, owner, friend, sender, receiver, message, time)
        except:
            print("database")
        response = {
            'response' : 'BABRAOKAY'
        }
        response = json.dumps(str(response))
        return (response)




