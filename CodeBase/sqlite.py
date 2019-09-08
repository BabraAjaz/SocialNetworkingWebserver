import sqlite3
from datetime import datetime
from html.parser import HTMLParser

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.strict = False
        self.convert_charrefs= True
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

def create(self):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    #c.execute("""create table broadcasts(username string not null, message string not null, time text not null)""")
    #c.execute("""create table users(username string not null unique, connection_address string not null, connection_location integer not null, pubkey string not null, time string not null, status string)""")
    #c.execute("""create table pm(owner string not null, sender string not null, encrypted_message string not null, time string not null)""")
    #c.execute("""create table messenger(owner string not null, friend string not null, sender string, receiver string, encrypted_message string not null, time string not null)""")
    conn.commit()
    conn.close()
    return 0

###########################
"""BROADCAST INTERACTION"""
###########################
def add(self, username, broadcast, time):

    broadcast = strip_tags(str(broadcast))
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute('''insert into broadcasts 
                (username, message, time) 
                values
                (?,?,?)''',(str(username), str(broadcast), str(time)))
    conn.commit()
    conn.close()
    return 0

def get(self):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(""" SELECT username, message, time from broadcasts""")
    rows = c.fetchall()
    conn.commit()
    conn.close()
    name = list()
    message = list()
    time = list()

    for fow in rows:
        name.append(fow[0])
        message.append(fow[1])
        time.append(fow[2])
    
    '''converting unix time to date and time
    num = 1559821690.73662
    num0 = int(num/1)
    print(datetime.utcfromtimestamp(num0).strftime('%Y-%m-%d %H:%M:%S'))
    '''
    for i in range(len(message)):
        message[i] = strip_tags(str(message[i]))

    messages = {
        'name' : name,
        'message' : message,
        'time' : time
    }
    return messages

def update(self):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""UPDATE broadcasts SET username = ? WHERE username = ?""", ("misl000","Baja156"))
    conn.commit()
    conn.close()


###################################
"""PRIVATE MESSAGING INTERACTION"""
###################################
def insertPM(self, owner, friend, sender, receiver, encrypted_message, time):
    #owner, friend, sender, receiver, message, time
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    owner = owner.lower()
    friend = friend.lower()
    sender = sender.lower()
    receiver = receiver.lower()
    sender = sender.replace('"',"")
    #username, target_username, encrypted_message, pubkey, time, to, from
    c.execute("""insert into messenger
            (owner, friend, sender, receiver, encrypted_message, time)
            values
            (?, ?, ?, ?, ?, ?)""",(str(owner), str(friend), str(sender), str(receiver), str(encrypted_message), str(time)))
    conn.commit()
    conn.close()
    return 0

def getPM(self, owner, friend):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    owner = owner.lower()
    c.execute(""" SELECT sender, receiver, encrypted_message, time from messenger WHERE owner = ? and friend = ?""", (owner,friend,))
    
    rows = c.fetchall()
    conn.commit()
    conn.close()
    sender = list()
    receiver = list()
    message = list()
    time = list()
    for fow in rows:
        sender.append(fow[0])
        receiver.append(fow[1])
        message.append(fow[2])
        time.append(fow[3])
    data = {
        'sender' : sender,
        'receiver' : receiver,
        'message' : message,
        'time' : time
    }
    return data


###########################
"""USERS INTERACTION"""
###########################
def online(self, username, address, location, pubkey, time, status):
    #username, address, location, pubkey, time, status
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    try:
        c.execute("""insert into users
            (username, connection_address, connection_location, pubkey, time, status)
            values
            (?, ?, ?, ?, ?, ?)""",(str(username), str(address), str(location), str(pubkey), str(time), str(status)))
    except:
        print("Already existed")
    conn.commit()
    conn.close()
    return 0

def getOnline(self):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    #username, connection_address, connection_location, pubkey, time, status
    c.execute(""" SELECT username, connection_address, connection_location, pubkey, time, status from users""")
    rows = c.fetchall()
    conn.commit()
    conn.close()
    username = list()
    address = list()
    location = list()
    pubkey = list()
    time = list()
    status = list()
    for fow in rows:
        username.append(fow[0])
        address.append(fow[1])
        
    data = {
        'name' : username,
        'address' : address
    }
    return data

def findOnline(self, username):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(""" SELECT pubkey from users WHERE username = ?""", (username,))
    rows = c.fetchall()
    conn.commit()
    conn.close()
    print(rows[0][0])
    return str(rows[0][0])

def updateUsers(self, username, address, location, pubkey, time, status):
    #(username, connection_address, connection_location, pubkey, time, status)
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""UPDATE users SET connection_address = ?, connection_location = ?, pubkey = ?, time = ?, status = ? WHERE username = ?""", (address, location, pubkey, time, status, username))
    conn.commit()
    conn.close()

##########################
"""""""""DELETION"""""""""
##########################
def delete(self):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""DELETE FROM users""")# WHERE username = ?""",("Baja156"))
    conn.commit()
    conn.close()

self=None
#self, username, address, location, pubkey, time, status
# username = "baja156"
# address = "123"
# location = "123"
# pubkey = "123"
# time = "123"
# status = "busy"
# updateUsers(self, username, address, location, pubkey, time, status)

#create(self)
#create(self)
#string = "Babra"
#string = string.replace('"','')
#print(string)
#create(self)
#add(self,"Baja156","HeyThere")
#delete(self)
#findOnline(self,"admin")




