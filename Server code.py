import socket
import os
import threading
import sqlite3
from threading import Lock
from datetime import datetime
import pytz

online_users_lock = Lock()
online_users = {}





def set_keepalive(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if os.name == 'posix':
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
    elif os.name == 'nt':
        
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec*1000, interval_sec*1000))



file_metadata = {}



def add_online_user(username, connection):
    with online_users_lock:
        online_users[username] = connection

def remove_online_user(username):
    with online_users_lock:
        if username in online_users:
            del online_users[username]

def get_online_user(username):
    with online_users_lock:
        return online_users.get(username)
    
def format_message_with_timestamp(username, message):
    beirut_tz = pytz.timezone('Asia/Beirut')
    timestamp = datetime.now(beirut_tz).strftime('%Y-%m-%d %H:%M:%S')
    return f"[{timestamp}] {username}: {message}"
    



def db_connection():
    return sqlite3.connect('yallachat.db', check_same_thread=False)

def setup_database():
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        
        cursor.execute('''
          CREATE TABLE IF NOT EXISTS friendships (
              user1 TEXT NOT NULL,
              user2 TEXT NOT NULL
          )
          ''')
          
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friend_requests (
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                UNIQUE(from_user, to_user)
            )''')
            
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            delivered INTEGER DEFAULT 0
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            UNIQUE(group_id, username)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            delivered INTEGER DEFAULT 0,
            FOREIGN KEY (group_id) REFERENCES groups(id)
            )
    ''')
                        

        conn.commit()

setup_database()

def deliver_undelivered_messages(cursor, username, connection):
    cursor.execute("SELECT sender, message, timestamp FROM messages WHERE receiver = ? AND delivered = 0", (username,))
    undelivered_messages = cursor.fetchall()

    if undelivered_messages:
        formatted_messages = "\n".join([format_message_with_timestamp(msg[0], msg[1]) for msg in undelivered_messages])
        connection.send(formatted_messages.encode("utf-8"))

        
        cursor.execute("UPDATE messages SET delivered = 1 WHERE receiver = ?", (username,))
        cursor.connection.commit()


import uuid 

def handle_file_transfer(connection, args):
    global file_metadata  
    
    
    if not os.path.exists("files"):
        os.makedirs("files")  
    
    try:
        if isinstance(args, list):
            args = ' '.join(args)  

        recipient, filename, filesize = args.split()
        filesize = int(filesize)
        unique_id = str(uuid.uuid4())  
        storage_path = f"files/{unique_id}_{filename}"  

        with open(storage_path, "wb") as f:
            remaining = filesize
            while remaining > 0:
                chunk = connection.recv(min(1024, remaining))
                if not chunk:
                    connection.send("TRANSFER_FAILED".encode())
                    return
                f.write(chunk)  
                remaining -= len(chunk)

        
        file_metadata[unique_id] = {
            "sender": None,  
            "recipient": recipient,
            "filename": filename,
            "storage_path": storage_path,
            "timestamp": datetime.now(pytz.timezone("Asia/Beirut"))
        }

    
        recipient_socket = get_online_user(recipient)
        if recipient_socket:
            recipient_socket.send(f"file_available {unique_id} {filename}".encode())
        
        connection.send("TRANSFER_SUCCESS".encode())  
    except Exception as e:
        print(f"Error during file transfer: {str(e)}")
        connection.send(f"TRANSFER_FAILED: {str(e)}".encode())




def fetch_file(connection, unique_id):
    global file_metadata  

    if unique_id not in file_metadata:
        connection.send("FILE_NOT_FOUND".encode())
        return

    metadata = file_metadata[unique_id]
    storage_path = metadata["storage_path"]  

    try:
        with open(storage_path, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                connection.send(chunk)  
    except Exception as e:
        print(f"Error during file fetch: {str(e)}")
        connection.send("FETCH_FAILED".encode())





def transfer_file_data(source_socket, target_socket, filesize):
    remaining = filesize
    while remaining > 0:
        chunk = source_socket.recv(min(1024, remaining))
        if not chunk:
            print("Failed to receive all data.")
            return False
        target_socket.send(chunk)
        remaining -= len(chunk)
    return True



def receive_file(connection, expected_size):
    received_size = 0
    with open("received_file", "wb") as file:  
        while received_size < expected_size:
            data = connection.recv(1024)
            if not data:
                break  
            file.write(data)
            received_size += len(data)
    return received_size == expected_size  



serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
if os.name == 'nt':  
    serverSocket.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 3000))  

serverSocket.bind(('', 13000))
serverSocket.listen(50)
online_users = {}  


if not os.path.exists("files"):
    os.makedirs("files")  
    
print('The server is ready to receive')

def client_thread(connection, address):
    username = None
    try:
        with db_connection() as conn:
            cursor = conn.cursor()
            while True:
                data = connection.recv(1024).decode()
                command, *args = data.split(maxsplit=1)
                if not data:
                    break
                command, *args = data.split()
                
                if command == "signup":
                    name, email, address, usernm, password = args
                    try:
                        cursor.execute('INSERT INTO users (name, email, address, username, password) VALUES (?, ?, ?, ?, ?)', (name, email, address, usernm, password))
                        conn.commit()
                        username = usernm
                        add_online_user(username, connection)  
                        connection.send("Signup successful.".encode())
                    except sqlite3.IntegrityError:
                        connection.send("Username already exists.".encode())
                        
                elif command == "file":
                    if args and len(args) == 1:
                        args = args[0]  
                    handle_file_transfer(connection, args)
    
                elif command == "fetch_file":
                    unique_id = args[0]  
                    fetch_file(connection, unique_id)
                        
                elif command == "login":
                    usernm, password = args
                    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (usernm, password))
                    if cursor.fetchone():
                        username = usernm
                        add_online_user(username, connection) 
                        connection.send("Login successful\n".encode())
                      
                        
                    else:
                        connection.send("Invalid credentials. Try signing up or using correct info.".encode())
                        
                elif command == "send_friend_request":
                    friend_username = args[0]
                    if username:
                        cursor.execute('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', (username, friend_username, friend_username, username))
                        if cursor.fetchone():
                            connection.send("Already friends.".encode())
                        else:
                            cursor.execute('INSERT OR IGNORE INTO friend_requests (from_user, to_user) VALUES (?, ?)', (username, friend_username))
                            conn.commit()
                            connection.send("Friend request sent.".encode())
                    else:
                        connection.send("You must be logged in to send friend requests.".encode())

                elif command == "respond_friend_request":
                    friend_username, action = args
                    if username:
                        if action == "accept":
                            cursor.execute('DELETE FROM friend_requests WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)', (friend_username, username, username, friend_username))
                            conn.commit()
                            cursor.execute('INSERT INTO friendships (user1, user2) VALUES (?, ?)', (username, friend_username))
                            conn.commit()
                            connection.send("Friend request accepted.".encode())
                        elif action == "decline":
                            cursor.execute('DELETE FROM friend_requests WHERE from_user = ? AND to_user = ?', (friend_username, username))
                            conn.commit()
                            connection.send("Friend request declined.".encode())
                        else:
                            connection.send("Invalid action.".encode())
                    else:
                        connection.send("You must be logged in to respond to friend requests.".encode())

                elif command == "list_friend_requests":
                    if username:
                        cursor.execute('SELECT from_user FROM friend_requests WHERE to_user = ?', (username,))
                        pending_requests = cursor.fetchall()
                        if pending_requests:
                            requests_list = ", ".join([request[0] for request in pending_requests])
                            connection.send(f"Pending friend requests from: {requests_list}".encode())
                        else:
                            connection.send("No pending friend requests.".encode())
                    else:
                        connection.send("You must be logged in to view friend requests.".encode())

                elif command == "view_friends":
                    if username:
                        cursor.execute('SELECT user1 FROM friendships WHERE user2 = ? UNION SELECT user2 FROM friendships WHERE user1 = ?', (username, username))
                        friends = cursor.fetchall()
                        if friends:
                            friends_status = []
                            for friend in friends:
                                friend_username = friend[0]
                                friend_connection = get_online_user(friend_username)  
                                online_status = "online" if friend_connection else "offline"
                                friends_status.append(f"{friend_username} is {online_status}")
                            friends_status_str = "\n".join(friends_status)
                            connection.send(friends_status_str.encode())
                        else:
                            connection.send("You have no friends added.".encode())
                    else:
                        connection.send("You must be logged in to view friends.".encode())

                
                elif command == "chat":
                    receiver, message_content = args[0], ' '.join(args[1:])
                    formatted_message = f"{username}: {message_content}"
                    cursor.execute(
                        "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                        (username, receiver, message_content)
                    )
                    conn.commit()
                    
                    receiver_connection = get_online_user(receiver)  
                    if receiver_connection:  
                        receiver_connection.send(formatted_message.encode())
                            
                        
                elif command == "create_group":
                    group_name = args[0]  
                    try:
                        cursor.execute("INSERT INTO groups (name, created_by) VALUES (?, ?)", (group_name, username))
                        group_id = cursor.lastrowid  
                        cursor.execute("INSERT INTO group_members (group_id, username) VALUES (?, ?)", (group_id, username))
                        conn.commit()
                        connection.send(f"Group '{group_name}' created successfully.".encode())
                    except Exception as e:
                        connection.send(f"Error creating group: {str(e)}".encode())

                
                elif command == "list_groups":
                    cursor.execute(
                        "SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?",
                        (username,),
                    )
                    groups = cursor.fetchall()
                    if groups:
                        groups_list = "\n".join([f"{group[0]}: {group[1]}" for group in groups])
                        connection.send(groups_list.encode())
                    else:
                        connection.send("You are not in any groups.".encode())

                
                elif command == "add_to_group":
                    group_id, member_username = args[0], args[1]
                    try:
                        cursor.execute("INSERT INTO group_members (group_id, username) VALUES (?, ?)", (group_id, member_username))
                        conn.commit()
                        connection.send("Member added to group successfully.".encode())
                    except Exception as e:
                        connection.send(f"Error adding member to group: {str(e)}".encode())

                
                elif command == "send_group_message":
                    group_id, message_content = args[0], args[1]
                    formatted_message = format_message_with_timestamp(username, message_content)
                    try:
                        
                        cursor.execute(
                            "INSERT INTO group_messages (group_id, sender, message) VALUES (?, ?, ?)",
                            (group_id, username, message_content),
                        )
                        conn.commit()

                       
                        cursor.execute("SELECT username FROM group_members WHERE group_id = ?", (group_id,))
                        members = cursor.fetchall()
                        for member in members:
                            member_username = member[0]
                            if member_username != username:  
                                member_socket = get_online_user(member_username)  
                                if member_socket: 
                                    member_socket.send(formatted_message.encode())

                        connection.send("Message sent to group.".encode())
                    except Exception as e:
                        connection.send(f"Error sending group message: {str(e)}".encode())

                
                elif command == "fetch_group_chat_history":
                    group_id = args[0]
                    cursor.execute("SELECT sender, message, timestamp FROM group_messages WHERE group_id = ? ORDER BY timestamp ASC", (group_id,))
                    group_messages = cursor.fetchall()

                    formatted_messages = "\n".join(
                        [f"[{msg[2]}] {msg[0]}: {msg[1]}" for msg in group_messages]
                    )
                    connection.send(formatted_messages.encode())
                           
                                
                elif command == "fetch_undelivered_messages":
                    deliver_undelivered_messages(cursor, username, connection)  
                elif command == "logout":
                    if username:
                        remove_online_user(username)  
                    connection.send("Logout successful.".encode())  
                 
            
                    
                elif command == "search_usernames":
                    search_query = args[0]
                    cursor.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{search_query}%",))
                    results = cursor.fetchall()
                    if results:
                        usernames = " ".join([result[0] for result in results])
                        connection.send(usernames.encode("utf-8"))
                    else:
                        connection.send("No matching usernames found.".encode("utf-8"))


                
                elif command == "send_group_message":
                        group_id, message_content = args[0], ' '.join(args[1:])
                        formatted_message = format_message_with_timestamp(username, message_content)
                        try:
                            cursor.execute('SELECT username FROM group_members WHERE group_id = ?', (group_id,))
                            members = cursor.fetchall()
                            for member in members:
                                member_username = member[0]
                                if member_username != username:  
                                    friend_connection = get_online_user(member_username)
                                    if friend_connection:
                                        friend_connection.send(formatted_message.encode())
                            
                            cursor.execute('INSERT INTO group_messages (group_id, sender, message, delivered) VALUES (?, ?, ?, 1)', (group_id, username, message_content))
                            conn.commit()
                            connection.send("Message sent to group.".encode())
                        except Exception as e:
                            connection.send(f"Error sending group message: {str(e)}".encode())

                elif command == "fetch_chat_history":
                    partner_username = args[0]
                    cursor.execute(
                        "SELECT sender, message, timestamp FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timestamp ASC",
                        (username, partner_username, partner_username, username)
                    )
                    chat_history = cursor.fetchall()
                
                    formatted_messages = "\n".join([f"[{msg[2]}] {msg[0]}: {msg[1]}" for msg in chat_history])
                    connection.send(formatted_messages.encode("utf-8"))



                    
                    
                elif command == "fetch_group_chat_history":
                    group_id = args[0]
                    cursor.execute('SELECT sender, message, timestamp FROM group_messages WHERE group_id = ? ORDER BY timestamp ASC', (group_id,))
                    messages = cursor.fetchall()
                    formatted_messages = "\n".join([format_message_with_timestamp(msg[0], msg[1]) for msg in messages])
                    connection.send(formatted_messages.encode())

            

                elif command == "file":
                    handle_file_transfer(connection, args[0].split())
                    
                    
    except Exception as e:
        print(f"Exception occurred: {e}")
    
                
    finally:
        if username:
            remove_online_user(username)  
        connection.close()
        print(f"{username} has disconnected.")


while True:
    connectionSocket, addr = serverSocket.accept()
    
    
    set_keepalive(connectionSocket)
    
    
    threading.Thread(target=client_thread, args=(connectionSocket, addr)).start() 
