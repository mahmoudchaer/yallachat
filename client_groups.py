# Standard library imports
import socket
import sys
import threading
from datetime import datetime
import pytz

import os
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QPushButton, QMessageBox, QLabel
from PyQt5.QtGui import QFont, QPainter, QColor, QLinearGradient
from PyQt5.QtCore import Qt, QRect
import re

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QListWidget, QListWidgetItem, QSplitter
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# PyQt5 imports for core functionality
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor

# PyQt5 imports for widgets
from PyQt5.QtWidgets import QApplication, QDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget, QInputDialog
from PyQt5.QtWidgets import QFileDialog

import socket
import os

def set_keepalive(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if os.name == 'posix':
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
    elif os.name == 'nt':
       
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec*1000, interval_sec*1000))



class GradientWidget(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor("#8E2DE2"))  # Example gradient color 1
        gradient.setColorAt(1.0, QColor("#4A00E0"))  # Example gradient color 2
        painter.fillRect(QRect(0, 0, self.width(), self.height()), gradient)





class GroupListenerThread(QThread):
    messageReceived = pyqtSignal(str)

    def __init__(self, clientSocket, stopEvent, group_id):
        super().__init__()
        self.clientSocket = clientSocket
        self.stopEvent = stopEvent
        self.group_id = group_id

    def run(self):
        self.clientSocket.settimeout(1)  
        while not self.stopEvent.is_set():
            try:
                data = self.clientSocket.recv(1024).decode('utf-8')
                if data:
                    recv_group_id, sender, message = data.split(':', 2)
                    if recv_group_id == self.group_id:
                        self.messageReceived.emit(f"{sender}: {message}")
            except socket.timeout:
                continue
            except ValueError:
                print("Error receiving message: not enough values to unpack")
                continue
            except Exception as e:
                print(f"Error receiving message: {e}")
                break
   


from PyQt5.QtCore import QThread, pyqtSignal
import socket

class ListenerThread(QThread):
    messageReceived = pyqtSignal(str)

    def __init__(self, clientSocket, stopEvent):
        super().__init__()
        self.clientSocket = clientSocket
        self.stopEvent = stopEvent

    def run(self):
        while not self.stopEvent.is_set():
            try:
                data = self.clientSocket.recv(1024).decode("utf-8")
                if data:
                    self.messageReceived.emit(data)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving message: {e}")
                break



from PyQt5.QtCore import QThread, pyqtSignal

class FileTransferThread(QThread):
    transferComplete = pyqtSignal(str)
    transferError = pyqtSignal(str)
    transferProgress = pyqtSignal(int)

    def __init__(self, socket, file_path, recipient, parent=None):
        super(FileTransferThread, self).__init__(parent)  
        self.socket = socket
        self.file_path = file_path
        self.recipient = recipient

    def run(self):
        try:
            with open(self.file_path, "rb") as file:
                total_size = os.path.getsize(self.file_path)
                self.socket.send(f"file {self.recipient} {os.path.basename(self.file_path)} {total_size}".encode())
                
                total_sent = 0
                while True:
                    chunk = file.read(1024)
                    if not chunk:
                        break
                    self.socket.sendall(chunk)
                    total_sent += len(chunk)
                    self.transferProgress.emit((total_sent / total_size) * 100)  # Emit progress as a percentage

               
                confirmation = self.socket.recv(1024).decode()
                if confirmation == "RECEIVED":
                    self.transferComplete.emit("File transfer complete.")
                else:
                    self.transferError.emit("Error in file transfer confirmation.")
        except Exception as e:
            self.transferError.emit(f"File transfer failed: {str(e)}")





            
            
class FetchUndeliveredMessagesThread(QThread):
    fetched = pyqtSignal(str)  

    def __init__(self, clientSocket):
        super().__init__()
        self.clientSocket = clientSocket

    def run(self):
        self.clientSocket.settimeout(1)  
        try:
           
            self.clientSocket.send("fetch_undelivered_messages".encode())
            messages_response = self.clientSocket.recv(4096).decode() 
            self.fetched.emit(messages_response) 
        except Exception as e:
            print(f"Error fetching undelivered messages: {e}")
            self.fetched.emit("") 


def send_to_server(clientSocket, message):
    try:
        clientSocket.send(message.encode())
        response = clientSocket.recv(1024).decode()
        return response
    except Exception as e:
        return f"Error communicating with the server: {e}"


from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel
from PyQt5.QtGui import QPainter, QColor, QLinearGradient, QFont
from PyQt5.QtCore import Qt, QRect


class PreLoginWindow(GradientWidget): 
    def __init__(self, clientSocket):
        super().__init__()
        self.clientSocket = clientSocket
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('YALLA CHAT - Welcome')
        self.setGeometry(300, 300, 400, 200) 
        
        self.setStyleSheet("""
            QLabel#title {
                font-size: 20px;
                color: #FFFFFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QPushButton {
                font-size: 16px;
                border: none;
                border-radius: 20px;
                padding: 10px 20px;
                color: white;
                background-color: #4CAF50;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #81C784;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
        """)
        
        layout = QVBoxLayout()
        
        self.label = QLabel('Welcome to YALLA CHAT!', self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setObjectName('title')
        layout.addWidget(self.label)
        
        self.btnLogin = QPushButton('Log In', self)
        self.btnLogin.clicked.connect(self.on_login_clicked)
        layout.addWidget(self.btnLogin)
        
        self.btnSignup = QPushButton('Sign Up', self)
        self.btnSignup.clicked.connect(self.on_signup_clicked)
        layout.addWidget(self.btnSignup)
        
        self.setLayout(layout)
        
    def on_login_clicked(self):
        self.loginWindow = LoginWindow(self.clientSocket)
        self.loginWindow.show()

    def on_signup_clicked(self):
        self.signupWindow = SignupWindow(self.clientSocket)
        self.signupWindow.show()


class SignupWindow(GradientWidget):
    def __init__(self, clientSocket=None):
        super().__init__()
        self.clientSocket = clientSocket
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('Sign Up')
        self.setGeometry(300, 300, 350, 500) 
        self.setStyleSheet("""
            QLineEdit {
                border: 1px solid #DDD;
                border-radius: 20px;
                padding: 12px;
                background-color: #FFF;
                margin-bottom: 10px;
            }
            QPushButton {
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin-bottom: 10px;
            }
            QPushButton#socialButton {
                background-color: #FFF;
                color: #555;
            }
            QLabel#title {
                font-size: 24px;
                color: #FFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QLabel, QPushButton {
                font-size: 16px;
            }
        """)
        
        layout = QVBoxLayout()
        
        title = QLabel('Sign Up', self)
        title.setAlignment(Qt.AlignCenter)
        title.setObjectName('title')
        layout.addWidget(title)
        
        self.name = QLineEdit(self)
        self.name.setPlaceholderText('Full Name')
        layout.addWidget(self.name)
        
        self.email = QLineEdit(self)
        self.email.setPlaceholderText('Email Address')
        layout.addWidget(self.email)
        
        self.address = QLineEdit(self)  
        self.address.setPlaceholderText('Address')
        layout.addWidget(self.address)
        
        self.username = QLineEdit(self)
        self.username.setPlaceholderText('Username')
        layout.addWidget(self.username)
        
        self.password = QLineEdit(self)
        self.password.setPlaceholderText('Password')
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)
        
        self.signupBtn = QPushButton('Sign Up', self)
        self.signupBtn.clicked.connect(self.on_signup_clicked)
        layout.addWidget(self.signupBtn)
        
        
        self.setLayout(layout)

    def on_signup_clicked(self):
        # Get signup information
        signup_info = {
            "name": self.name.text(),
            "email": self.email.text(),
            "address": self.address.text(),
            "username": self.username.text(),
            "password": self.password.text(),
        }
        
      
        if not self.validate_email(signup_info["email"]):
            QMessageBox.warning(self, "Invalid Email", "The email address format is invalid. Please enter a valid email.")
            return  
    
        if not self.validate_password(signup_info["password"]):
            QMessageBox.warning(self, "Weak Password", "Password must be at least 8 characters, contain an uppercase letter, a lowercase letter, and a special character.")
            return  
    
      
        try:
           
            self.clientSocket.send(f"signup {' '.join(signup_info.values())}".encode())
            response = self.clientSocket.recv(1024).decode()
            
            # Display response to the user
            QMessageBox.information(self, "Signup Status", response)
            
           
            if "Signup successful" in response:
                self.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to communicate with the server: {e}")
    
 
    def validate_email(self, email):
        """ Validate the email format. """
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
    
    def validate_password(self, password):
        """ Ensure password meets criteria. """
        return (
            len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
        )

                
class LoginWindow(GradientWidget):
    def __init__(self, clientSocket):
        super().__init__()
        self.clientSocket = clientSocket
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Login')
        self.setGeometry(300, 300, 350, 250)  
        self.setStyleSheet("""
            QLineEdit {
                border: 1px solid #DDD;
                border-radius: 20px;
                padding: 12px;
                background-color: #FFF;
                margin-bottom: 10px;
            }
            QPushButton {
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin-bottom: 10px;
            }
            QLabel#title {
                font-size: 24px;
                color: #FFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QLabel, QPushButton {
                font-size: 16px;
            }
        """)

        layout = QVBoxLayout()

        self.username = QLineEdit(self)
        self.username.setPlaceholderText('Username')
        layout.addWidget(self.username)

        self.password = QLineEdit(self)
        self.password.setPlaceholderText('Password')
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        self.loginBtn = QPushButton('Log In', self)
        self.loginBtn.clicked.connect(self.on_login_clicked)
        layout.addWidget(self.loginBtn)

        self.setLayout(layout)
        

    def on_login_clicked(self):
        username_text = self.username.text()
        password_text = self.password.text()
        try:
            self.clientSocket.send(f"login {username_text} {password_text}".encode())
            login_response = self.clientSocket.recv(1024).decode()

            if "Login successful" in login_response:
                
                self.fetchThread = FetchUndeliveredMessagesThread(self.clientSocket)
                self.fetchThread.fetched.connect(self.display_undelivered_messages)
                self.fetchThread.start()

              
                self.close()
                self.postLoginWindow = PostLoginWindow(self.clientSocket, username_text)  # SHOW POSTLOGIN WINDOW NOW
                self.postLoginWindow.show()
            else:
                QMessageBox.warning(self, "Login Failed", login_response)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to communicate with the server: {e}")
    
    
    def display_undelivered_messages(self, messages):
        msgBox = QMessageBox()
        msgBox.setWindowTitle("While you were offline")
    
        if messages.strip(): 
            msgBox.setText("You have received messages while offline:")
            msgBox.setDetailedText(messages) 
        else:
            msgBox.setText("No messages received.")
    
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.exec_()


            
            
class PostLoginWindow(GradientWidget):
    def __init__(self, clientSocket, username):
        super().__init__()
        self.clientSocket = clientSocket
        self.username = username
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ChatApp - Main Menu')
        self.setGeometry(300, 300, 500, 300)
        self.setStyleSheet("""
            QLabel#title {
                font-size: 20px;
                color: #FFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QLabel {
                font-size: 16px;
                color: #FFF;
            }
            QPushButton {
                font-size: 16px;
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #81C784;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
        """)
        
        layout = QVBoxLayout()
        
        self.usernameLabel = QLabel(f"Logged in as: {self.username}", self)
        self.usernameLabel.setAlignment(Qt.AlignCenter)
        self.usernameLabel.setObjectName('title')
        layout.addWidget(self.usernameLabel)
        
        # The rest of your buttons and layout setup
        self.btnViewFriends = QPushButton('View Friends & Status', self)
        self.btnViewFriends.clicked.connect(self.view_friends)
        layout.addWidget(self.btnViewFriends)
        
        self.btnFriendRequests = QPushButton('View Friend Requests', self)
        self.btnFriendRequests.clicked.connect(self.view_friend_requests)
        layout.addWidget(self.btnFriendRequests)

        self.btnSendFriendRequest = QPushButton('Send Friend Request', self)
        self.btnSendFriendRequest.clicked.connect(self.send_friend_request)
        layout.addWidget(self.btnSendFriendRequest)
        
        self.btnStartChat = QPushButton('Start Chat/Send Message', self)
        self.btnStartChat.clicked.connect(self.start_chat)
        layout.addWidget(self.btnStartChat)

        self.btnExit = QPushButton('Exit', self)
        self.btnExit.clicked.connect(self.exit_app)
        layout.addWidget(self.btnExit)
        
        self.btnGroups = QPushButton('Groups', self)
        self.btnGroups.clicked.connect(self.open_groups_window)
        layout.addWidget(self.btnGroups)

        self.setLayout(layout)


    def view_friend_requests(self):
        self.friendRequestsListWindow = FriendRequestsListWindow(self.clientSocket)
        self.friendRequestsListWindow.show()

    def view_friends(self):
        self.friendsListWindow = FriendsListWindow(self.clientSocket)
        self.friendsListWindow.show()

    # Inside PostLoginWindow
    def send_friend_request(self):
        friend_username, okPressed = QInputDialog.getText(self, "Send Friend Request","Friend's username:", QLineEdit.Normal, "")
        if okPressed and friend_username != '':
            response = send_to_server(self.clientSocket, f"send_friend_request {friend_username}")
            QMessageBox.information(self, "Server Response", response)


    def start_chat(self):
        self.chatWindow = ChatWindow(self.clientSocket, self.username)
        self.chatWindow.show()



    def exit_app(self):
       
        try:
            self.clientSocket.send("logout".encode())
         
            response = self.clientSocket.recv(1024).decode()
            print(f"Server response to logout: {response}")  
        except Exception as e:
            print(f"Error sending logout command: {e}")
        
        self.close()
        
    def open_groups_window(self):
        self.groupsWindow = GroupsWindow(self.clientSocket, self.username)
        self.groupsWindow.show()

class FriendRequestsListWindow(GradientWidget):
    def __init__(self, clientSocket):
        super().__init__()
        self.clientSocket = clientSocket
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Friend Requests')
        self.setGeometry(300, 300, 400, 300) 
        
        self.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #81C784;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
            QListWidget {
                border-radius: 15px;
                border: 1px solid #CCC;
                background-color: white;
                padding: 5px;
            }
        """)

        layout = QVBoxLayout()

        self.listWidget = QListWidget(self)
        layout.addWidget(self.listWidget)
        
        self.refreshButton = QPushButton('Refresh', self)
        self.refreshButton.clicked.connect(self.load_friend_requests)
        layout.addWidget(self.refreshButton)
        
        self.acceptButton = QPushButton('Accept', self)
        self.acceptButton.clicked.connect(lambda: self.respond_to_request("accept"))
        layout.addWidget(self.acceptButton)
        
        self.declineButton = QPushButton('Decline', self)
        self.declineButton.clicked.connect(lambda: self.respond_to_request("decline"))
        layout.addWidget(self.declineButton)
        
        self.setLayout(layout)
        self.load_friend_requests()
        
    def load_friend_requests(self):
        response = send_to_server(self.clientSocket, "list_friend_requests")
        self.listWidget.clear()
        if not response.startswith("No pending friend requests"):
            for request in response.split(", "):
                self.listWidget.addItem(request.replace("Pending friend requests from: ", ""))
    
    def respond_to_request(self, action):
        selectedItem = self.listWidget.currentItem()
        if selectedItem:
            selected_user = selectedItem.text()
            command = f"respond_friend_request {selected_user} {action}"
            response = send_to_server(self.clientSocket, command)
            QMessageBox.information(self, "Server Response", response)
            self.load_friend_requests()
            

class FriendsListWindow(GradientWidget):
    def __init__(self, clientSocket):
        super().__init__()
        self.clientSocket = clientSocket
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Friends List')
        self.setGeometry(300, 300, 400, 300) 
        
        self.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: #81C784;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
            QListWidget {
                border-radius: 15px;
                border: 1px solid #CCC;
                background-color: white;
                padding: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        self.listWidget = QListWidget(self)
        layout.addWidget(self.listWidget)
        
        self.refreshButton = QPushButton('Refresh', self)
        self.refreshButton.clicked.connect(self.load_friends)
        layout.addWidget(self.refreshButton)
        
        self.setLayout(layout)
        self.load_friends()
    
    def load_friends(self):
        response = send_to_server(self.clientSocket, "view_friends")
        self.listWidget.clear()
        if not response.startswith("You have no friends added."):
            for friend_info in response.split('\n'):
                username, status = friend_info.rsplit(' ', 1)  
                item = QListWidgetItem(f"{username} ({status})")
                if status == "online":
                    item.setForeground(Qt.green)  
                else:
                    item.setForeground(Qt.red) 
                self.listWidget.addItem(item)


class ChatWindow(QWidget):
    def __init__(self, clientSocket, username):
        super().__init__()
        self.clientSocket = clientSocket
        self.username = username
        self.current_chat_with = None
        self.stop_listening = threading.Event()  
        self.listenerThread = ListenerThread(self.clientSocket, self.stop_listening)  
        self.listenerThread.messageReceived.connect(self.on_message_received)  
        self.initUI()  
        self.listenerThread.start()  

    def initUI(self):
        self.setWindowTitle("Chat Window")
        self.setGeometry(300, 300, 800, 600)  

        mainLayout = QVBoxLayout() 
        splitter = QSplitter(Qt.Horizontal) 

        # Search section for usernames
        searchLayout = QVBoxLayout()
        self.usernameSearch = QLineEdit()
        self.usernameSearch.setPlaceholderText("Search for a username")
        searchLayout.addWidget(self.usernameSearch)

        self.searchButton = QPushButton("Search")
        self.searchButton.clicked.connect(self.search_usernames)  
        searchLayout.addWidget(self.searchButton)

        self.userListWidget = QListWidget()
        self.userListWidget.itemClicked.connect(self.on_user_selected)  
        searchLayout.addWidget(self.userListWidget)

        
        searchWidget = QWidget()
        searchWidget.setLayout(searchLayout)
        splitter.addWidget(searchWidget)

       
        chatLayout = QVBoxLayout()
        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)  
        chatLayout.addWidget(self.chatDisplay)

        self.messageInput = QLineEdit()  
        chatLayout.addWidget(self.messageInput)

        self.sendButton = QPushButton("Send")
        self.sendButton.clicked.connect(self.send_message)  
        chatLayout.addWidget(self.sendButton)
        
        self.sendFileButton = QPushButton("Send File")
        self.sendFileButton.clicked.connect(self.send_file)
        chatLayout.addWidget(self.sendFileButton)


        chatWidget = QWidget()
        chatWidget.setLayout(chatLayout)
        splitter.addWidget(chatWidget)

        
        mainLayout.addWidget(splitter)
        self.setLayout(mainLayout)

    def search_usernames(self):
        search_query = self.usernameSearch.text()
        if search_query:
            self.clientSocket.send(f"search_usernames {search_query}".encode())
            response = self.clientSocket.recv(4096).decode()
            self.userListWidget.clear()  

            usernames = response.strip().split()
            if usernames:
                for username in usernames:
                    self.userListWidget.addItem(username) 
            else:
                self.userListWidget.addItem("No matching usernames found.")

    def on_user_selected(self, item):
       
        self.current_chat_with = item.text()
        self.chatDisplay.clear()  
        self.load_chat_history()  

    def send_message(self):
        message_content = self.messageInput.text()
        if message_content and self.current_chat_with:
            formatted_message = f"{self.username}: {message_content}"
            self.clientSocket.send(f"chat {self.current_chat_with} {message_content}".encode())  # Send the message
            self.display_message(formatted_message, sent=True)  
            self.save_to_history(formatted_message)
            self.messageInput.clear() 

    def on_message_received(self, message):
        self.display_message(message)  
        if self.current_chat_with:
            self.save_to_history(message)  

    def load_chat_history(self):
        if self.current_chat_with:
            self.clientSocket.send(f"fetch_chat_history {self.current_chat_with}".encode())  # Fetch chat history
            response = self.clientSocket.recv(4096).decode()  # Receive response
            self.chatDisplay.clear()  # Clear the chat display
            for line in response.split("\n"):
                if line.strip():  # Display each message
                    self.chatDisplay.append(line.strip())

    def display_message(self, message, sent=False):
        color = "blue" if sent else "green" 
        formatted_message = f'<div style="color: {color};">{message}</div>'
        self.chatDisplay.append(formatted_message)  

    def save_to_history(self, message):
        if self.current_chat_with:
            chat_history_filename = f"chat_history_{self.username}_{self.current_chat_with}.txt"  # File name
            with open(chat_history_filename, 'a') as file:
                file.write(f"{message}\n")  
                
                
    def send_file(self):
        file_dialog = QFileDialog(self)
        file_path = file_dialog.getOpenFileName(self, "Select File")[0]
        if file_path:
            self.fileTransferThread = FileTransferThread(self.clientSocket, file_path, self.username)
            self.fileTransferThread.transferComplete.connect(self.on_transfer_complete)
            self.fileTransferThread.transferError.connect(self.on_transfer_error)
            self.fileTransferThread.transferProgress.connect(self.update_transfer_progress)  # Connect progress signal
            self.fileTransferThread.start()

    def update_transfer_progress(self, progress):
      
        print(f"Transfer progress: {progress}%")

    def on_transfer_complete(self, message):
        QMessageBox.information(self, "Transfer Complete", message)

    def on_transfer_error(self, error_message):
        QMessageBox.critical(self, "Transfer Error", error_message)





    def closeEvent(self, event):
        self.stop_listening.set()  
        if self.listenerThread.isRunning():
            self.listenerThread.wait() 
        super().closeEvent(event) 





class GroupsWindow(QWidget):
    def __init__(self, clientSocket, username):
        super().__init__()
        self.clientSocket = clientSocket
        self.username = username
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Groups')
        self.setGeometry(300, 300, 400, 400)
        
        layout = QVBoxLayout()
        
        self.newGroupName = QLineEdit(self)
        self.newGroupName.setPlaceholderText('New Group Name')
        layout.addWidget(self.newGroupName)
        
        self.createGroupBtn = QPushButton('Create Group', self)
        self.createGroupBtn.clicked.connect(self.create_group)
        layout.addWidget(self.createGroupBtn)
        
        self.groupIdToAdd = QLineEdit(self)
        self.groupIdToAdd.setPlaceholderText('Group ID to add members')
        layout.addWidget(self.groupIdToAdd)
        
        self.memberUsernameToAdd = QLineEdit(self)
        self.memberUsernameToAdd.setPlaceholderText('Username to add to group')
        layout.addWidget(self.memberUsernameToAdd)
        
        self.addMemberBtn = QPushButton('Add Member to Group', self)
        self.addMemberBtn.clicked.connect(self.add_to_group)
        layout.addWidget(self.addMemberBtn)
        
        self.listGroupsBtn = QPushButton('List My Groups', self)
        self.listGroupsBtn.clicked.connect(self.list_groups)
        layout.addWidget(self.listGroupsBtn)
        
        self.groupsList = QListWidget(self)
        layout.addWidget(self.groupsList)
        self.groupsList.itemClicked.connect(self.select_group)
        
        self.setLayout(layout)
    
    def create_group(self):
        group_name = self.newGroupName.text()
        if group_name:
            response = send_to_server(self.clientSocket, f"create_group {group_name}")
            QMessageBox.information(self, "Server Response", response)
            self.newGroupName.clear()
    
    def add_to_group(self):
        group_id = self.groupIdToAdd.text()
        member_username = self.memberUsernameToAdd.text()
        if group_id and member_username:
            response = send_to_server(self.clientSocket, f"add_to_group {group_id} {member_username}")
            QMessageBox.information(self, "Server Response", response)
            self.groupIdToAdd.clear()
            self.memberUsernameToAdd.clear()
    
    def list_groups(self):
        self.groupsList.clear()
        response = send_to_server(self.clientSocket, "list_groups")
        if response.strip() != "You are not in any groups.":
            for group in response.split('\n'):
                self.groupsList.addItem(group)
        else:
            QMessageBox.information(self, "Groups", response)
    
    def select_group(self, item):
        group_id, group_name = item.text().split(":")[0].strip(), item.text().split(":")[1].strip()
        self.groupChatWindow = GroupChatWindow(self.clientSocket, self.username, group_id, group_name)
        self.groupChatWindow.show()
        
class GroupChatWindow(QWidget):
    def __init__(self, clientSocket, username, group_id, group_name):
         super().__init__()
         self.clientSocket = clientSocket
         self.username = username
         self.group_id = group_id
         self.group_name = group_name
         self.initUI()
         self.start_listening()
         self.fetch_and_display_group_chat_history()

    def fetch_and_display_group_chat_history(self):
        self.chatDisplay.clear()  
        send_to_server(self.clientSocket, f"fetch_group_chat_history {self.group_id}")

        
    def initUI(self):
        self.setWindowTitle(f'Group Chat - {self.group_name}')
        self.setGeometry(300, 300, 600, 400)
        
        layout = QVBoxLayout()
        
        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)
        layout.addWidget(self.chatDisplay)
        
        self.messageInput = QLineEdit()
        layout.addWidget(self.messageInput)
        
        self.sendButton = QPushButton("Send")
        self.sendButton.clicked.connect(self.send_message)
        layout.addWidget(self.sendButton)
        
       
        self.refreshButton = QPushButton("Refresh")
        self.refreshButton.clicked.connect(self.fetch_and_display_group_chat_history)
        layout.addWidget(self.refreshButton)
        
        self.setLayout(layout)
    
 

    def send_message(self):
        message_content = self.messageInput.text()
        if message_content:
         
            beirut_tz = pytz.timezone('Asia/Beirut')
            timestamp = datetime.now(beirut_tz).strftime('%Y-%m-%d %H:%M:%S')
            formatted_message_for_display = f"[{timestamp}] {self.username}: {message_content}"

          
            send_to_server(self.clientSocket, f"send_group_message {self.group_id} {message_content}")
            
           
            self.display_message(formatted_message_for_display)
            
            self.messageInput.clear()
    def start_listening(self):
        self.stopListening = threading.Event()
        self.listenerThread = ListenerThread(self.clientSocket, self.stopListening)  
        self.listenerThread.messageReceived.connect(self.on_message_received)  
        self.listenerThread.start()

    def display_message(self, message):
        self.chatDisplay.append(message)
        
    def closeEvent(self, event):
        self.stopListening.set()
        if self.listenerThread.isRunning():
            self.listenerThread.wait()
        super().closeEvent(event)
        
    def on_message_received(self, message):
         if message.startswith("history:"):
           
             history_messages = message[len("history:"):].split('\n')
             for msg in history_messages:
                 self.display_message(msg)
         else:
             
             self.display_message(message)







def main():
    app = QApplication(sys.argv)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    clientSocket.connect(('localhost', 13000))
    
    # Set keepalive options
    set_keepalive(clientSocket)
    
    window = PreLoginWindow(clientSocket)  # Accept and store the socket here 
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

# #
# The client code for your messaging application uses PyQt5 for the GUI and Python's socket and threading modules for networking and concurrent execution. Let's analyze the multithreading aspects and how chatting is handled.

# Multithreading in Client Code
# The client application utilizes multithreading in two significant ways to enhance user experience and application performance:

# ListenerThread: This thread listens for incoming messages from the server. It's initiated as soon as the user successfully logs in and continues to run in the background, listening for messages. When a message is received, it emits a signal (messageReceived) with the message content, which the GUI thread catches to update the chat display. 
#This approach allows the application to asynchronously receive messages, ensuring the GUI remains responsive.
# FetchUndeliveredMessagesThread: This thread is specifically used for fetching undelivered messages from the server. It's a one-time operation initiated right after a user logs in. The thread sends a request to the server to fetch undelivered messages, waits for the response, and then emits a signal (fetched) with the fetched messages. 
#The GUI thread catches this signal to display the messages to the user.
# Both threads are designed to not block the main GUI thread, ensuring that the application remains responsive to user interactions. They use the QThread class from PyQt5, which is a convenient way to manage threads in a PyQt application.