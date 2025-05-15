import os
import re
import socket
import sys
import threading
from datetime import datetime
import pytz
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QRegularExpression, QRect, QThread, pyqtSignal
from PyQt5.QtGui import QPainter, QTextCharFormat, QColor, QLinearGradient, QTextCursor
from PyQt5.QtWidgets import QApplication, QHBoxLayout, QLabel, QSpacerItem, QSizePolicy, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget, QInputDialog, QFileDialog, QSplitter

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
        gradient.setColorAt(0.0, QColor("#8E2DE2"))
        gradient.setColorAt(1.0, QColor("#4A00E0"))
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
                    self.transferProgress.emit((total_sent / total_size) * 100)
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
        self.showMaximized()

    def initUI(self):
        self.setWindowTitle('Login')

        self.setStyleSheet("""
            QLineEdit {
                border: 1px solid #DDD;
                border-radius: 20px;
                padding: 20px;
                background-color: #FFF;
                margin-bottom: 25px;
                max-width: 250px;
            }
            QPushButton {
                border: none;
                border-radius: 20px;
                padding: 12px;
                background-color: #4CAF50;
                color: white;
                margin-bottom: 15px;
            }
            QLabel#title {
                font-size: 24px;
                color: #FFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QLabel#welcomeLabel {
                font-size: 24px;
                color: white;
                margin: 0;
            }
            QPushButton#signupBtn {
                font-size: 20px; /* Smaller font size */
                color: #1E90FF; /* Blue text color */
                text-decoration: underline;
                background: none; /* No background */
                border: none;
                margin-top: 10px;
            }
            QPushButton#loginBtn {
                font-size: 16px;
                color: white;
                border: 2px solid #4CAF50;
                background-color: #333;
                border-radius: 20px;
                padding: 10px 20px;
                margin-top: 20px;
            }
        """)

        mainLayout = QHBoxLayout()

        gradientPanel = GradientWidget()
        logo_label = QLabel(gradientPanel)
        pixmap = QPixmap(r"C:\Users\user\Downloads\WhatsApp_Image_2024-04-25_at_11.06.47_24e26e34-removebg-preview.png")
        resized_pixmap = pixmap.scaled(900, 900, Qt.KeepAspectRatio, Qt.SmoothTransformation) 
        logo_label.setPixmap(resized_pixmap)

        gradientPanelLayout = QVBoxLayout()
        gradientPanelLayout.addWidget(logo_label, alignment=Qt.AlignLeft)

        gradientPanel.setLayout(gradientPanelLayout)
        mainLayout.addWidget(gradientPanel, 1)  

        rightPanel = GradientWidget()
        rightPanelLayout = QVBoxLayout()
        rightPanel.setLayout(rightPanelLayout)

        self.username = QLineEdit(self)
        self.username.setPlaceholderText('Username')
        rightPanelLayout.addWidget(self.username)

        self.password = QLineEdit(self)
        self.password.setPlaceholderText('Password')
        self.password.setEchoMode(QLineEdit.Password)
        rightPanelLayout.addWidget(self.password)

        self.loginBtn = QPushButton('Log In', self)
        self.loginBtn.setObjectName("loginBtn") 
        self.loginBtn.clicked.connect(self.on_login_clicked)
        rightPanelLayout.addWidget(self.loginBtn)
        
        self.signupBtn = QPushButton("Don't have an account? Sign up", self)
        self.signupBtn.setObjectName("signupBtn")  
        self.signupBtn.clicked.connect(self.on_signup_clicked)
        rightPanelLayout.addWidget(self.signupBtn)
        
        rightPanelLayout.setAlignment(Qt.AlignCenter)

        mainLayout.addWidget(rightPanel, 1)  

        self.setLayout(mainLayout)
        
    def on_signup_clicked(self):
        self.signupWindow = SignupWindow(self.clientSocket)
        self.signupWindow.show()
        

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
                self.postLoginWindow = PostLoginWindow(self.clientSocket, username_text)  
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
        self.setWindowTitle("YallaChat - Main Menu")
        self.showMaximized()

        # Set stylesheet
        self.setStyleSheet(
            """
            QLabel#title {
                font-size: 24px;
                color: #FFF;
                font-weight: bold;
                margin-bottom: 20px;
            }
            QLabel {
                font-size: 18px;
                color: #FFF;
            }
            QPushButton {
                    font-size: 18px;
                border: none;
                border-radius: 15px;
                padding: 15px;
                background-color: #4CAF50;
                color: white;
                margin: 10px;
                max-width: 250px;
            }
            QPushButton:hover {
                background-color: #81C784;
            QPushButton:pressed {
                background-color: #388E3C;
            }
            """
        )

        main_layout = QVBoxLayout()

        top_layout = QHBoxLayout()

        logo_label = QLabel(self)
        pixmap = QPixmap(r"C:\Users\user\Downloads\WhatsApp_Image_2024-04-25_at_11.06.47_24e26e34-removebg-preview.png")  # Path to your logo
        resized_pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)  # Resize to make it bigger
        logo_label.setPixmap(resized_pixmap)
        top_layout.addWidget(logo_label, alignment=Qt.AlignLeft)  

        main_layout.addLayout(top_layout)

        self.usernameLabel = QLabel(f"Logged in as: {self.username}", self)
        self.usernameLabel.setAlignment(Qt.AlignCenter)
        self.usernameLabel.setObjectName("title")
        main_layout.addWidget(self.usernameLabel)

        middle_spacer = QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
        main_layout.addItem(middle_spacer)

        button_layout = QVBoxLayout()

        button_texts = [
            ("View Friends & Status", self.view_friends),
            ("View Friend Requests", self.view_friend_requests),
            ("Send Friend Request", self.send_friend_request),
            ("Start Chat/Send Message", self.start_chat),
            ("Groups", self.open_groups_window),
            ("Exit", self.exit_app),
        ]

        for text, method in button_texts:
            button = QPushButton(text, self)
            button.clicked.connect(method)
            button_layout.addWidget(button)

        # Center the buttons in the layout
        button_layout.setAlignment(Qt.AlignCenter)
        main_layout.addLayout(button_layout)

        # Spacer at the bottom
        bottom_spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        main_layout.addItem(bottom_spacer)

        self.setLayout(main_layout)

    def view_friend_requests(self):
        self.friendRequestsListWindow = FriendRequestsListWindow(self.clientSocket)
        self.friendRequestsListWindow.show()

    def view_friends(self):
        self.friendsListWindow = FriendsListWindow(self.clientSocket)
        self.friendsListWindow.show()

   
    def send_friend_request(self):
        dialog = QInputDialog(self)
        dialog.setInputMode(QInputDialog.TextInput)
        dialog.setLabelText("Friend's username:")
        dialog.setWindowTitle("Send Friend Request")
        dialog.setTextValue("")
        
        dialog.setStyleSheet("QLabel { color: #009688; font-size: 16px; } QPushButton { width: 100px; }")
        okPressed = dialog.exec_()
        friend_username = dialog.textValue()
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

        self.setStyleSheet("background-color: #6c1cbe; color: white;")

        mainLayout = QVBoxLayout()  
        splitter = QSplitter(Qt.Horizontal)  

        searchLayout = QVBoxLayout()
        self.usernameSearch = QLineEdit()
        self.usernameSearch.setPlaceholderText("Search for a username")
        self.usernameSearch.setStyleSheet("background-color: #f1f5f8; color: black;")
        searchLayout.addWidget(self.usernameSearch)

        self.searchButton = QPushButton("Search")
        self.searchButton.setStyleSheet("background-color: #4CAF50; color: white;")
        self.searchButton.clicked.connect(self.search_usernames)
        searchLayout.addWidget(self.searchButton)

        self.userListWidget = QListWidget()
        self.userListWidget.setStyleSheet("background-color: #f1f5f8; color: black;")
        self.userListWidget.itemClicked.connect(self.on_user_selected)
        searchLayout.addWidget(self.userListWidget)

        searchWidget = QWidget()
        searchWidget.setLayout(searchLayout)
        splitter.addWidget(searchWidget)


        chatLayout = QVBoxLayout()
        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)
        self.chatDisplay.setStyleSheet("background-color: #f1f5f8; color: black;")
        chatLayout.addWidget(self.chatDisplay)

        self.messageInput = QLineEdit()
        self.messageInput.setStyleSheet("background-color: #f1f5f8; color: black;")
        chatLayout.addWidget(self.messageInput)

        self.sendButton = QPushButton("Send")
        self.sendButton.setStyleSheet("background-color: #4CAF50; color: white;")
        self.sendButton.clicked.connect(self.send_message)
        chatLayout.addWidget(self.sendButton)

        self.sendFileButton = QPushButton("Send File")
        self.sendFileButton.setStyleSheet("background-color: #4CAF50; color: white;")
        self.sendFileButton.clicked.connect(self.send_file)
        chatLayout.addWidget(self.sendFileButton)


        self.searchTopicInput = QLineEdit()
        self.searchTopicInput.setPlaceholderText("Enter topic to search in chat...")
        self.searchTopicInput.setStyleSheet("background-color: #f1f5f8; color: black;")
        chatLayout.addWidget(self.searchTopicInput)

        self.searchTopicButton = QPushButton("Search Topic")
        self.searchTopicButton.setStyleSheet("background-color: #4CAF50; color: white;")
        self.searchTopicButton.clicked.connect(self.search_in_chat)
        chatLayout.addWidget(self.searchTopicButton)

        chatWidget = QWidget()
        chatWidget.setLayout(chatLayout)
        splitter.addWidget(chatWidget)

        mainLayout.addWidget(splitter)
        self.setLayout(mainLayout)

    def search_in_chat(self):
        search_term = self.searchTopicInput.text()
        if search_term:
            cursor = self.chatDisplay.textCursor()
            format = QTextCharFormat()
            format.setBackground(QColor("yellow"))
            
           
            cursor.select(QTextCursor.Document)
            cursor.setCharFormat(QTextCharFormat())
            
            
            regex = QRegularExpression(search_term, QRegularExpression.CaseInsensitiveOption)
            pos = 0
            index = regex.match(self.chatDisplay.toPlainText(), pos)
            while index.hasMatch():
                cursor.setPosition(index.capturedStart())
                cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, index.capturedLength())
                cursor.setCharFormat(format)
                pos = index.capturedEnd()
                index = regex.match(self.chatDisplay.toPlainText(), pos)
            self.searchTopicInput.clear()

    
    


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
        # Reset the chat state
        self.current_chat_with = item.text()  
        self.chatDisplay.clear()  
        self.load_chat_history()  

    def send_message(self):
        message_content = self.messageInput.text()
        if message_content and self.current_chat_with:
            formatted_message = f"{self.username}: {message_content}"
            self.clientSocket.send(f"chat {self.current_chat_with} {message_content}".encode())
            self.display_message(formatted_message, sent=True)
            self.messageInput.clear()


    def on_message_received(self, message):
        
        if message.startswith("file"):
            _, file_name, file_size = message.split()[:3]
            file_size = int(file_size)
    
            
            with open(file_name, "wb") as f:
                received = 0
                while received < file_size:
                    data = self.clientSocket.recv(1024)  
                    f.write(data)
                    received += len(data)
    
            QMessageBox.information(self, "File Received", f"File {file_name} received and saved.")
        else:
            self.display_message(message)


    def load_chat_history(self):
        if self.current_chat_with:
            self.clientSocket.send(f"fetch_chat_history {self.current_chat_with}".encode())
            response = self.clientSocket.recv(4096).decode()
            self.chatDisplay.clear()
            for line in response.split("\n"):
                if line.strip():
                    self.chatDisplay.append(line.strip())


    def display_message(self, message, sent=False):
        color = "blue" if sent else "green"  
        formatted_message = f'<div style="color: {color};">{message}</div>'
        self.chatDisplay.append(formatted_message)  

                
                
    

    def send_file(self):
        file_dialog = QFileDialog(self)
        file_path = file_dialog.getOpenFileName(self, "Select File")[0]
        if file_path:
            
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
    
            self.clientSocket.send(f"file {self.current_chat_with} {file_name} {file_size}".encode())
    
            
            with open(file_path, "rb") as file:
                while True:
                    data = file.read(1024)  
                    if not data:
                        break
                    self.clientSocket.sendall(data)


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
        self.selected_group_id = None
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

        self.listGroupsBtn = QPushButton('List My Groups', self)
        self.listGroupsBtn.clicked.connect(self.list_groups)
        layout.addWidget(self.listGroupsBtn)

        self.groupsList = QListWidget(self)
        layout.addWidget(self.groupsList)
        self.groupsList.itemClicked.connect(self.select_group)  

        self.addMemberBtn = QPushButton('Add Member to Selected Group', self)
        self.addMemberBtn.clicked.connect(self.add_member_to_selected_group)  
        layout.addWidget(self.addMemberBtn)

        self.setLayout(layout)

    def create_group(self):
        group_name = self.newGroupName.text()
        if group_name:
            response = send_to_server(self.clientSocket, f"create_group {group_name}")
            QMessageBox.information(self, "Server Response", response)
            self.newGroupName.clear()  
            self.list_groups()  

    def list_groups(self):
        self.groupsList.clear()  
        response = send_to_server(self.clientSocket, "list_groups")
        if response.strip() != "You are not in any groups.":
            for group in response.split('\n'):
                self.groupsList.addItem(group)
        else:
            QMessageBox.information(self, "Groups", response)

    def select_group(self, item):
        group_info = item.text()
        group_id, group_name = group_info.split(":")[0].strip(), group_info.split(":")[1].strip()
        self.selected_group_id = group_id  
        self.groupChatWindow = GroupChatWindow(self.clientSocket, self.username, group_id, group_name)
        self.groupChatWindow.show()

    def add_member_to_selected_group(self):
        if not self.selected_group_id:
            QMessageBox.warning(self, "Select Group", "Please select a group first.")
            return

        member_username, okPressed = QInputDialog.getText(self, "Add Member to Group", "Enter username:", QLineEdit.Normal, "")
        if okPressed and member_username:
            response = send_to_server(self.clientSocket, f"add_to_group {self.selected_group_id} {member_username}")
            QMessageBox.information(self, "Server Response", response)

        
class GroupChatWindow(GradientWidget):
    def __init__(self, clientSocket, username, group_id, group_name):
        super().__init__()
        self.clientSocket = clientSocket
        self.username = username
        self.group_id = group_id
        self.group_name = group_name
        self.stop_listening = threading.Event()  
        self.listenerThread = GroupListenerThread(clientSocket, self.stop_listening, self.group_id) 
        self.listenerThread.messageReceived.connect(self.on_message_received)  
        self.listenerThread.start()  
        self.initUI()  
        self.fetch_and_display_group_chat_history()  

    def initUI(self):
        self.setWindowTitle(f"Group Chat - {self.group_name}")
        self.setGeometry(300, 300, 600, 400)

        layout = QVBoxLayout()

       
        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)  
        layout.addWidget(self.chatDisplay)

        
        self.messageInput = QLineEdit()
        self.messageInput.setPlaceholderText("Type a message...")
        layout.addWidget(self.messageInput)

        
        self.sendButton = QPushButton("Send")
        self.sendButton.clicked.connect(self.send_message)
        layout.addWidget(self.sendButton)

        self.setLayout(layout)

    def fetch_and_display_group_chat_history(self):
        self.chatDisplay.clear()  
        response = send_to_server(self.clientSocket, f"fetch_group_chat_history {self.group_id}")
        self.chatDisplay.append(response)  
    def send_message(self):
        message_content = self.messageInput.text()  
        if message_content:  
            timestamp = datetime.now(pytz.timezone("Asia/Beirut")).strftime("%Y-%m-%d %H:%M:%S")  
            formatted_message = f"[{timestamp}] {self.username}: {message_content}"


            
            self.chatDisplay.append(formatted_message)  

            self.messageInput.clear()  

    def on_message_received(self, message):
        if message.startswith("history:"):
            history_messages = message[len("history:"):].split("\n")
            for msg in history_messages:
                self.chatDisplay.append(msg)  
        else:
            
            self.chatDisplay.append(message)

    def closeEvent(self, event):
        self.stop_listening.set()  
        if self.listenerThread.isRunning():
            self.listenerThread.wait()  
        super().closeEvent(event)  







def main():
    app = QApplication(sys.argv)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
    clientSocket.connect(('localhost', 13000))
    
  
    set_keepalive(clientSocket)
    
    window = LoginWindow(clientSocket)   
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

