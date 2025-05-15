# YallaChat

YallaChat is a real-time messaging application with a modern UI that allows users to chat with friends, create groups, and share files.

## Features

- **User Authentication**: Secure signup and login system
- **Real-time Messaging**: Instant private messaging between users
- **Friend Management**: Send/accept friend requests and manage your friends list
- **Group Chat**: Create and manage group conversations
- **File Sharing**: Send and receive files between users
- **Message History**: Access your conversation history
- **Offline Messaging**: Receive messages sent while you were offline
- **Search Functionality**: Search for messages and users

## Technical Details

- **Client-Side**: Built with PyQt5 for a modern and responsive GUI
- **Server-Side**: Multi-threaded socket server handling multiple client connections
- **Database**: SQLite for storing user data, messages, and relationships
- **Communication**: TCP socket-based client-server architecture
- **Security**: Password validation and secure connections

## Requirements

- Python 3.6+
- PyQt5
- SQLite3
- Socket library
- Threading library
- pytz (for timezone handling)

## How to Run

### Server
```
python Server_code.py
```

### Client
```
python Client_code.py
```
or
```
python client_groups.py
```

## Usage

1. **Start the Server**: Launch the server application first
2. **Start the Client**: Launch the client application
3. **Create an Account**: Sign up with a name, email, address, username, and password
4. **Login**: Use your credentials to log in
5. **Add Friends**: Send friend requests to other users
6. **Chat**: Select a friend to start chatting
7. **Create Groups**: Make group conversations and add members
8. **Share Files**: Send files to friends during chat

## Project Structure

- `Server code.py`: Main server application handling client connections
- `Server_groups.py`: Server-side group chat functionality
- `Client code.py`: Main client application with GUI
- `client_groups.py`: Client-side group chat functionality

## Database Schema

The application uses SQLite with the following tables:
- `users`: Stores user information
- `friendships`: Tracks friend relationships
- `friend_requests`: Manages pending friend requests
- `messages`: Stores private messages between users
- `groups`: Contains group information
- `group_members`: Tracks group membership
- `group_messages`: Stores messages sent in groups 