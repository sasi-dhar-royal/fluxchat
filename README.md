# CloudChat - One-to-Many Private Support System

Professional Support Chat Application built with Node.js, Express, Socket.io, and MongoDB.

## Features
- **Strict One-to-Many Architecture**: Regular users can only see and chat with the Admin.
- **Admin Dashboard**: Sidebar user list with real-time "Green Dot" status indicators.
- **Real-time Messaging**: Instant communication powered by Socket.io.
- **Persistence**: Chat history and user data stored in MongoDB.
- **Modern UI**: Glassmorphism login, responsive design, and professional color palette.

## Prerequisites
- Node.js installed.
- MongoDB running locally (default: `mongodb://localhost:2017/cloudchat`).

## Setup & Running
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   node server.js
   ```
3. Open in browser:
   - `http://localhost:3000`

## Credentials
- **Admin**: `admin` / `admin123` (Auto-created on first run)
- **User**: Enter any username and password on the login page; a new user account will be created automatically.
