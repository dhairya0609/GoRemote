
# 🔐 GoRemote: Secure & Scalable Remote Code Execution Platform

GoRemote is a secure, scalable, and resilient platform for remote code execution, specializing in **Go language** support. It provides **low-latency**, **isolated**, and **malware-resistant** execution environments powered by Docker, MongoDB, and semantic OWL reasoning. Designed for high availability and real-time monitoring, GoRemote is built to handle large-scale, concurrent workloads safely.

---

## 📌 Table of Contents

- [🎯 Overview](#-overview)
- [🚀 Features](#-features)
- [🛠️ Architecture](#-architecture)
- [🧱 Components](#-components)
- [⚙️ Technologies Used](#️-technologies-used)
- [☁️ Cloud Services](#-cloud-services)
- [📜 Algorithms & Flow](#-algorithms--flow)
- [💻 Hardware & Software Setup](#-hardware--software-setup)
- [🗃️ Database Schema](#-database-schema)
- [📈 Future Enhancements](#-future-enhancements)

---

## 🎯 Overview

**GoRemote** provides:
- 🚀 Fast and secure execution of Go code
- 🐳 Docker-based isolation for each user
- 🧠 Malware detection via OWL-based reasoning engine
- ⚖️ Smart request distribution using nginx load balancer
- 💾 Persistent storage of user, code, and logs in MongoDB
- ♻️ Auto-removal of idle containers to optimize performance

---

## 🚀 Features

- **User Authentication**: Register/Login/Logout using JWT & password hashing.
- **Code Management**: Create, Read, Update, and Delete Go code snippets.
- **Secure Execution**: Dockerized containers per user ensure safe, isolated execution.
- **Malware Detection**: Python-based OWL engine flags malicious code before execution.
- **Load Balancing**: nginx routes requests to Go/Rust servers in round-robin fashion.
- **Auto Cleanup**: Docker containers are stopped after 10 minutes of inactivity.
- **Comprehensive Logging**: All actions and outputs are logged and stored.

---

## 🛠️ Architecture

```
Client → Authorization (JWT) → Ontology Check (OWL)
     → nginx Load Balancer → Go/Rust Execution Servers (Docker)
     → MongoDB for Code, Logs, Users
```

- **Router VM**: nginx + Reverse Proxy + Resource Allocator
- **Execution VMs**: Go & Rust servers running code in Docker containers
- **Ontology Module**: Detects malicious code using OWL semantic analysis
- **Database VM**: MongoDB for persistent storage

---

## 🧱 Components

### 1. 🔐 Authorization Module
- Handles user registration, login, logout
- Stores hashed credentials and session tokens in MongoDB

### 2. 🧠 Ontology Module
- Uses OWL (Web Ontology Language) + rule engine
- Detects suspicious or malicious code patterns

### 3. 🌐 Router VM
- nginx handles load balancing and reverse proxying
- Routes to least-burdened execution server

### 4. 🧪 Execution VMs
- Docker containers per user
- Reuses containers for better performance
- Executes Go code (Rust server also present for future scaling)

### 5. 💾 MongoDB
- Stores users, sessions, code, execution logs, and output

---

## ⚙️ Technologies Used

| Purpose                | Tech Stack                |
|------------------------|---------------------------|
| Server-side Execution  | Go, Rust                  |
| Malware Detection      | Python + OWL              |
| Containerization       | Docker                    |
| Load Balancing         | nginx                     |
| Persistence            | MongoDB                   |
| API & Routing          | chi router (Go)           |
| Authentication         | JWT, bcrypt               |

---

## ☁️ Cloud Services

| Category               | Cloud Service             |
|------------------------|---------------------------|
| Hosting                | PaaS for Go/Rust servers  |
| Database               | MongoDB (Self-hosted/Atlas) |
| Ontology               | OWL-based Python service  |
| Authorization          | Custom Auth Service       |
| Execution              | Docker on Execution VMs   |
| Routing                | nginx                     |

---

## 📜 Algorithms & Flow

### 🔁 Main Flow
```
Start → Listen for Request → Process_Request(Request)
```

### 🔐 Process_Request(Request)
```pseudo
Input: user_token, code
→ Authorize_User(user_token)
  → If fail, return "Authorization Failed"
→ Malicious_Code_Check(code)
  → If malicious, return "Malicious Code Detected"
→ Route_To_Execution_Server(user_id, code)
  → Execute code in container
→ Return code output to client
```

### ⚖️ Route_To_Execution_Server
```pseudo
→ nginx selects least-loaded server
→ Create or reuse Docker container
→ Copy code and execute inside container
→ Capture and return output
```

### 📝 Update_MongoDB
```pseudo
→ Save user_id, file_path, code, output, logs to MongoDB
```

---

## 💻 Hardware & Software Setup

| Component         | Specs (CPUs / RAM) | Purpose                           |
|------------------|--------------------|-----------------------------------|
| Router VM        | 2 CPUs / 4 GB      | nginx Load Balancer               |
| Execution VM 1   | 2 CPUs / 4 GB      | Go Server + Docker                |
| Execution VM 2   | 2 CPUs / 4 GB      | Rust Server + Docker              |
| MongoDB VM       | 2 CPUs / 4 GB      | Data persistence                  |

---

## 🗃️ Database Schema

### Users Collection
```json
{
  "user_id": "UUID",
  "email": "example@mail.com",
  "password_hash": "hashed_pw",
  "session_token": "JWT_token"
}
```

### Code Collection
```json
{
  "user_id": "UUID",
  "file_name": "main.go",
  "code": "package main...",
  "execution_logs": "...",
  "output": "Hello, World!"
}
```

---

## 📈 Future Enhancements

- 🌍 Add Web UI for code editing and execution
- 🧠 AI-powered code anomaly detection
- 📊 Real-time container metrics & visualization
- 🌐 Multi-language support (Python, C++, etc.)
- 🛡️ Rate limiting and DoS protection

---

## 💬 Feedback & Contribution

Pull requests, issue reports, and suggestions are welcome!  
If you'd like to contribute, please fork the repo and submit a PR.

---
