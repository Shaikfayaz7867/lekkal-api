# Lekkal Personal Finance Manager Sync Backend

This is a fully functional, production-ready, database-connected Express + SQLite backend for the **Lekkal Personal Finance Manager** Android application. It allows secure multi-device synchronization, real-time cloud backups, user authorization, and data alignment for both expenses and budgets.

---

## Features

- 🔐 **Secure JWT Authentication**: Built-in register and login endpoints with dynamic token generation.
- 🔑 **Cryptographic Password Hashing**: Passwords are securely encrypted using `bcryptjs` before DB insertion.
- 🗄️ **Robust SQLite Database**: Connected to local `lekkal_backup.db` for instant, frictionless file-based storage. No complex database servers needed!
- ⚡ **Bi-directional Sync**: A single, highly optimized sync endpoint `/api/sync` that merges incoming offline records and downloads updated clouds.
- 🩺 **Health Monitoring**: Dedicated health checks.

---

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: SQLite3
- **Security**: jsonwebtoken, bcryptjs

---

## Directory Setup & Files

- `server.js`: Standard entry point with SQLite schemas and authentication gates.
- `package.json`: Main dependency manager.
- `.env`: Active environment configurations (e.g. JWT secrets, ports).

---

## API Endpoints

### 1. Public Endpoints
- **GET** `/api/health`
  - *Description*: Returns API status, server timestamp, and database connectivity.
- **POST** `/api/auth/register`
  - *Description*: Sign up a new user account.
  - *Body*:
    ```json
    {
      "email": "user@example.com",
      "password": "secure_passcode_here",
      "name": "Jane Doe"
    }
    ```
- **POST** `/api/auth/login`
  - *Description*: Log in to an existing account and obtain a JWT.
  - *Body*:
    ```json
    {
      "email": "user@example.com",
      "password": "secure_passcode_here"
    }
    ```

### 2. Protected Sync Endpoints (Requires `Authorization: Bearer <JWT_TOKEN>`)
- **POST** `/api/sync`
  - *Description*: Bi-directional synchronization for mobile local databases.
  - *Body*:
    ```json
    {
      "expenses": [
        {
          "id": 1,
          "merchant": "Zomato",
          "amount": 380.0,
          "timestamp": 1720275583000,
          "category": "Food",
          "paymentMethod": "UPI",
          "isSimulated": false,
          "notes": "Dinner with friends"
        }
      ],
      "budgets": [
        {
          "id": 1,
          "name": "Overall Limit",
          "isCategory": false,
          "amount": 15000.0,
          "timestamp": 1720275583000
        }
      ]
    }
    ```
  - *Response*: Returns fully combined/synced databases from the cloud back to the device to merge seamlessly.

---

## Quick Start (How to Run)

1. **Prerequisites**: Ensure you have [Node.js](https://nodejs.org/) installed on your machine.
2. **Navigate** into the `/backend` folder:
   ```bash
   cd backend
   ```
3. **Install Dependencies**:
   ```bash
   npm install
   ```
4. **Start the Server**:
   ```bash
   npm start
   ```
   The backend will start listening at `http://localhost:5000`!
