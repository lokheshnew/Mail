# 📧 Local Mail Server Testing Guide

This guide provides a step-by-step process for testing a custom Python-based mail server using a web-based mail client on both a laptop and a mobile device connected to the same Wi-Fi network.

---

## ✅ Step 1: Setup and Preparation

### On Your Laptop (Server):

1. Make sure your Python mail server is running:
   ```bash
   python your_mail_server.py
   ```

2. Note the network IP address shown in the console (e.g., `http://192.168.1.100:8000`).

3. Save the HTML file (mail client interface) as `mail_client.html` on your laptop.

---

## 🌐 Step 2: Find Your Server's IP Address

### On Your Laptop:

- **Windows**:
  - Open **Command Prompt** and run:
    ```bash
    ipconfig
    ```

- **Mac/Linux**:
  - Open **Terminal** and run:
    ```bash
    ifconfig
    ```
    or
    ```bash
    ip addr
    ```

> Look for your **WiFi adapter's IP address** (usually starts with `192.168.x.x`).

---

## 💻 Step 3: Test from Laptop

1. Open `mail_client.html` in a browser (double-click or drag it in).

2. **Register second user**:
   - **Username:** `user2`
   - **Email:** `user2@test.com`
   - **Password:** `password456`
   - **Service:** Custom Local Mail  
   - Click **"Register"**

---

## 📱 Step 4: Test from Mobile

1. **Connect your mobile device to the same Wi-Fi network** as your laptop.

2. **Access the server**:
   - Open a browser on your mobile.
   - Navigate to:  
     ```
     http://YOUR_LAPTOP_IP:8000
     ```
     Replace `YOUR_LAPTOP_IP` with the actual IP you found earlier.

3. You should see the API info page.

4. **Access the mail client**:
   - Option 1: Copy the HTML content to your mobile and save it as a file.
   - Option 2: Host the HTML file on your laptop and access it via mobile browser.

5. **Open `mail_client.html`** in your mobile browser.

6. **Configure Server URL**:
   - Enter:  
     ```
     http://YOUR_LAPTOP_IP:8000
     ```
   - Click **"Test Connection"** — you should see the API info.

7. **Register first user**:
   - **Username:** `user1`
   - **Email:** `user1@test.com`
   - **Password:** `password123`
   - **Service:** Custom Local Mail  
   - Click **"Register"**

---

## ✉️ Step 5: Email Testing Process

### 🟩 A. Login on Laptop
- Login as `user1@test.com` with password `password123`
- The status bar should turn **green**

### 🟩 B. Login on Mobile
- Login as `user2@test.com` with password `password456`
- The status bar should turn **green**

### 📤 C. Send Email from Laptop (user1)
- Fill out the **Send Email** form:
  - **To:** `user2@test.com`
  - **Subject:** `Test from Laptop`
  - **Message:** `Hello from user1 on laptop!`
- Click **"Send Email"**
- You should see a **success message**

### 📥 D. Check Email on Mobile (user2)
- Click **"Refresh Inbox"**
- You should see the email from user1
- Click the email to view details

### ↩️ E. Reply from Mobile (user2)
- Send reply email:
  - **To:** `user1@test.com`
  - **Subject:** `Reply from Mobile`
  - **Message:** `Hello back from user2 on mobile!`
- Click **"Send Email"**

### 📬 F. Check Reply on Laptop (user1)
- Click **"Refresh Inbox"**
- You should see the reply from user2

---

## 📝 Notes

- Ensure both devices are on the **same network**.
- Use `localhost` or `127.0.0.1` **only** on the server itself, not from mobile.
- For hosting the HTML client over HTTP, you can use a simple Python HTTP server:
  ```bash
  python -m http.server 8080
  ```

---

Happy Testing! 🚀
