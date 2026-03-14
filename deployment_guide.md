# ThreatLens Deployment Guide

ThreatLens is designed to be deployed easily using Docker. Because it requires deep packet inspection (DPI), it needs specific network permissions that standard web hosts (like Vercel or Netlify) cannot provide.

Here is the best way to deploy ThreatLens: **A dedicated VPS (Virtual Private Server) running Linux (Ubuntu/Debian)**.

---

## 🌩️ Option 1: The Best Way (DigitalOcean, AWS EC2, or Linode)

The most reliable way to run ThreatLens and capture real network traffic is on a Linux VPS. You can get a basic VPS for about $5-6/month.

### Step 1: Get a Server
1. Create a server (Droplet/EC2 instance) running **Ubuntu 22.04 or 24.04**.
2. **Minimum Specs:** 2GB RAM, 1 vCPU (4GB RAM recommended if capturing heavy traffic).
3. SSH into your new server:  
   `ssh root@your-server-ip`

### Step 2: Install Docker & Git
Run these commands on your server to install the required tools:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Git and Docker
sudo apt install -y git curl
curl -fsSL https://get.docker.com | sh
```

### Step 3: Clone and Configure ThreatLens
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/threatlens_project.git
cd threatlens_project

# Set up the environment variables
cp .env.example .env
nano .env
```
Inside the `.env` file, change your login credentials:
```env
ADMIN_USER=your_secure_username
ADMIN_PASS=your_secure_password
```

### Step 4: Start ThreatLens
Run the container in the background. ThreatLens uses `network_mode: host` and `cap_add: NET_ADMIN` to allow Scapy to listen to the server's network traffic.

```bash
docker compose up --build -d
```

### Step 5: Access the Dashboard
Open your web browser and go to:
`http://your-server-ip:8000`

Login using the credentials you set in Step 3!

---

## 🚂 Option 2: Railway or Render (Demo Mode Only)

If you don't care about capturing *live* host network traffic and just want to host the dashboard to analyze PCAP files or view the synthetic demo traffic, you can use **Railway.app** or **Render.com**.

1. Push your code to GitHub.
2. Sign up for [Railway](https://railway.app/) or [Render](https://render.com/).
3. Create a new project -> **Deploy from GitHub repo**.
4. Select the `threatlens_project` repository.
5. In the platform's settings, add your Environment Variables:
   - `ADMIN_USER` = `admin`
   - `ADMIN_PASS` = `your_password`
   - `PORT` = `8000`
   - `HOST` = `0.0.0.0`
6. Click **Deploy**. The platform will read the [Dockerfile](file:///c:/Users/sswai/Documents/threatlens_project/Dockerfile) and build everything automatically.

*Note: On cloud platforms like Railway, you do not have raw packet capture privileges (`NET_ADMIN`). ThreatLens will automatically fallback to "Demo Mode" (generating synthetic traffic) or you can upload PCAP files via volume mounts if configured.*

---

## 🔒 Securing Your Deployment with HTTPS (Nginx)

If you chose Option 1 (VPS), you should secure your dashboard with HTTPS using Nginx and Let's Encrypt.

```bash
# Install Nginx and Certbot
sudo apt install -y nginx certbot python3-certbot-nginx

# Map your domain name (e.g., threatlens.yourdomain.com) to your server IP in your DNS provider.

# Edit Nginx configuration
sudo nano /etc/nginx/sites-available/threatlens
```

Paste the following config (replace `yourdomain.com`):
```nginx
server {
    listen 80;
    server_name threatlens.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable the site and get an SSL certificate:
```bash
sudo ln -s /etc/nginx/sites-available/threatlens /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d threatlens.yourdomain.com
```

Your ThreatLens dashboard is now securely accessible worldwide via `https://threatlens.yourdomain.com`!
