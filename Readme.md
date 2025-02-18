# Digital Forensics Toolkit

A comprehensive digital forensics tool built with React, Node.js, and Material-UI to provide File Analysis, Network Monitoring, Malware Detection, Email Forensics, and Cloud Forensics capabilities.

1 Table of Contents

Features
Prerequisites
Installation
Usage
File Analysis
Network Monitoring
Malware Detection
Email Forensics
Cloud Forensics
Configuration
Troubleshooting
Security
Support
License
Features

1. File Analysis
Metadata Extraction: Extract detailed file metadata.
Content Inspection: Perform in-depth content analysis.
Hash Generation: Generate MD5, SHA-1, and SHA-256 hashes.
Timeline Analysis: View file creation, modification, and access times.
File Recovery: Recover deleted or corrupted files.
Multi-Format Support: Analyze various file formats.
Report Generation: Generate detailed analysis reports.

2. Network Monitoring
Real-time Traffic Analysis: Monitor network traffic live.
Protocol Analysis: Analyze network protocol distribution.
Connection Tracking: Track active connections.
Bandwidth Monitoring: Measure network bandwidth usage.
Security Alerts: Get real-time security alerts.
Port Scanning Detection: Identify port scanning activities.
Historical Data Analysis: Review historical network activity data.

3. Malware Detection
Real-time Scanning: Monitor files continuously.
Signature Matching: Detect known malware signatures.
Behavioral Analysis: Identify suspicious patterns.
File Quarantine: Isolate suspicious files.
Automated Response: Take immediate action against threats.
Threat Reports: Generate detailed threat analysis reports.

4. Email Forensics
Header Analysis: Analyze email headers for authenticity.
Attachment Scanning: Check attachments for malware.
Phishing Detection: Identify phishing attempts.
Timeline Reconstruction: Rebuild email timelines.
Metadata Extraction: Extract relevant email metadata.
Server Log Analysis: Examine email server activity logs.

5. Cloud Forensics
Storage Analysis: Analyze cloud storage data.
Access Logs: Review access patterns.
Data Recovery: Restore deleted or corrupted cloud data.
User Activity Tracking: Monitor user actions.
Provider Integration: Support for major cloud providers.
Timeline Reconstruction: Analyze cloud activity history.

## Required Software & Downloads

### Core Software

1. Node.js (v18.x or higher)
   - Download: <https://nodejs.org/en/download>
   - Guide: <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm>

2. Git
   - Windows: <https://git-scm.com/download/win>
   - Mac: <https://git-scm.com/download/mac>
   - Linux: `sudo apt-get install git`

3. Visual Studio Code (Recommended IDE)
   - Download: <https://code.visualstudio.com/download>

### Package Managers

- npm (comes with Node.js)
- yarn (optional): <https://yarnpkg.com/getting-started/install>

## Dependencies Installation

### Backend Packages

bash
npm install express@latest
npm install express-fileupload@latest
npm install cors@latest
npm install dotenv@latest

### Frontend Packages

bash
npm install react@latest
npm install @mui/material @emotion/react @emotion/styled
npm install @mui/icons-material
npm install axios@latest
npm install typescript@latest

## Development Tools

1. Postman (API Testing)
   - Download: <https://www.postman.com/downloads/>

2. MongoDB Compass (Optional - if using MongoDB)
   - Download: <https://www.mongodb.com/try/download/compass>

## Browser Requirements

- Chrome (Recommended): <https://www.google.com/chrome/>
- Firefox: <https://www.mozilla.org/firefox/>
- Edge: <https://www.microsoft.com/edge>

# Prerequisites

System Requirements

Operating System: Windows 10/11, Linux, or macOS
RAM: 8GB minimum
Disk Space: 50GB free
Admin Privileges
Software Requirements
Node.js (v14.0.0 or higher)
Python (v3.8 or higher)
Git
MongoDB (v4.4 or higher)
Visual Studio Code
Installation
Clone the Repository:

bash

git clone <https://github.com/username/digital-forensics-toolkit.git>  
cd digital-forensics-toolkit  

Install Backend Dependencies:

bash

cd server  
npm install express cors systeminformation nodemailer multer crypto axios express-fileupload node-yara @azure/storage-blob aws-sdk mongodb mongoose

Install Frontend Dependencies:

bash

cd ../client  
npm install @mui/material @mui/icons-material @emotion/react @emotion/styled recharts @mui/x-date-pickers dayjs axios react-router-dom  

[optional for cloud forensics]
{Set Up Environment Variables:
Create a .env file in the server directory:

env

Copy code
PORT=3000  
MONGODB_URI=mongodb://localhost:27017/forensics  
AWS_ACCESS_KEY=your_aws_key  
AWS_SECRET_KEY=your_aws_secret  
AZURE_STORAGE_CONNECTION_STRING=your_azure_connection  }

Start the Application:

bash

# Start MongoDB  

mongod  or if u have mongo db compass add new connection

# Start Backend  

cd server  
node index.js  

# Start Frontend  

cd ../client  
npm run dev  

Usage
File Analysis
Navigate to the File Analysis tab.
Upload files via drag-and-drop or the file selector.
Review analysis results on the dashboard.
Network Monitoring
Go to the Network Monitoring tab.
Start monitoring and review real-time stats.
Export network analysis reports if needed.
Malware Detection
Choose files/directories to scan.
Select the scan type and review threats.
Take recommended actions.
Email Forensics
Import email files.
Analyze headers and attachments.
Generate detailed forensic reports.
Cloud Forensics
Connect cloud services.
Select data sources for analysis.
Export findings as reports.
Configuration

# Backend

javascript

// server/config/default.js  
module.exports = {  
  port: process.env.PORT || 3000,  
  mongodb: process.env.MONGODB_URI,  
  aws: {  
    accessKey: process.env.AWS_ACCESS_KEY,  
    secretKey: process.env.AWS_SECRET_KEY,  
  },  
  azure: {  
    connectionString: process.env.AZURE_STORAGE_CONNECTION_STRING,  
  },  
};  

# Frontend

javascript

// client/src/config/config.js  
export const API_BASE_URL = '<http://localhost:3000>';  
export const SOCKET_URL = 'ws://localhost:3000';  
Troubleshooting
Connection Issues:

Ensure MongoDB is running.
Verify backend server status.
Check for port conflicts.
File Upload Errors:

Verify file size and permissions.
Check supported file formats.
Network Monitoring Failures:

Run as administrator.
Verify firewall settings.
Security
Follow best practices:
Keep software updated.
Encrypt sensitive data.
Implement role-based access control.
Regularly audit logs.

Support
<maaz7084@gmail.com>

Documentation: Refer to the official docs.
Issues: Report via GitHub.
Contact: Email <maaz7084@gmail.com>
License
This project is licensed under the MIT License.

Last updated: November 18, 2024
Created by Mohd Maaz
