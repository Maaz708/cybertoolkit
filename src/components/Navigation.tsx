import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import { Link } from 'react-router-dom';
import { Security, Storage, NetworkCheck, Email, Cloud, Restore } from '@mui/icons-material';

const Navigation = () => {
  const links = [
    { to: '/', text: 'Dashboard', icon: <Security /> },
    { to: '/file-analysis', text: 'File Analysis', icon: <Storage /> },
    { to: '/network-monitor', text: 'Network Monitor', icon: <NetworkCheck /> },
    { to: '/malware-detection', text: 'Malware Detection', icon: <Security /> },
    { to: '/email-forensics', text: 'Email Forensics', icon: <Email /> },
    { to: '/cloud-forensics', text: 'Cloud Forensics', icon: <Cloud /> },
    { to: '/file-recovery', text: 'File Recovery', icon: <Restore /> },
  ];

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          Digital Forensics Toolkit
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          {links.map((link) => (
            <Button
              key={link.to}
              component={Link}
              to={link.to}
              color="inherit"
              startIcon={link.icon}
            >
              {link.text}
            </Button>
          ))}
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navigation;