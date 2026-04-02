import React, { useState } from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Avatar, Menu, MenuItem, ListItemIcon, ListItemText, Divider } from '@mui/material';
import { Link, useNavigate } from 'react-router-dom';
import { Security, Storage, NetworkCheck, Email, Cloud, Restore, AccountCircle, Logout, Settings } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const Navigation = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const links = [
    { to: '/dashboard', text: 'Dashboard', icon: <Security /> },
    { to: '/file-analysis', text: 'File Analysis', icon: <Storage /> },
    { to: '/network-monitor', text: 'Network Monitor', icon: <NetworkCheck /> },
    { to: '/malware-detection', text: 'Malware Detection', icon: <Security /> },
    { to: '/email-forensics', text: 'Email Forensics', icon: <Email /> },
    /*{ to: '/cloud-forensics', text: 'Cloud Forensics', icon: <Cloud /> },*/
    { to: '/file-recovery', text: 'File Recovery', icon: <Restore /> },
  ];

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    handleMenuClose();
    // Navigate first to avoid ProtectedRoute interference
    navigate('/', { replace: true });
    // Then clear auth state
    await logout();
  };

  const handleProfile = () => {
    handleMenuClose();
    // Navigate to profile page (you can create this later)
    console.log('Navigate to profile');
  };

  const handleSettings = () => {
    handleMenuClose();
    // Navigate to settings page (you can create this later)
    console.log('Navigate to settings');
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography 
          variant="h6" 
          component={Link} 
          to="/dashboard"
          sx={{ 
            flexGrow: 1,
            textDecoration: 'none',
            color: 'inherit',
            fontFamily: "'Orbitron', monospace",
            fontWeight: 700
          }}
        >
          CyberToolkit
        </Typography>
        
        {/* Navigation Links */}
        <Box sx={{ display: { xs: 'none', md: 'flex' }, gap: 1, mr: 2 }}>
          {links.map((link) => (
            <Button
              key={link.to}
              component={Link}
              to={link.to}
              color="inherit"
              startIcon={link.icon}
              sx={{
                textTransform: 'none',
                fontWeight: 500,
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.1)'
                }
              }}
            >
              {link.text}
            </Button>
          ))}
        </Box>

        {/* User Profile */}
        {user && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography
              variant="body2"
              sx={{
                display: { xs: 'none', sm: 'block' },
                color: 'rgba(255, 255, 255, 0.8)'
              }}
            >
              {user.firstName} {user.lastName}
            </Typography>
            
            <Button
              onClick={handleMenuOpen}
              sx={{
                minWidth: 'auto',
                p: 1,
                borderRadius: '50%',
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.1)'
                }
              }}
            >
              <Avatar
                sx={{
                  width: 32,
                  height: 32,
                  bgcolor: 'primary.main',
                  fontSize: '14px',
                  fontWeight: 600
                }}
              >
                {user.firstName?.[0]?.toUpperCase() || user.email?.[0]?.toUpperCase() || 'U'}
              </Avatar>
            </Button>

            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
              onClick={handleMenuClose}
              PaperProps={{
                sx: {
                  mt: 1.5,
                  minWidth: 200,
                  background: '#1e293b',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  '& .MuiMenuItem-root': {
                    color: '#e2e8f0',
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.05)'
                    }
                  }
                }
              }}
            >
              {/* User Info */}
              <Box sx={{ px: 2, py: 1 }}>
                <Typography variant="subtitle2" sx={{ color: '#f1f5f9', fontWeight: 600 }}>
                  {user.firstName} {user.lastName}
                </Typography>
                <Typography variant="body2" sx={{ color: '#94a3b8', fontSize: '12px' }}>
                  {user.email}
                </Typography>
                <Typography variant="body2" sx={{ color: '#00d4ff', fontSize: '11px', mt: 0.5 }}>
                  {user.role.toUpperCase()} • {user.subscriptionTier.toUpperCase()}
                </Typography>
              </Box>
              
              <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
              
              {/* Menu Items */}
              <MenuItem onClick={handleProfile}>
                <ListItemIcon>
                  <AccountCircle sx={{ color: '#94a3b8', fontSize: 20 }} />
                </ListItemIcon>
                <ListItemText>Profile</ListItemText>
              </MenuItem>
              
              <MenuItem onClick={handleSettings}>
                <ListItemIcon>
                  <Settings sx={{ color: '#94a3b8', fontSize: 20 }} />
                </ListItemIcon>
                <ListItemText>Settings</ListItemText>
              </MenuItem>
              
              <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
              
              <MenuItem onClick={handleLogout}>
                <ListItemIcon>
                  <Logout sx={{ color: '#f87171', fontSize: 20 }} />
                </ListItemIcon>
                <ListItemText sx={{ color: '#f87171' }}>Logout</ListItemText>
              </MenuItem>
            </Menu>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Navigation;