import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { CircularProgress, Box, Typography } from '@mui/material';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        sx={{
          background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
        }}
      >
        <CircularProgress
          size={60}
          thickness={4}
          sx={{
            color: '#00d4ff',
            mb: 2
          }}
        />
        <Typography
          variant="h6"
          sx={{
            color: '#e2e8f0',
            fontFamily: "'Syne', 'Segoe UI', sans-serif",
            fontWeight: 600
          }}
        >
          Loading...
        </Typography>
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check if user's email is verified (optional - skip for now)
  // if (user && !user.emailVerified) {
  //   return (
  //     <Box
  //       display="flex"
  //       flexDirection="column"
  //       justifyContent="center"
  //       alignItems="center"
  //       minHeight="100vh"
  //       sx={{
  //         background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
  //         padding: 3
  //       }}
  //     >
  //       <Typography
  //         variant="h4"
  //         sx={{
  //           color: '#f59e0b',
  //           fontFamily: "'Orbitron', monospace",
  //           fontWeight: 700,
  //           mb: 2,
  //           textAlign: 'center'
  //         }}
  //       >
  //         Email Verification Required
  //       </Typography>
  //       <Typography
  //         variant="body1"
  //         sx={{
  //           color: '#94a3b8',
  //           textAlign: 'center',
  //           maxWidth: 400,
  //           mb: 3
  //         }}
  //       >
  //         Please verify your email address before accessing the dashboard. Check your inbox for the verification link.
  //       </Typography>
  //       <Typography
  //         variant="body2"
  //         sx={{
  //           color: '#64748b',
  //           textAlign: 'center'
  //         }}
  //       >
  //         If you need to resend the verification email, please contact support.
  //       </Typography>
  //     </Box>
  //   );
  // }

  // User is authenticated, render the protected content
  return <>{children}</>;
}
