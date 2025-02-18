import React from 'react';
import { Grid, Card, CardContent, Typography, Box } from '@mui/material';
import { Security, Storage, NetworkCheck, Email, Cloud } from '@mui/icons-material';
import { Line } from 'react-chartjs-2'; // Importing Chart.js for line charts
import { Chart, registerables } from 'chart.js'; // Import Chart and registerables
import { styled } from '@mui/material/styles'; // Use styled from @mui/material/styles

// Register all necessary components
Chart.register(...registerables);

// Custom styles for the dashboard
const DashboardContainer = styled(Box)(({ theme }) => ({
  background: 'linear-gradient(to right, #f0f4f8, #e0e7ff)',
  minHeight: '100vh',
  padding: theme.spacing(3),
}));

const StyledCard = styled(Card)(({ theme }) => ({
  transition: 'transform 0.3s',
  '&:hover': {
    transform: 'scale(1.05)',
  },
}));

const ChartContainer = styled(Box)(({ theme }) => ({
  marginTop: theme.spacing(3),
}));

const Dashboard = () => {
  const modules = [
    {
      title: 'File Analysis',
      icon: <Storage />,
      description: 'Analyze file metadata and content. This module allows users to extract and examine file properties, including size, type, and creation/modification dates. It helps in identifying suspicious files and understanding their origins.'
    },
    {
      title: 'Network Monitor',
      icon: <NetworkCheck />,
      description: 'Real-time network traffic analysis. This module monitors incoming and outgoing network traffic, providing insights into data packets, protocols used, and potential anomalies that could indicate security breaches.'
    },
    {
      title: 'Malware Detection',
      icon: <Security />,
      description: 'ML-powered malware detection. Utilizing machine learning algorithms, this module scans files and processes to identify known and unknown malware threats, helping to protect systems from malicious attacks.'
    },
    {
      title: 'Email Forensics',
      icon: <Email />,
      description: 'Email header and content analysis. This module examines email headers and body content to trace the origin of emails, detect phishing attempts, and analyze communication patterns for forensic investigations.'
    },
    /*{
      title: 'Cloud Forensics',
      icon: <Cloud />,
      description: 'Cloud storage investigation tools. This module provides tools to analyze data stored in cloud environments, helping to recover lost data, investigate unauthorized access, and ensure compliance with data protection regulations.'
    },*/
  ];

  // Sample data for charts
  const data = {
    labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
    datasets: [
      {
        label: 'Email Forensics',
        data: [65, 59, 80, 81, 56, 55, 40],
        fill: false,
        backgroundColor: 'rgba(75,192,192,0.4)',
        borderColor: 'rgba(75,192,192,1)',
      },
      {
        label: 'File Analysis',
        data: [28, 48, 40, 19, 86, 27, 90],
        fill: false,
        backgroundColor: 'rgba(153,102,255,0.4)',
        borderColor: 'rgba(153,102,255,1)',
      },
      {
        label: 'Malware Detection',
        data: [12, 33, 45, 67, 23, 45, 78],
        fill: false,
        backgroundColor: 'rgba(255,99,132,0.4)',
        borderColor: 'rgba(255,99,132,1)',
      },
      {
        label: 'Network Monitoring',
        data: [45, 67, 23, 45, 78, 90, 100],
        fill: false,
        backgroundColor: 'rgba(255,206,86,0.4)',
        borderColor: 'rgba(255,206,86,1)',
      },
      {
        label: 'Cloud Forensics',
        data: [30, 20, 50, 70, 90, 100, 110],
        fill: false,
        backgroundColor: 'rgba(54,162,235,0.4)',
        borderColor: 'rgba(54,162,235,1)',
      },
    ],
  };

  return (
    <DashboardContainer>
      <Typography variant="h4" gutterBottom sx={{ color: 'red' }}>
        Digital Forensics Toolkit
      </Typography>
      <Grid container spacing={3}>
        {modules.map((module, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <StyledCard>
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  {module.icon}
                  <Typography variant="h6" sx={{ ml: 1 }}>
                    {module.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {module.description}
                </Typography>
              </CardContent>
            </StyledCard>
          </Grid>
        ))}
      </Grid>

      /*<ChartContainer>
        <Typography variant="h5" gutterBottom sx={{ color: 'red' }}>
          Module Statistics
        </Typography>
        <Line data={data} />
      </ChartContainer>*/
    </DashboardContainer>
  );
};

export default Dashboard;