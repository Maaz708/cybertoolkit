import React, { useState } from 'react';
import {
    Box,
    Button,
    Card,
    CardContent,
    Typography,
    CircularProgress,
    Alert,
    List,
    ListItem,
    ListItemText,
    Stepper,
    Step,
    StepLabel
} from '@mui/material';
import { Restore, Download } from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:3000/api/recovery';

const FileRecovery: React.FC = () => {
    const [file, setFile] = useState<File | null>(null);
    const [recovering, setRecovering] = useState(false);
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState<string>('');

    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const files = event.target.files;
        if (files && files[0]) {
            setFile(files[0]);
            setResult(null);
            setError('');
        }
    };

    const handleRecovery = async () => {
        if (!file) return;

        setRecovering(true);
        setError('');
        setResult(null);

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await axios.post(`${API_BASE_URL}/recover`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });

            if (response.data.status === 'success') {
                setResult(response.data.data);
            } else {
                throw new Error(response.data.message);
            }
        } catch (err: any) {
            setError(err.message || 'Recovery failed');
        } finally {
            setRecovering(false);
        }
    };

    const downloadRecoveredFile = async () => {
        if (!result?.recoveredPath) return;

        try {
            const filename = result.recoveredPath.split('/').pop();
            const response = await axios.get(`${API_BASE_URL}/download/${filename}`, {
                responseType: 'blob'
            });

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `recovered_${file?.name}`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (err) {
            setError('Failed to download recovered file');
        }
    };

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h4" gutterBottom>
                File Recovery
            </Typography>

            <Card sx={{ mb: 3 }}>
                <CardContent>
                    <Typography variant="h6" gutterBottom>
                        Upload Corrupted File
                    </Typography>

                    <Button
                        variant="contained"
                        component="label"
                        startIcon={<Restore />}
                        disabled={recovering}
                    >
                        Select File
                        <input
                            type="file"
                            hidden
                            onChange={handleFileChange}
                        />
                    </Button>

                    {file && (
                        <>
                            <Typography sx={{ mt: 2 }} color="textSecondary">
                                Selected: {file.name}
                            </Typography>

                            <Button
                                variant="contained"
                                color="primary"
                                onClick={handleRecovery}
                                disabled={recovering}
                                sx={{ mt: 2 }}
                            >
                                {recovering ? 'Recovering...' : 'Start Recovery'}
                            </Button>
                        </>
                    )}
                </CardContent>
            </Card>

            {error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {error}
                </Alert>
            )}

            {recovering && (
                <Box sx={{ display: 'flex', justifyContent: 'center', my: 3 }}>
                    <CircularProgress />
                </Box>
            )}

            {result && (
                <Card>
                    <CardContent>
                        <Typography variant="h6" gutterBottom>
                            Recovery Results
                        </Typography>

                        <Stepper activeStep={result.log.steps.length} orientation="vertical">
                            {result.log.steps.map((step: string, index: number) => (
                                <Step key={index} completed={true}>
                                    <StepLabel>{step}</StepLabel>
                                </Step>
                            ))}
                        </Stepper>

                        {result.success ? (
                            <Box sx={{ mt: 3 }}>
                                <Alert severity="success" sx={{ mb: 2 }}>
                                    File recovered successfully!
                                </Alert>
                                <Button
                                    variant="contained"
                                    color="primary"
                                    startIcon={<Download />}
                                    onClick={downloadRecoveredFile}
                                >
                                    Download Recovered File
                                </Button>
                            </Box>
                        ) : (
                            <Alert severity="error" sx={{ mt: 3 }}>
                                Recovery failed: {result.error}
                            </Alert>
                        )}
                    </CardContent>
                </Card>
            )}
        </Box>
    );
};

export default FileRecovery; 