/**
 * Socket.io Real-time Service
 * Broadcasts network stats, alerts, and suspicious activity
 * NEW: Additive feature - doesn't affect existing REST APIs
 */

const { Server } = require('socket.io');
const logger = require('../utils/logger');

class RealtimeService {
    constructor(httpServer, options = {}) {
        this.io = new Server(httpServer, {
            cors: {
                origin: options.corsOrigin || "*",
                methods: ["GET", "POST"]
            },
            path: '/socket.io'
        });
        
        this.connectedClients = new Map();
        this.broadcastInterval = null;
        this.isMonitoring = false;
        
        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.io.on('connection', (socket) => {
            logger.info('Client connected to Socket.io', { 
                socketId: socket.id,
                ip: socket.handshake.address 
            });
            
            this.connectedClients.set(socket.id, {
                socket,
                connectedAt: new Date(),
                subscriptions: new Set()
            });
            
            // Send connection confirmation
            socket.emit('connection', {
                status: 'connected',
                socketId: socket.id,
                timestamp: new Date().toISOString()
            });
            
            // Handle subscription requests
            socket.on('subscribe', (channel) => {
                const client = this.connectedClients.get(socket.id);
                if (client) {
                    client.subscriptions.add(channel);
                    socket.join(channel);
                    logger.info(`Client ${socket.id} subscribed to ${channel}`);
                    socket.emit('subscribed', { channel, status: 'success' });
                }
            });
            
            socket.on('unsubscribe', (channel) => {
                const client = this.connectedClients.get(socket.id);
                if (client) {
                    client.subscriptions.delete(channel);
                    socket.leave(channel);
                    logger.info(`Client ${socket.id} unsubscribed from ${channel}`);
                    socket.emit('unsubscribed', { channel, status: 'success' });
                }
            });
            
            // Handle ping/pong for keepalive
            socket.on('ping', () => {
                socket.emit('pong', { timestamp: new Date().toISOString() });
            });
            
            socket.on('disconnect', (reason) => {
                logger.info('Client disconnected from Socket.io', { 
                    socketId: socket.id, 
                    reason 
                });
                this.connectedClients.delete(socket.id);
            });
        });
    }

    /**
     * Broadcast network stats update
     * @param {Object} stats - Network statistics
     */
    broadcastNetworkStats(stats) {
        const payload = {
            type: 'NETWORK_STATS',
            data: stats,
            timestamp: new Date().toISOString()
        };
        
        this.io.to('network-stats').emit('networkUpdate', payload);
        this.io.emit('networkStats', payload); // Also broadcast to all
    }

    /**
     * Broadcast alert
     * @param {Object} alert - Alert object
     */
    broadcastAlert(alert) {
        const payload = {
            type: 'ALERT',
            data: alert,
            timestamp: new Date().toISOString()
        };
        
        this.io.to('alerts').emit('alert', payload);
        
        // Critical alerts go to everyone
        if (alert.severity === 'critical' || alert.severity === 'high') {
            this.io.emit('criticalAlert', payload);
        }
    }

    /**
     * Broadcast suspicious activity
     * @param {Object} activity - Suspicious activity details
     */
    broadcastSuspiciousActivity(activity) {
        const payload = {
            type: 'SUSPICIOUS_ACTIVITY',
            data: activity,
            timestamp: new Date().toISOString()
        };
        
        this.io.to('security').emit('suspiciousActivity', payload);
    }

    /**
     * Broadcast connection update
     * @param {Array} connections - Active connections
     */
    broadcastConnections(connections) {
        const payload = {
            type: 'CONNECTIONS_UPDATE',
            data: connections,
            count: connections.length,
            timestamp: new Date().toISOString()
        };
        
        this.io.to('connections').emit('connectionsUpdate', payload);
    }

    /**
     * Broadcast bandwidth update
     * @param {Object} bandwidth - Bandwidth data
     */
    broadcastBandwidth(bandwidth) {
        const payload = {
            type: 'BANDWIDTH_UPDATE',
            data: bandwidth,
            timestamp: new Date().toISOString()
        };
        
        this.io.to('bandwidth').emit('bandwidthUpdate', payload);
    }

    /**
     * Start periodic broadcasting
     * @param {Function} dataProvider - Function that returns current data
     * @param {number} interval - Broadcast interval in ms (default: 3000)
     */
    startBroadcasting(dataProvider, interval = 3000) {
        if (this.broadcastInterval) {
            clearInterval(this.broadcastInterval);
        }
        
        this.isMonitoring = true;
        
        this.broadcastInterval = setInterval(async () => {
            try {
                const data = await dataProvider();
                if (data) {
                    this.broadcastNetworkStats(data);
                    
                    if (data.connections) {
                        this.broadcastConnections(data.connections);
                    }
                    
                    if (data.bandwidth) {
                        this.broadcastBandwidth(data.bandwidth);
                    }
                }
            } catch (error) {
                logger.error('Error broadcasting data', { error: error.message });
            }
        }, interval);
        
        logger.info('Socket.io broadcasting started', { interval });
    }

    /**
     * Stop broadcasting
     */
    stopBroadcasting() {
        this.isMonitoring = false;
        if (this.broadcastInterval) {
            clearInterval(this.broadcastInterval);
            this.broadcastInterval = null;
        }
        logger.info('Socket.io broadcasting stopped');
    }

    /**
     * Get WebSocket info for /ws-info endpoint
     * @returns {Object} WebSocket connection info
     */
    getWsInfo() {
        const clients = Array.from(this.connectedClients.values()).map(client => ({
            connectedAt: client.connectedAt,
            subscriptions: Array.from(client.subscriptions),
            duration: Date.now() - client.connectedAt.getTime()
        }));
        
        return {
            status: 'active',
            isMonitoring: this.isMonitoring,
            connectedClients: this.connectedClients.size,
            clientDetails: clients,
            availableChannels: [
                'network-stats',
                'alerts',
                'security',
                'connections',
                'bandwidth'
            ],
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Get IO instance for external use
     * @returns {Server} Socket.io server instance
     */
    getIO() {
        return this.io;
    }
}

module.exports = RealtimeService;
