#!/usr/bin/env node

const bcrypt = require('bcryptjs');

async function testPassword() {
    const storedHash = '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukx.LFvO6';
    const password = 'admin123';
    
    console.log('🔐 Testing password hash...');
    console.log('Password:', password);
    console.log('Hash:', storedHash);
    
    const isValid = await bcrypt.compare(password, storedHash);
    console.log('Password matches:', isValid);
    
    if (!isValid) {
        console.log('❌ Password hash is incorrect');
        // Generate correct hash
        const correctHash = await bcrypt.hash(password, 12);
        console.log('Correct hash should be:', correctHash);
    } else {
        console.log('✅ Password hash is correct');
    }
}

testPassword().catch(console.error);
