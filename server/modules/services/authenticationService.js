class AuthenticationService {
    analyzeAuthentication(parsed) {
        const auth = {
            spf: { status: 'unknown', details: null },
            dkim: { status: 'unknown', details: null },
            dmarc: { status: 'unknown', details: null }
        };
        
        const authResultsHeader = parsed.headers.get('authentication-results');
        if (authResultsHeader) {
            const authText = authResultsHeader.toLowerCase();
            
            if (authText.includes('spf=pass')) {
                auth.spf = { status: 'pass', details: 'SPF verification passed' };
            } else if (authText.includes('spf=fail') || authText.includes('spf=softfail')) {
                auth.spf = { status: 'fail', details: 'SPF verification failed' };
            }
            
            if (authText.includes('dkim=pass')) {
                auth.dkim = { status: 'pass', details: 'DKIM signature verified' };
            } else if (authText.includes('dkim=fail') || authText.includes('dkim=permerror')) {
                auth.dkim = { status: 'fail', details: 'DKIM verification failed' };
            }
            
            if (authText.includes('dmarc=pass')) {
                auth.dmarc = { status: 'pass', details: 'DMARC policy satisfied' };
            } else if (authText.includes('dmarc=fail') || authText.includes('dmarc=none')) {
                auth.dmarc = { status: 'fail', details: 'DMARC verification failed' };
            }
        }
        
        const spfHeader = parsed.headers.get('received-spf');
        if (spfHeader && auth.spf.status === 'unknown') {
            if (spfHeader.toLowerCase().includes('pass')) {
                auth.spf = { status: 'pass', details: 'SPF verification passed' };
            } else if (spfHeader.toLowerCase().includes('fail')) {
                auth.spf = { status: 'fail', details: 'SPF verification failed' };
            }
        }
        
        const dkimHeader = parsed.headers.get('dkim-signature');
        if (dkimHeader && auth.dkim.status === 'unknown') {
            auth.dkim = { status: 'pass', details: 'DKIM signature present' };
        }
        
        return auth;
    }

    getAuthenticationScore(auth) {
        let score = 0;
        
        if (auth.spf.status === 'fail') score -= 20;
        if (auth.dkim.status === 'fail') score -= 15;
        if (auth.dmarc.status === 'fail') score -= 15;
        
        return score;
    }
}

module.exports = AuthenticationService;
