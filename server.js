// Cybersecurity Jobs API Server for Railway Deployment
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cron = require('node-cron');

// Initialize Express app
const app = express();
app.use(cors());
app.use(express.json());

// Configuration - Uses environment variables for security
const CONFIG = {
    adzuna: {
        appId: process.env.ADZUNA_APP_ID || 'e9c428e1',
        appKey: process.env.ADZUNA_APP_KEY || '08b9f27b0b5ea186022614f1844d054a',
        baseUrl: 'https://api.adzuna.com/v1/api/jobs'
    },
    port: process.env.PORT || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
    maxJobAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    newJobThreshold: 6 * 60 * 60 * 1000, // 6 hours
    fetchInterval: process.env.FETCH_INTERVAL || '0 */6 * * *' // Every 6 hours
};

// Job categories with search terms
const JOB_CATEGORIES = {
    'general': {
        terms: ['cybersecurity', 'information security', 'infosec', 'security engineer', 'security analyst'],
        location: 'us'
    },
    'vulnerability': {
        terms: ['vulnerability', 'vuln mgmt', 'VM', 'patch management', 'Tenable', 'Qualys', 'Nessus', 'Rapid7'],
        location: 'us'
    },
    'iam': {
        terms: ['IAM', 'Identity and Access Management', 'Identity Governance', 'IGA', 'PAM', 'Okta', 'Entra ID', 'Azure AD'],
        location: 'us'
    },
    'incident-response': {
        terms: ['incident response', 'DFIR', 'SOC analyst', 'threat hunter', 'blue team', 'SIEM', 'SOAR'],
        location: 'us'
    },
    'grc': {
        terms: ['GRC', 'governance risk compliance', 'risk analyst', 'ISO 27001', 'NIST 800-53', 'SOC 2'],
        location: 'us'
    },
    'pci': {
        terms: ['PCI DSS', 'QSA', 'payment card', 'PCI compliance'],
        location: 'us'
    },
    'awareness': {
        terms: ['security awareness', 'security training', 'phishing simulation'],
        location: 'us'
    },
    'third-party': {
        terms: ['third party risk', 'vendor risk', 'TPRM', 'supplier risk'],
        location: 'us'
    },
    'hipaa': {
        terms: ['HIPAA', 'healthcare security', 'PHI', 'HITRUST'],
        location: 'us'
    },
    'leadership': {
        terms: ['CISO', 'Head of Security', 'Director of Security', 'Security Manager'],
        location: 'us'
    },
    'emerging': {
        terms: ['AI security', 'ML security', 'model security', 'LLM security', 'MLOps security', 'cloud security', 'DevSecOps', 'OT security', 'ICS security'],
        location: 'us'
    },
    'us-remote': {
        terms: ['cybersecurity', 'information security', 'infosec', 'security engineer', 'security analyst'],
        location: 'us',
        remote: true
    },
    'uk-remote': {
        terms: ['cybersecurity', 'information security', 'infosec', 'security engineer', 'security analyst'],
        location: 'gb'
    },
    'au-remote': {
        terms: ['cybersecurity', 'information security', 'infosec', 'security engineer', 'security analyst'],
        location: 'au'
    }
};

// In-memory database (will be replaced with PostgreSQL in Railway)
let jobsDatabase = {
    jobs: [],
    lastUpdated: null,
    totalFetched: 0,
    stats: {
        total: 0,
        new: 0,
        remote: 0,
        companies: 0
    },
    fetchLog: [],
    serverStartTime: new Date().toISOString()
};

// Utility Functions
function generateJobId(job) {
    const crypto = require('crypto');
    const baseString = `${job.title}-${job.company?.display_name}-${job.created}`.toLowerCase();
    return crypto.createHash('md5').update(baseString).digest('hex');
}

function isJobNew(createdDate) {
    if (!createdDate) return false;
    const jobDate = new Date(createdDate);
    const now = new Date();
    return (now - jobDate) < CONFIG.newJobThreshold;
}

function isJobExpired(createdDate) {
    if (!createdDate) return true;
    const jobDate = new Date(createdDate);
    const now = new Date();
    return (now - jobDate) > CONFIG.maxJobAge;
}

function categorizeJob(title, description, location) {
    const text = `${title} ${description} ${location}`.toLowerCase();
    
    if (text.includes('iam') || text.includes('identity')) return 'iam';
    if (text.includes('incident') || text.includes('soc')) return 'incident-response';
    if (text.includes('grc') || text.includes('compliance')) return 'grc';
    if (text.includes('vulnerability') || text.includes('penetration')) return 'vulnerability';
    if (text.includes('ciso') || text.includes('director') || text.includes('manager')) return 'leadership';
    if (text.includes('cloud') || text.includes('devsecops') || text.includes('ai security')) return 'emerging';
    if (text.includes('awareness') || text.includes('training')) return 'awareness';
    if (text.includes('third party') || text.includes('vendor risk')) return 'third-party';
    if (text.includes('hipaa') || text.includes('healthcare')) return 'hipaa';
    if (text.includes('pci')) return 'pci';
    
    if (location && location.toLowerCase().includes('remote')) {
        if (location.toLowerCase().includes('uk')) return 'uk-remote';
        if (location.toLowerCase().includes('au')) return 'au-remote';
        return 'us-remote';
    }
    
    return 'general';
}

function extractRequirements(description) {
    if (!description) return 'See job description';
    
    const certifications = ['CISSP', 'CISM', 'CISA', 'Security+', 'GSEC', 'CEH', 'GCIH', 'GCFA', 'GPEN', 'OSCP', 'CCSP', 'CRISC'];
    const found = certifications.filter(cert => 
        description.toLowerCase().includes(cert.toLowerCase())
    );
    return found.length > 0 ? found.join(', ') : 'Security experience required';
}

function isRemoteJob(title, description, location) {
    const text = `${title} ${description} ${location}`.toLowerCase();
    const remoteKeywords = ['remote', 'work from home', 'wfh', 'telecommute', 'distributed', 'anywhere'];
    return remoteKeywords.some(keyword => text.includes(keyword));
}

function formatSalary(min, max) {
    if (!min && !max) return 'Salary not disclosed';
    if (min && max) return `$${min.toLocaleString()} - $${max.toLocaleString()}`;
    if (min) return `From $${min.toLocaleString()}`;
    if (max) return `Up to $${max.toLocaleString()}`;
    return 'Competitive salary';
}

// Adzuna API Functions
async function fetchJobsFromAdzuna(category, page = 1) {
    const categoryConfig = JOB_CATEGORIES[category];
    if (!categoryConfig) return [];

    const searchTerms = categoryConfig.terms.join(' OR ');
    const location = categoryConfig.location;
    
    const params = {
        app_id: CONFIG.adzuna.appId,
        app_key: CONFIG.adzuna.appKey,
        results_per_page: 50,
        what: searchTerms,
        where: location,
        page: page,
        sort_by: 'date',
        max_days_old: 7
    };

    if (categoryConfig.remote) {
        params.part_time = '0';
        params.permanent = '1';
    }

    try {
        const response = await axios.get(`${CONFIG.adzuna.baseUrl}/${location}/search/1`, { params });
        
        console.log(`✅ [${new Date().toISOString()}] Fetched ${response.data.results?.length || 0} jobs for category: ${category}`);
        
        // Log successful fetch
        jobsDatabase.fetchLog.push({
            category,
            timestamp: new Date().toISOString(),
            jobsFound: response.data.results?.length || 0,
            status: 'success'
        });
        
        return response.data.results || [];
        
    } catch (error) {
        console.error(`❌ [${new Date().toISOString()}] Error fetching jobs for ${category}:`, error.message);
        
        // Log failed fetch
        jobsDatabase.fetchLog.push({
            category,
            timestamp: new Date().toISOString(),
            jobsFound: 0,
            status: 'error',
            error: error.message
        });
        
        return [];
    }
}

async function fetchAllCybersecurityJobs() {
    console.log(`🔄 [${new Date().toISOString()}] Starting comprehensive cybersecurity job fetch...`);
    
    const allJobs = [];
    let totalFetched = 0;

    // Fetch jobs from each category
    for (const [categoryKey, categoryConfig] of Object.entries(JOB_CATEGORIES)) {
        try {
            const jobs = await fetchJobsFromAdzuna(categoryKey);
            
            const processedJobs = jobs.map(job => ({
                id: generateJobId(job),
                title: job.title || 'Untitled Position',
                company: job.company?.display_name || 'Company Not Listed',
                description: job.description || '',
                location: job.location?.display_name || 'Location not specified',
                salary: formatSalary(job.salary_min, job.salary_max),
                url: job.redirect_url || job.url || '#',
                created: job.created || new Date().toISOString(),
                category: categorizeJob(job.title, job.description, job.location?.display_name),
                isNew: isJobNew(job.created),
                remote: isRemoteJob(job.title, job.description, job.location?.display_name),
                requirements: extractRequirements(job.description),
                source: 'Adzuna API',
                fetchedAt: new Date().toISOString()
            }));

            allJobs.push(...processedJobs);
            totalFetched += jobs.length;
            
            // Rate limiting - wait 1 second between API calls
            await new Promise(resolve => setTimeout(resolve, 1000));
            
        } catch (error) {
            console.error(`❌ Failed to fetch category ${categoryKey}:`, error.message);
        }
    }

    console.log(`✅ [${new Date().toISOString()}] Total jobs fetched: ${totalFetched}`);
    return allJobs;
}

// Database Operations
function removeDuplicateJobs(jobs) {
    const seen = new Map();
    const uniqueJobs = [];

    for (const job of jobs) {
        const key = `${job.title.toLowerCase()}-${job.company.toLowerCase()}`;
        
        if (!seen.has(key)) {
            seen.set(key, job);
            uniqueJobs.push(job);
        } else {
            const existingJob = seen.get(key);
            if (new Date(job.created) > new Date(existingJob.created)) {
                const index = uniqueJobs.findIndex(j => j.id === existingJob.id);
                if (index !== -1) {
                    uniqueJobs[index] = job;
                    seen.set(key, job);
                }
            }
        }
    }

    console.log(`🔧 [${new Date().toISOString()}] Removed ${jobs.length - uniqueJobs.length} duplicate jobs`);
    return uniqueJobs;
}

function removeExpiredJobs(jobs) {
    const validJobs = jobs.filter(job => !isJobExpired(job.created));
    const removedCount = jobs.length - validJobs.length;
    
    if (removedCount > 0) {
        console.log(`🗑️ [${new Date().toISOString()}] Removed ${removedCount} expired jobs (older than 7 days)`);
    }
    
    return validJobs;
}

function markNewJobs(jobs) {
    jobs.forEach(job => {
        job.isNew = isJobNew(job.created);
    });
    
    const newJobsCount = jobs.filter(job => job.isNew).length;
    console.log(`🆕 [${new Date().toISOString()}] Marked ${newJobsCount} jobs as new`);
    
    return jobs;
}

function calculateStats(jobs) {
    const uniqueCompanies = new Set(jobs.map(job => job.company)).size;
    const newJobs = jobs.filter(job => job.isNew).length;
    const remoteJobs = jobs.filter(job => job.remote).length;

    return {
        total: jobs.length,
        new: newJobs,
        remote: remoteJobs,
        companies: uniqueCompanies
    };
}

async function updateJobsDatabase() {
    console.log(`\n🚀 [${new Date().toISOString()}] Starting scheduled job update...`);
    
    try {
        // Fetch fresh jobs
        const freshJobs = await fetchAllCybersecurityJobs();
        
        // Combine with existing jobs
        const allJobs = [...jobsDatabase.jobs, ...freshJobs];
        
        // Remove duplicates
        const uniqueJobs = removeDuplicateJobs(allJobs);
        
        // Remove expired jobs
        const validJobs = removeExpiredJobs(uniqueJobs);
        
        // Mark new jobs
        const finalJobs = markNewJobs(validJobs);
        
        // Sort by date (newest first)
        finalJobs.sort((a, b) => new Date(b.created) - new Date(a.created));
        
        // Update database
        jobsDatabase = {
            ...jobsDatabase,
            jobs: finalJobs,
            lastUpdated: new Date().toISOString(),
            totalFetched: freshJobs.length,
            stats: calculateStats(finalJobs)
        };
        
        // Keep only last 100 fetch log entries
        if (jobsDatabase.fetchLog.length > 100) {
            jobsDatabase.fetchLog = jobsDatabase.fetchLog.slice(-100);
        }
        
        console.log(`✅ [${new Date().toISOString()}] Job database updated successfully!`);
        console.log(`📊 Stats: ${jobsDatabase.stats.total} total, ${jobsDatabase.stats.new} new, ${jobsDatabase.stats.remote} remote`);
        
    } catch (error) {
        console.error(`❌ [${new Date().toISOString()}] Error updating jobs database:`, error);
    }
}

// API Routes
app.get('/', (req, res) => {
    res.json({
        message: 'Cybersecurity Jobs API Server',
        version: '1.0.0',
        status: 'running',
        serverStartTime: jobsDatabase.serverStartTime,
        lastUpdated: jobsDatabase.lastUpdated,
        totalJobs: jobsDatabase.stats.total,
        endpoints: {
            'GET /api/jobs': 'Fetch jobs with filtering and pagination',
            'GET /api/stats': 'Get database statistics',
            'GET /api/categories': 'Get jobs by category',
            'GET /health': 'Health check',
            'POST /api/admin/update': 'Manual update trigger'
        }
    });
});

app.get('/api/jobs', (req, res) => {
    const { category, search, page = 1, limit = 50 } = req.query;
    
    let filteredJobs = jobsDatabase.jobs;
    
    // Filter by category
    if (category && category !== 'all') {
        filteredJobs = filteredJobs.filter(job => job.category === category);
    }
    
    // Filter by search term
    if (search) {
        const searchLower = search.toLowerCase();
        filteredJobs = filteredJobs.filter(job => 
            job.title.toLowerCase().includes(searchLower) ||
            job.company.toLowerCase().includes(searchLower) ||
            job.description.toLowerCase().includes(searchLower) ||
            job.location.toLowerCase().includes(searchLower)
        );
    }
    
    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedJobs = filteredJobs.slice(startIndex, endIndex);
    
    res.json({
        success: true,
        data: {
            jobs: paginatedJobs,
            pagination: {
                currentPage: parseInt(page),
                totalJobs: filteredJobs.length,
                totalPages: Math.ceil(filteredJobs.length / limit),
                hasNext: endIndex < filteredJobs.length,
                hasPrev: page > 1
            },
            stats: jobsDatabase.stats,
            lastUpdated: jobsDatabase.lastUpdated
        }
    });
});

app.get('/api/stats', (req, res) => {
    res.json({
        success: true,
        data: {
            stats: jobsDatabase.stats,
            lastUpdated: jobsDatabase.lastUpdated,
            totalFetched: jobsDatabase.totalFetched,
            serverStartTime: jobsDatabase.serverStartTime,
            fetchLogEntries: jobsDatabase.fetchLog.length
        }
    });
});

app.get('/api/categories', (req, res) => {
    const categoryCounts = {};
    
    Object.keys(JOB_CATEGORIES).forEach(category => {
        categoryCounts[category] = jobsDatabase.jobs.filter(job => job.category === category).length;
    });
    
    res.json({
        success: true,
        data: categoryCounts
    });
});

app.get('/api/logs', (req, res) => {
    const { limit = 50 } = req.query;
    const recentLogs = jobsDatabase.fetchLog.slice(-parseInt(limit));
    
    res.json({
        success: true,
        data: {
            logs: recentLogs,
            totalEntries: jobsDatabase.fetchLog.length
        }
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        jobsCount: jobsDatabase.jobs.length,
        lastUpdated: jobsDatabase.lastUpdated,
        memoryUsage: process.memoryUsage(),
        environment: CONFIG.nodeEnv
    });
});

// Admin endpoint to manually trigger update
app.post('/api/admin/update', async (req, res) => {
    try {
        console.log(`🔄 [${new Date().toISOString()}] Manual update triggered via API`);
        await updateJobsDatabase();
        res.json({
            success: true,
            message: 'Job database updated successfully',
            stats: jobsDatabase.stats,
            lastUpdated: jobsDatabase.lastUpdated
        });
    } catch (error) {
        console.error(`❌ Manual update failed:`, error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Express error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        availableEndpoints: ['/api/jobs', '/api/stats', '/api/categories', '/health']
    });
});

// Schedule automatic updates
console.log(`⏰ Scheduling automatic updates with cron: ${CONFIG.fetchInterval}`);
cron.schedule(CONFIG.fetchInterval, () => {
    console.log(`\n⏰ [${new Date().toISOString()}] Scheduled job update triggered...`);
    updateJobsDatabase();
});

// Initialize server
async function startServer() {
    console.log(`🚀 Starting Cybersecurity Jobs API Server...`);
    console.log(`🌍 Environment: ${CONFIG.nodeEnv}`);
    console.log(`🔑 Using Adzuna App ID: ${CONFIG.adzuna.appId}`);
    
    // Initial job fetch
    console.log('🔄 Performing initial job fetch...');
    await updateJobsDatabase();
    
    // Start server
    app.listen(CONFIG.port, () => {
        console.log(`\n🚀 Server running on port ${CONFIG.port}`);
        console.log(`📊 Database initialized with ${jobsDatabase.jobs.length} jobs`);
        console.log(`🔗 API Endpoints:`);
        console.log(`   GET  /api/jobs       - Fetch jobs with filtering`);
        console.log(`   GET  /api/stats      - Get database statistics`);
        console.log(`   GET  /api/categories - Get jobs by category`);
        console.log(`   GET  /api/logs       - Get fetch logs`);
        console.log(`   GET  /health         - Health check`);
        console.log(`   POST /api/admin/update - Manual update trigger`);
        console.log(`\n⏰ Automatic updates scheduled: ${CONFIG.fetchInterval}`);
        console.log(`\n🌐 Server ready at: http://localhost:${CONFIG.port}`);
    });
}

// Error handling
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Start the server
startServer().catch(console.error);

module.exports = app;
