// SecureSys Auditor - Load Testing Script (k6)
// Run with: k6 run --vus 50 --duration 5m load-test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomItem, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const scanSubmissionTime = new Trend('scan_submission_time');
const webhookDeliveryTime = new Trend('webhook_delivery_time');
const scanCount = new Counter('scans_submitted');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'https://api.securesys.io';
const API_KEY = __ENV.API_KEY || 'test-api-key';

// Test scenarios
export const options = {
  scenarios: {
    // Scenario 1: Normal load - simulates typical usage
    normal_load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 20 },  // Ramp up
        { duration: '5m', target: 20 },  // Steady state
        { duration: '2m', target: 0 },   // Ramp down
      ],
      gracefulRampDown: '30s',
    },
    
    // Scenario 2: Spike test - sudden traffic surge
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 10 },   // Baseline
        { duration: '30s', target: 100 }, // Spike!
        { duration: '2m', target: 100 },  // Sustained spike
        { duration: '30s', target: 10 },  // Recovery
        { duration: '1m', target: 0 },    // Ramp down
      ],
      startTime: '10m',  // Start after normal_load
    },
    
    // Scenario 3: Stress test - find breaking point
    stress_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { duration: '2m', target: 50 },   // Ramp up
        { duration: '5m', target: 100 },  // High load
        { duration: '2m', target: 150 },  // Stress point
        { duration: '2m', target: 0 },    // Recovery
      ],
      startTime: '20m',  // Start after spike_test
    },
  },
  
  thresholds: {
    // Response time thresholds
    http_req_duration: ['p(95)<2000', 'p(99)<5000'],  // 95% under 2s, 99% under 5s
    
    // Error rate thresholds
    errors: ['rate<0.05'],  // Less than 5% errors
    
    // Custom metric thresholds
    scan_submission_time: ['p(95)<3000'],  // Scan submissions under 3s
  },
};

// Test data
const systemHosts = [
  'webserver-01.example.com',
  'database-01.example.com',
  'cache-01.example.com',
  'worker-01.example.com',
  'api-01.example.com',
];

const scanTypes = ['vulnerability', 'compliance', 'configuration'];
const severities = ['critical', 'high', 'medium', 'low', 'info'];

// Generate realistic scan payload
function generateScanPayload() {
  const hostname = randomItem(systemHosts);
  const numFindings = randomIntBetween(5, 50);
  
  const findings = [];
  for (let i = 0; i < numFindings; i++) {
    findings.push({
      title: `Finding ${i + 1}: ${randomItem(['CVE-2023-1234', 'CWE-79', 'OWASP-A01', 'Missing patch'])}`,
      severity: randomItem(severities),
      description: 'Detailed description of the security finding.',
      recommendation: 'Recommended remediation steps.',
      affected_component: `/usr/local/bin/app-${randomIntBetween(1, 10)}`,
    });
  }
  
  return {
    hostname: hostname,
    scan_type: randomItem(scanTypes),
    agent_version: '2.0.0',
    started_at: new Date(Date.now() - randomIntBetween(60000, 300000)).toISOString(),
    completed_at: new Date().toISOString(),
    findings: findings,
    metadata: {
      os: 'Ubuntu 22.04',
      kernel: '5.15.0-generic',
      agent_id: `agent-${randomIntBetween(1, 100)}`,
    },
  };
}

// Setup function - runs once at start
export function setup() {
  // Verify API is accessible
  const res = http.get(`${BASE_URL}/api/v1/health/`);
  check(res, {
    'Health check passes': (r) => r.status === 200,
  });
  
  return { startTime: Date.now() };
}

// Main test function
export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${API_KEY}`,
    'X-Request-ID': `k6-${__VU}-${__ITER}-${Date.now()}`,
  };
  
  group('Health Checks', function () {
    const res = http.get(`${BASE_URL}/api/v1/health/`, { headers });
    check(res, {
      'Health check status 200': (r) => r.status === 200,
      'Health check has version': (r) => JSON.parse(r.body).version !== undefined,
    });
    errorRate.add(res.status !== 200);
  });
  
  group('Scan Submission', function () {
    const payload = generateScanPayload();
    const startTime = Date.now();
    
    const res = http.post(
      `${BASE_URL}/api/v1/scans/`,
      JSON.stringify(payload),
      { headers }
    );
    
    const duration = Date.now() - startTime;
    scanSubmissionTime.add(duration);
    
    const success = check(res, {
      'Scan submission status 201': (r) => r.status === 201,
      'Scan has ID': (r) => {
        try {
          return JSON.parse(r.body).id !== undefined;
        } catch {
          return false;
        }
      },
      'Response time < 3s': (r) => r.timings.duration < 3000,
    });
    
    errorRate.add(!success);
    
    if (success) {
      scanCount.add(1);
    }
    
    sleep(randomIntBetween(1, 3));
  });
  
  group('List Scans', function () {
    const res = http.get(`${BASE_URL}/api/v1/scans/?page=1&page_size=20`, { headers });
    check(res, {
      'List scans status 200': (r) => r.status === 200,
      'Returns array of scans': (r) => {
        try {
          const body = JSON.parse(r.body);
          return Array.isArray(body.results);
        } catch {
          return false;
        }
      },
    });
    errorRate.add(res.status !== 200);
  });
  
  group('Get Scan Details', function () {
    // First get a scan ID
    const listRes = http.get(`${BASE_URL}/api/v1/scans/?page=1&page_size=1`, { headers });
    if (listRes.status === 200) {
      try {
        const scans = JSON.parse(listRes.body).results;
        if (scans.length > 0) {
          const scanId = scans[0].id;
          const detailRes = http.get(`${BASE_URL}/api/v1/scans/${scanId}/`, { headers });
          check(detailRes, {
            'Scan detail status 200': (r) => r.status === 200,
            'Has findings count': (r) => JSON.parse(r.body).findings_count !== undefined,
          });
          errorRate.add(detailRes.status !== 200);
        }
      } catch (e) {
        console.error('Error parsing scan list:', e);
      }
    }
  });
  
  group('Dashboard Stats', function () {
    const res = http.get(`${BASE_URL}/api/v1/dashboard/stats/`, { headers });
    check(res, {
      'Dashboard stats status 200': (r) => r.status === 200,
    });
    errorRate.add(res.status !== 200);
  });
  
  sleep(randomIntBetween(2, 5));
}

// Teardown function - runs once at end
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Test completed in ${duration}s`);
}

// Handle test results
export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: '  ', enableColors: true }),
    'load-test-results.json': JSON.stringify(data, null, 2),
  };
}

function textSummary(data, options) {
  return `
================================================================================
SecureSys Auditor Load Test Results
================================================================================

Duration: ${data.state.testRunDurationMs / 1000}s
VUs Max:  ${data.metrics.vus_max?.values?.max || 'N/A'}

HTTP Requests:
  Total:    ${data.metrics.http_reqs?.values?.count || 0}
  Rate:     ${(data.metrics.http_reqs?.values?.rate || 0).toFixed(2)}/s

Response Times:
  Avg:      ${(data.metrics.http_req_duration?.values?.avg || 0).toFixed(2)}ms
  P95:      ${(data.metrics.http_req_duration?.values['p(95)'] || 0).toFixed(2)}ms
  P99:      ${(data.metrics.http_req_duration?.values['p(99)'] || 0).toFixed(2)}ms
  Max:      ${(data.metrics.http_req_duration?.values?.max || 0).toFixed(2)}ms

Errors:
  Rate:     ${((data.metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%

Custom Metrics:
  Scans Submitted:    ${data.metrics.scans_submitted?.values?.count || 0}
  Scan Time (P95):    ${(data.metrics.scan_submission_time?.values['p(95)'] || 0).toFixed(2)}ms

Thresholds:
${Object.entries(data.metrics)
  .filter(([_, m]) => m.thresholds)
  .map(([name, m]) => {
    const passed = Object.values(m.thresholds).every(t => t.ok);
    return `  ${passed ? '✓' : '✗'} ${name}: ${passed ? 'PASSED' : 'FAILED'}`;
  })
  .join('\n')}

================================================================================
`;
}
