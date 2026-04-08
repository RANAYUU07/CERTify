// Honeypot / decoy endpoints — any hit = AUTO HIGH SEVERITY
export const DECOY_ENDPOINTS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.backup',
  '/.git/config',
  '/.git/HEAD',
  '/wp-admin',
  '/wp-admin/',
  '/wp-login.php',
  '/phpMyAdmin',
  '/phpmyadmin',
  '/pma',
  '/admin/config',
  '/config.php',
  '/backup.sql',
  '/backup.zip',
  '/backup.tar.gz',
  '/.htaccess',
  '/server-status',
  '/server-info',
  '/actuator/env',
  '/actuator/health',
  '/actuator/mappings',
  '/console',
  '/h2-console',
  '/manager/html',
  '/jmx-console',
  '/web-console',
  '/admin/',
  '/administrator/',
  '/adminer.php',
  '/shell.php',
  '/webshell.php',
  '/c99.php',
  '/r57.php',
  '/eval.php',
  '/xmlrpc.php',
  '/.DS_Store',
  '/composer.json',
  '/package.json',
  '/yarn.lock',
  '/Gemfile',
  '/requirements.txt',
]

// Check if a path matches any decoy endpoint
export function isDecoyEndpoint(path) {
  const cleanPath = path.split('?')[0].toLowerCase()
  return DECOY_ENDPOINTS.some(decoy => {
    const d = decoy.toLowerCase()
    return cleanPath === d || cleanPath.startsWith(d + '/')
  })
}
