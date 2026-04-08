/**
 * Mock geo data for all IPs in sampleLog.js
 * Used in Demo Mode to bypass real API calls — ensures demo works offline
 * and for the impossible Mumbai→Moscow geo-velocity anomaly demonstration
 */
export const MOCK_GEO_DATA = {
  // Normal traffic IPs (Indian ISPs)
  '103.12.45.67':  { ip: '103.12.45.67',  country_name: 'India',       city: 'Mumbai',      latitude: 19.0760, longitude: 72.8777, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '106.51.22.88':  { ip: '106.51.22.88',  country_name: 'India',       city: 'Bengaluru',   latitude: 12.9716, longitude: 77.5946, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '117.96.230.21': { ip: '117.96.230.21', country_name: 'India',       city: 'Delhi',       latitude: 28.7041, longitude: 77.1025, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '122.167.41.55': { ip: '122.167.41.55', country_name: 'India',       city: 'Hyderabad',   latitude: 17.3850, longitude: 78.4867, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '106.79.20.14':  { ip: '106.79.20.14',  country_name: 'India',       city: 'Chennai',     latitude: 13.0827, longitude: 80.2707, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '49.207.134.22': { ip: '49.207.134.22', country_name: 'India',       city: 'Pune',        latitude: 18.5204, longitude: 73.8567, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '103.244.133.55':{ ip: '103.244.133.55',country_name: 'India',       city: 'Kolkata',     latitude: 22.5726, longitude: 88.3639, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '117.55.234.78': { ip: '117.55.234.78', country_name: 'India',       city: 'Ahmedabad',   latitude: 23.0225, longitude: 72.5714, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '182.73.120.34': { ip: '182.73.120.34', country_name: 'India',       city: 'Jaipur',      latitude: 26.9124, longitude: 75.7873, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '59.144.0.99':   { ip: '59.144.0.99',   country_name: 'India',       city: 'Surat',       latitude: 21.1702, longitude: 72.8311, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '223.186.41.56': { ip: '223.186.41.56', country_name: 'India',       city: 'Lucknow',     latitude: 26.8467, longitude: 80.9462, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '115.240.29.133':{ ip: '115.240.29.133',country_name: 'India',       city: 'Patna',       latitude: 25.5941, longitude: 85.1376, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '1.22.33.44':    { ip: '1.22.33.44',    country_name: 'India',       city: 'Bhopal',      latitude: 23.2599, longitude: 77.4126, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '27.6.254.32':   { ip: '27.6.254.32',   country_name: 'India',       city: 'Nagpur',      latitude: 21.1458, longitude: 79.0882, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '182.71.99.2':   { ip: '182.71.99.2',   country_name: 'India',       city: 'Indore',      latitude: 22.7196, longitude: 75.8577, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '14.139.125.15': { ip: '14.139.125.15', country_name: 'India',       city: 'Visakhapatnam',latitude: 17.6868,longitude: 83.2185, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '202.88.16.18':  { ip: '202.88.16.18',  country_name: 'India',       city: 'Kochi',       latitude: 9.9312,  longitude: 76.2673, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  '61.246.223.1':  { ip: '61.246.223.1',  country_name: 'India',       city: 'Coimbatore',  latitude: 11.0168, longitude: 76.9558, org: 'AS18101 BSNL', asn: 'AS18101', proxy: false, hosting: false, tor: false },
  '203.192.246.10':{ ip: '203.192.246.10',country_name: 'India',       city: 'Chandigarh',  latitude: 30.7333, longitude: 76.7794, org: 'AS24560 Airtel', asn: 'AS24560', proxy: false, hosting: false, tor: false },
  '125.17.147.32': { ip: '125.17.147.32', country_name: 'India',       city: 'Vadodara',    latitude: 22.3072, longitude: 73.1812, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },

  // Attacker IPs
  '185.220.101.45':{ ip: '185.220.101.45',country_name: 'Russia',      city: 'Moscow',      latitude: 55.7558, longitude: 37.6176, org: 'AS215699 Tor Exit', asn: 'AS215699', proxy: true,  hosting: false, tor: true  },
  '45.142.212.100':{ ip: '45.142.212.100',country_name: 'Netherlands', city: 'Amsterdam',   latitude: 52.3676, longitude: 4.9041,  org: 'AS209103 HostRoyale', asn: 'AS209103', proxy: true,  hosting: true,  tor: false },
  '91.108.4.15':   { ip: '91.108.4.15',   country_name: 'Germany',     city: 'Frankfurt',   latitude: 50.1109, longitude: 8.6821,  org: 'AS24940 Hetzner', asn: 'AS24940', proxy: false, hosting: true,  tor: false },
  '194.165.16.11': { ip: '194.165.16.11', country_name: 'Moldova',     city: 'Chisinau',    latitude: 47.0105, longitude: 28.8638, org: 'AS51430 ComIntergroup', asn: 'AS51430', proxy: true,  hosting: false, tor: false },
  '162.142.125.12':{ ip: '162.142.125.12',country_name: 'United States','city': 'Kansas City',latitude: 39.0997, longitude: -94.5786,org: 'AS5678 Hurricane Electric', asn: 'AS5678', proxy: false, hosting: true,  tor: false },
  '80.82.77.39':   { ip: '80.82.77.39',   country_name: 'Netherlands', city: 'Amsterdam',   latitude: 52.3676, longitude: 4.9041,  org: 'AS16276 OVH', asn: 'AS16276', proxy: true,  hosting: true,  tor: false },
  '193.32.162.15': { ip: '193.32.162.15', country_name: 'Russia',      city: 'Saint Petersburg',latitude: 59.9343,longitude: 30.3351,org: 'AS49505 Selectel', asn: 'AS49505', proxy: false, hosting: true,  tor: false },
  '77.91.77.6':    { ip: '77.91.77.6',    country_name: 'Russia',      city: 'Moscow',      latitude: 55.7558, longitude: 37.6176, org: 'AS48416 Hosting', asn: 'AS48416', proxy: true,  hosting: true,  tor: false },
  '45.33.32.156':  { ip: '45.33.32.156',  country_name: 'United States','city': 'Atlanta',  latitude: 33.7490, longitude: -84.3880,org: 'AS63949 Linode', asn: 'AS63949', proxy: false, hosting: true,  tor: false },

  // GEO-VELOCITY pair ⭐
  // Mumbai IP - hits /api/transfer at T=0
  '103.26.228.15': { ip: '103.26.228.15', country_name: 'India',       city: 'Mumbai',      latitude: 19.0760, longitude: 72.8777, org: 'AS55836 Reliance Jio', asn: 'AS55836', proxy: false, hosting: false, tor: false },
  // Moscow IP - hits SAME endpoint 2 seconds later — 5,887 km in 2s = 2,943 km/s >> 300 threshold
  '95.213.192.120':{ ip: '95.213.192.120',country_name: 'Russia',      city: 'Moscow',      latitude: 55.7558, longitude: 37.6176, org: 'AS8359 Mobile TeleSystems', asn: 'AS8359', proxy: false, hosting: false, tor: false },

  // Distributed attack IPs (198.51.100.x) — all from China (anonymized)
  ...Object.fromEntries(
    Array.from({ length: 30 }, (_, i) => i + 1).map(i => [
      `198.51.100.${i}`,
      {
        ip: `198.51.100.${i}`,
        country_name: 'China',
        city: 'Beijing',
        latitude: 39.9042 + (Math.random() - 0.5) * 2,
        longitude: 116.4074 + (Math.random() - 0.5) * 2,
        org: `AS4134 China Telecom`,
        asn: 'AS4134',
        proxy: i % 3 === 0,
        hosting: i % 4 === 0,
        tor: false,
      }
    ])
  ),

  // Sequential IPs (203.0.113.x) — from various locations
  ...Object.fromEntries(
    Array.from({ length: 8 }, (_, i) => i + 1).map(i => [
      `203.0.113.${i}`,
      {
        ip: `203.0.113.${i}`,
        country_name: ['Russia', 'China', 'Vietnam', 'Ukraine', 'Romania', 'Brazil', 'South Korea', 'Iran'][i - 1],
        city: ['Moscow', 'Shanghai', 'Hanoi', 'Kyiv', 'Bucharest', 'São Paulo', 'Seoul', 'Tehran'][i - 1],
        latitude: [55.75, 31.22, 21.02, 50.45, 44.43, -23.55, 37.56, 35.69][i - 1],
        longitude: [37.61, 121.45, 105.83, 30.52, 26.10, -46.63, 126.97, 51.38][i - 1],
        org: `AS${12000 + i} Various ISP`,
        asn: `AS${12000 + i}`,
        proxy: false,
        hosting: false,
        tor: false,
      }
    ])
  ),
}
