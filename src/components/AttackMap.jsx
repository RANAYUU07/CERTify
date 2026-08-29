import { useEffect } from 'react'
import { MapContainer, TileLayer, CircleMarker, Popup, Polyline, useMap } from 'react-leaflet'
import L from 'leaflet'
import useCertifyStore from '../store/certifyStore'
import { getGeoVelocityArcs } from '../engine/layer2_rotation.js'

// Fix Leaflet default icon paths (broken in Vite)
delete L.Icon.Default.prototype._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
})

const SEVERITY_MARKER_STYLES = {
  CRITICAL: { color: '#FF1744', fillColor: '#FF1744', radius: 10 },
  HIGH:     { color: '#FF6D00', fillColor: '#FF6D00', radius: 8  },
  MEDIUM:   { color: '#DFE104', fillColor: '#DFE104', radius: 6  },
  LOW:      { color: '#A1A1AA', fillColor: '#A1A1AA', radius: 4  },
}

function MapResizer() {
  const map = useMap()
  useEffect(() => {
    // Trigger resize after small delay to allow container to stabilize
    const timer = setTimeout(() => {
      map.invalidateSize()
    }, 100)
    return () => clearTimeout(timer)
  }, [map])
  return null
}

function MapUpdater({ bounds }) {
  const map = useMap()
  useEffect(() => {
    if (bounds && bounds.length > 0) {
      try {
        map.invalidateSize(); // Also fix before fitting
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
      } catch (err) {
        console.warn("AttackMap: failed to fit bounds", err);
      }
    }
  }, [bounds, map])
  return null
}

// Build a quadratic bezier curve through a midpoint above the arc
function geodesicArcPoints(lat1, lon1, lat2, lon2, steps = 25) {
  const midLat = (lat1 + lat2) / 2
  const midLon = (lon1 + lon2) / 2
  const dist = Math.sqrt((lat2 - lat1) ** 2 + (lon2 - lon1) ** 2)
  const controlLat = midLat + dist * 0.3
  const controlLon = midLon

  const points = []
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    const lat = (1 - t) ** 2 * lat1 + 2 * (1 - t) * t * controlLat + t ** 2 * lat2
    const lon = (1 - t) ** 2 * lon1 + 2 * (1 - t) * t * controlLon + t ** 2 * lon2
    points.push([lat, lon])
  }
  return points
}

export default function AttackMap() {
  const { layer1Results, layer2Results, geoData } = useCertifyStore()

  // Find worst severity per IP
  const ipSeverity = {}
  for (const event of layer1Results) {
    const current = ipSeverity[event.ip]
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if (!current || order.indexOf(event.severity) > order.indexOf(current)) {
      ipSeverity[event.ip] = event.severity
    }
  }

  // Build attack types per IP for popup
  const ipAttackTypes = {}
  for (const event of layer1Results) {
    if (!ipAttackTypes[event.ip]) ipAttackTypes[event.ip] = new Set()
    ipAttackTypes[event.ip].add(event.type)
  }

  // Markers: unique IPs with geo data
  const markers = []
  const bounds = []
  const seen = new Set()

  for (const ip of Object.keys(ipSeverity)) {
    const geo = geoData[ip]
    if (!geo?.latitude || !geo?.longitude || seen.has(ip)) continue
    seen.add(ip)
    markers.push({ ip, geo, severity: ipSeverity[ip] })
    bounds.push([geo.latitude, geo.longitude])
  }

  // Geo-velocity arcs
  const geoArcs = getGeoVelocityArcs(layer2Results)

  const hasData = markers.length > 0

  return (
    <div className="flex flex-col h-[calc(100vh-130px)] min-h-[500px]">
      {/* Header */}
      <div className="px-6 md:px-12 py-6 border-b-2 border-border flex justify-between items-end flex-shrink-0">
        <div>
          <h2 className="text-2xl md:text-4xl font-bold uppercase tracking-tighter leading-none">
            ATTACK <span className="text-accent">MAP</span>
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            {markers.length} source IPs geolocated · {geoArcs.length} geo-velocity anomaly{geoArcs.length !== 1 ? 'ies' : ''} detected
          </p>
        </div>
        <div className="flex gap-3 items-center">
          {/* Legend */}
          {[
            { label: 'CRITICAL', color: 'bg-severity-critical' },
            { label: 'HIGH', color: 'bg-severity-high' },
            { label: 'MEDIUM', color: 'bg-accent' },
          ].map(({ label, color }) => (
            <span key={label} className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-muted-foreground">
              <span className={`w-2 h-2 rounded-full ${color}`} />
              {label}
            </span>
          ))}
          {geoArcs.length > 0 && (
            <span className="flex items-center gap-1.5 text-xs uppercase tracking-widest text-severity-critical">
              <span className="w-4 h-0.5 bg-severity-critical inline-block" />
              GEO-VELOCITY
            </span>
          )}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="px-6 md:px-12 py-2 border-b border-border flex-shrink-0">
        <p className="text-xs text-muted-foreground italic">
          Source IP distribution — true attacker origin may differ if proxies, VPNs, or Tor are used
        </p>
      </div>

      {/* Map */}
      <div className="flex-1 relative">
        {!hasData && (
          <div className="absolute inset-0 flex items-center justify-center bg-background z-10">
            <div className="text-center">
              <div className="text-[6rem] font-bold text-muted leading-none mb-4" aria-hidden="true">🌐</div>
              <p className="text-xl text-muted-foreground uppercase tracking-widest">No geo data available</p>
              <p className="text-sm text-muted-foreground mt-2">API calls may have been rate-limited</p>
            </div>
          </div>
        )}

        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: '100%', width: '100%', background: '#09090B' }}
          zoomControl={true}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
          />

          <MapResizer />

          {bounds.length > 0 && <MapUpdater bounds={bounds} />}

          {/* Attack markers */}
          {markers.map(({ ip, geo, severity }) => {
            const style = SEVERITY_MARKER_STYLES[severity] || SEVERITY_MARKER_STYLES.LOW
            const attackTypes = [...(ipAttackTypes[ip] || [])]
            return (
              <CircleMarker
                key={ip}
                center={[geo.latitude, geo.longitude]}
                radius={style.radius}
                color={style.color}
                fillColor={style.fillColor}
                fillOpacity={0.9}
                weight={2}
                opacity={0.9}
              >
                <Popup>
                  <div className="bg-background border-0 p-0 font-sans min-w-[200px]">
                    <div className="bg-muted px-4 py-2 border-b border-border">
                      <p className="font-mono font-bold text-accent text-base">{ip}</p>
                      <p className="text-xs uppercase tracking-widest text-muted-foreground mt-0.5">
                        {geo.city !== 'Unknown' ? geo.city + ', ' : ''}{geo.country_name}
                      </p>
                    </div>
                    <div className="px-4 py-3 space-y-2">
                      {geo.asn && (
                        <p className="font-mono text-xs text-foreground">
                          <span className="text-muted-foreground mr-2">ASN:</span>{geo.asn}
                        </p>
                      )}
                      {geo.org && (
                        <p className="text-xs text-muted-foreground truncate max-w-[220px]">{geo.org}</p>
                      )}
                      <div className="flex flex-wrap gap-1 mt-2">
                        {geo.proxy && <span className="text-xs bg-severity-critical/20 border border-severity-critical text-severity-critical px-2 py-0.5 uppercase font-bold tracking-wider">PROXY</span>}
                        {geo.hosting && <span className="text-xs bg-severity-high/20 border border-severity-high text-severity-high px-2 py-0.5 uppercase font-bold tracking-wider">HOSTING</span>}
                        {geo.tor && <span className="text-xs bg-severity-critical/20 border border-severity-critical text-severity-critical px-2 py-0.5 uppercase font-bold tracking-wider">TOR</span>}
                      </div>
                      <div className="pt-2 border-t border-border">
                        <p className="text-xs uppercase tracking-widest text-muted-foreground mb-1">Attack Types:</p>
                        {attackTypes.slice(0, 4).map(t => (
                          <span key={t} className="text-xs text-foreground block">{t.replace(/_/g, ' ')}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </Popup>
              </CircleMarker>
            )
          })}

          {/* Geo-velocity anomaly arcs */}
          {geoArcs.map((arc, idx) => {
            if (!arc.location1?.lat || !arc.location2?.lat) return null
            const arcPoints = geodesicArcPoints(
              arc.location1.lat, arc.location1.lon,
              arc.location2.lat, arc.location2.lon,
            )
            return (
              <Polyline
                key={idx}
                positions={arcPoints}
                color="#FF1744"
                weight={2}
                opacity={0.8}
                dashArray="8 4"
              >
                <Popup>
                  <div className="bg-background p-3 font-sans min-w-[220px]">
                    <p className="text-severity-critical font-bold text-sm uppercase tracking-wider mb-2">⚠ GEO-VELOCITY ANOMALY</p>
                    <p className="font-mono text-xs text-foreground">{arc.humanReadable}</p>
                    <div className="mt-2 space-y-1">
                      <p className="text-xs text-muted-foreground">Distance: <span className="text-foreground font-bold">{arc.distanceKm?.toLocaleString()} km</span></p>
                      <p className="text-xs text-muted-foreground">Time delta: <span className="text-foreground font-bold">{arc.timeDeltaSeconds}s</span></p>
                      <p className="text-xs text-muted-foreground">Speed: <span className="text-severity-critical font-bold">{arc.speedKmPerSecond?.toLocaleString()} km/s</span></p>
                    </div>
                  </div>
                </Popup>
              </Polyline>
            )
          })}
        </MapContainer>
      </div>
    </div>
  )
}
