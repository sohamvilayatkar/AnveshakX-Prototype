import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import { Globe, Server, ShieldAlert } from 'lucide-react';

// Fix Leaflet marker icons in React bundles
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// Custom neon map pin icon
const createCustomIcon = (isSource = false) => {
  const color = isSource ? '#ef4444' : '#06b6d4';
  return L.divIcon({
    className: 'custom-map-pin',
    html: `
      <div style="
        background-color: ${color};
        width: 18px;
        height: 18px;
        border-radius: 50%;
        border: 2px solid #ffffff;
        box-shadow: 0 0 10px ${color};
        display: flex;
        align-items: center;
        justify-content: center;
      ">
        <div style="background-color: #ffffff; width: 6px; height: 6px; border-radius: 50%;"></div>
      </div>
    `,
    iconSize: [18, 18],
    iconAnchor: [9, 9]
  });
};

export const GeoMap = ({ ipList = [], earliestSourceIp = null }) => {
  const geoIps = ipList.filter(ip => ip.latitude && ip.longitude);

  const defaultCenter = geoIps.length > 0
    ? [geoIps[0].latitude, geoIps[0].longitude]
    : [20.5937, 78.9629]; // Default India/Global view

  return (
    <div className="rounded-xl border border-soc-border bg-soc-card p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-white flex items-center gap-2">
            <Globe className="h-4 w-4 text-cyan-400" />
            Infrastructure Geolocation Intelligence
          </h3>
          <p className="text-xs text-soc-muted">Mapping transmission relay nodes and source infrastructure</p>
        </div>
        <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-black/40 border border-soc-border text-cyan-400">
          {geoIps.length} Nodes Mapped
        </span>
      </div>

      <div className="h-80 w-full rounded-lg overflow-hidden border border-soc-border relative z-0">
        <MapContainer
          center={defaultCenter}
          zoom={geoIps.length === 1 ? 4 : 2}
          scrollWheelZoom={false}
          style={{ height: '100%', width: '100%' }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />

          {geoIps.map((node) => {
            const isSource = node.ip === earliestSourceIp;
            return (
              <Marker
                key={node.ip}
                position={[node.latitude, node.longitude]}
                icon={createCustomIcon(isSource)}
              >
                <Popup>
                  <div className="font-mono text-xs p-1 space-y-1.5 min-w-[200px]">
                    <div className="flex items-center justify-between border-b border-slate-700 pb-1">
                      <span className="font-bold text-cyan-400">{node.ip}</span>
                      {isSource && (
                        <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold">
                          SOURCE
                        </span>
                      )}
                    </div>
                    <div className="text-slate-300 space-y-0.5">
                      <p><b className="text-slate-400">Location:</b> {node.city}, {node.country}</p>
                      <p><b className="text-slate-400">ISP:</b> {node.isp}</p>
                      <p><b className="text-slate-400">Organization:</b> {node.organization}</p>
                      <p><b className="text-slate-400">ASN:</b> {node.asn}</p>
                      <p><b className="text-slate-400">Coordinates:</b> {node.latitude?.toFixed(2)}, {node.longitude?.toFixed(2)}</p>
                    </div>
                    {node.is_proxy_vpn && (
                      <div className="p-1 rounded bg-amber-500/20 text-amber-300 text-[10px]">
                        ⚠️ Proxy / Tor / VPN routing observed
                      </div>
                    )}
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      </div>

      <div className="mt-3 text-[11px] font-mono text-soc-muted bg-black/30 p-2.5 rounded border border-soc-border flex items-start gap-2">
        <ShieldAlert className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <span>
          <b>Forensic Disclaimer:</b> IP geolocation represents Mail Transfer Agent (MTA) network infrastructure and ISP routing points. It does not establish the physical residence or personal identity of an individual.
        </span>
      </div>
    </div>
  );
};

export default GeoMap;
