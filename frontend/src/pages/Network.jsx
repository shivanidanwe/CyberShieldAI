import { useCallback, useEffect, useRef, useState } from 'react'
import { api, downloadCsv } from '../lib/api'
import { ErrorNotice, Panel, RefreshToggle, Spinner, notify } from '../components/shared'
import { formatLocalDateTime, formatLocalTime, getLocalTimezoneLabel } from '../lib/dateUtils'

const PAGE_SIZE = 50

// Wireshark-style protocol colors
const getRowColor = (protocol, service) => {
  if (service === 'DNS') return 'rgba(196, 223, 230, 0.15)' // Light blue
  if (service && service.includes('HTTP')) return 'rgba(234, 255, 234, 0.15)' // Light green
  if (protocol === 'TCP') return 'rgba(231, 230, 255, 0.15)' // Light purple/blue
  if (protocol === 'UDP') return 'rgba(218, 238, 255, 0.15)' // Light blue
  if (protocol === 'ICMP') return 'rgba(252, 224, 255, 0.15)' // Pink
  return 'transparent'
}

export default function Network({ captureStatus, onCaptureToggle }) {
  const [packets, setPackets] = useState([])
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [live, setLive] = useState(true)
  const [selectedPacket, setSelectedPacket] = useState(null)
  
  // Display filter
  const [filterText, setFilterText] = useState('')
  const [appliedFilter, setAppliedFilter] = useState('')

  const loadedRef = useRef(false)
  const wsRef = useRef(null) // Future WebSocket expansion
  const tzLabel = getLocalTimezoneLabel()

  const fetchPackets = useCallback(async (pageOverride, filterOverride) => {
    const currentPage = pageOverride ?? 1
    const currentFilter = filterOverride ?? appliedFilter
    
    setLoading(!loadedRef.current)
    try {
      // Parse a simple wireshark-like filter (e.g., "tcp", "port 80")
      // For now, we'll map simple text to the protocol query param if it matches known protocols,
      // otherwise we just fetch all and filter client-side (or build backend support later).
      let protocolParam = null
      if (['TCP', 'UDP', 'ICMP'].includes(currentFilter.toUpperCase())) {
        protocolParam = currentFilter.toUpperCase()
      }

      const data = await api.get('/packets', {
        limit: PAGE_SIZE + 1,
        offset: (currentPage - 1) * PAGE_SIZE,
        ...(protocolParam ? { protocol: protocolParam } : {}),
      })
      
      let results = data.slice(0, PAGE_SIZE)
      
      // Client-side fallback filtering if it wasn't a simple protocol match
      if (currentFilter && !protocolParam) {
        const lowerFilter = currentFilter.toLowerCase()
        results = results.filter(p => 
          p.source_ip.includes(lowerFilter) || 
          p.destination_ip.includes(lowerFilter) ||
          (p.service && p.service.toLowerCase().includes(lowerFilter)) ||
          (p.info && p.info.toLowerCase().includes(lowerFilter))
        )
      }

      setPackets(results)
      setHasMore(data.length > PAGE_SIZE)
      setError('')
      loadedRef.current = true
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [appliedFilter])

  // Fetch on mount + filter change.
  useEffect(() => {
    fetchPackets(1, appliedFilter)
    setPage(1)
  }, [fetchPackets, appliedFilter])

  // Live polling (faster 1.5s when capture is running, 3s otherwise).
  useEffect(() => {
    if (!live) return undefined
    const intervalMs = captureStatus?.enabled ? 1500 : 3000
    const interval = setInterval(() => {
      // Only poll if we are on the first page
      if (page === 1) fetchPackets(1, appliedFilter)
    }, intervalMs)
    return () => clearInterval(interval)
  }, [live, fetchPackets, page, appliedFilter, captureStatus?.enabled])

  const changePage = (next) => {
    setPage(next)
    fetchPackets(next)
    setSelectedPacket(null)
  }

  const handleApplyFilter = (e) => {
    e.preventDefault()
    setAppliedFilter(filterText)
  }

  const handleClearFilter = () => {
    setFilterText('')
    setAppliedFilter('')
  }

  const handleExport = async () => {
    try {
      await downloadCsv('/reports/csv/packets', `capture_${new Date().toISOString().slice(0, 10)}.csv`)
      notify('Capture exported as CSV.', 'success')
    } catch (err) {
      notify(`Export failed: ${err.message}`, 'error')
    }
  }

  return (
    <div className="page-stack">
      {error && <ErrorNotice message={error} onRetry={() => fetchPackets()} />}

      <Panel
        className="wireshark-panel"
        actions={
          <div className="wireshark-toolbar">
            <form onSubmit={handleApplyFilter} className="filter-bar">
              <span className="filter-icon">🔍</span>
              <input
                type="text"
                placeholder="Apply a display filter (e.g. 'tcp', '192.168.', 'http')..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className={`filter-input ${appliedFilter && appliedFilter === filterText ? 'filter-active' : ''}`}
              />
              {filterText && (
                <button type="button" className="clear-filter" onClick={handleClearFilter}>×</button>
              )}
              <button type="submit" className="apply-filter-btn">→</button>
            </form>
            
            <div className="toolbar-actions">
              <RefreshToggle enabled={live} onChange={setLive} />
              <button type="button" className="ghost-button" onClick={handleExport} title="Export Capture">
                Export
              </button>
            </div>
          </div>
        }
      >
        <div className="split-view">
          {/* Top Pane: Packet List */}
          <div className={`packet-list-pane ${selectedPacket ? 'half-height' : ''}`}>
            {captureStatus?.enabled && (
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                padding: '6px 14px',
                borderRadius: '8px',
                marginBottom: '10px',
                fontSize: '0.85rem',
                color: 'var(--green, #10b981)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}>
                <span style={{
                  display: 'inline-block',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: '#10b981',
                  boxShadow: '0 0 8px #10b981',
                }} />
                <span>Live capture active on <strong>{captureStatus.interface || 'active network interface'}</strong> — incoming packets update automatically</span>
              </div>
            )}
            <div className="table-wrap wireshark-table-wrap">
              <table className="wireshark-table">
                <thead>
                  <tr>
                    <th scope="col" width="60">No.</th>
                    <th scope="col" width="130">Time ({tzLabel})</th>
                    <th scope="col" width="150">Source</th>
                    <th scope="col" width="150">Destination</th>
                    <th scope="col" width="90">Protocol</th>
                    <th scope="col" width="80">Length</th>
                    <th scope="col">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && packets.length === 0 ? (
                    <tr>
                      <td colSpan="7" style={{ textAlign: 'center', padding: '2rem' }}>
                        <Spinner label="Capturing packets…" inline />
                      </td>
                    </tr>
                  ) : packets.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="muted" style={{ textAlign: 'center', padding: '2rem' }}>
                        No packets matched the display filter.
                      </td>
                    </tr>
                  ) : (
                    packets.map((packet) => {
                      const isSelected = selectedPacket?.id === packet.id;
                      const displayProto = packet.service || packet.protocol;
                      
                      return (
                        <tr 
                          key={packet.id} 
                          onClick={() => setSelectedPacket(isSelected ? null : packet)}
                          className={isSelected ? 'selected-row' : ''}
                          style={{ 
                            backgroundColor: isSelected ? 'var(--accent-muted)' : getRowColor(packet.protocol, packet.service),
                            cursor: 'pointer'
                          }}
                        >
                          <td className="muted">{packet.id}</td>
                          <td className="mono">{formatLocalTime(packet.timestamp)}</td>
                          <td className="mono">{packet.source_ip}</td>
                          <td className="mono">{packet.destination_ip}</td>
                          <td className="mono" style={{ fontWeight: 600 }}>{displayProto}</td>
                          <td>{packet.packet_length}</td>
                          <td className="mono text-truncate" title={packet.info}>
                            {packet.info || `${packet.source_port} → ${packet.destination_port} Len=${packet.packet_length}`}
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
            
            <div className="pagination-bar wireshark-pagination">
              <span className="muted">Packets: {packets.length}{hasMore ? '+' : ''}</span>
              <div>
                <button type="button" className="ghost-button" disabled={page <= 1} onClick={() => changePage(page - 1)}>← Prev</button>
                <span className="muted" style={{ margin: '0 12px' }}>Page {page}</span>
                <button type="button" className="ghost-button" disabled={!hasMore} onClick={() => changePage(page + 1)}>Next →</button>
              </div>
            </div>
          </div>

          {/* Bottom Pane: Packet Details */}
          {selectedPacket && (
            <div className="packet-details-pane">
              <div className="details-header">
                <h3>Packet {selectedPacket.id} Details</h3>
                <button type="button" onClick={() => setSelectedPacket(null)} className="close-btn">×</button>
              </div>
              
              <div className="details-content">
                {/* Frame Info (Always available) */}
                <div className="protocol-layer">
                  <details open>
                    <summary>Frame {selectedPacket.id}: {selectedPacket.packet_length} bytes on wire</summary>
                    <div className="layer-fields">
                      <div>Arrival Time: {formatLocalDateTime(selectedPacket.timestamp)} ({tzLabel})</div>
                      <div>Frame Length: {selectedPacket.packet_length} bytes</div>
                    </div>
                  </details>
                </div>

                {selectedPacket.layers?.length > 0 ? (
                  selectedPacket.layers.map((layer, idx) => (
                    <div key={idx} className="protocol-layer">
                      <details open={idx < 4}>
                        <summary>{layer.name}</summary>
                        <div className="layer-fields">
                          {Object.entries(layer.fields || {}).map(([key, val]) => (
                            <div key={key}><strong>{key}:</strong> {String(val)}</div>
                          ))}
                        </div>
                      </details>
                    </div>
                  ))
                ) : (
                  <>
                    {/* Fallback IP Layer */}
                    <div className="protocol-layer">
                      <details open>
                        <summary>Internet Protocol Version 4, Src: {selectedPacket.source_ip}, Dst: {selectedPacket.destination_ip}</summary>
                        <div className="layer-fields">
                          <div>Source Address: {selectedPacket.source_ip}</div>
                          <div>Destination Address: {selectedPacket.destination_ip}</div>
                          <div>Protocol: {selectedPacket.protocol}</div>
                          {selectedPacket.ttl && <div>Time to Live: {selectedPacket.ttl}</div>}
                        </div>
                      </details>
                    </div>

                    {/* Fallback Transport Layer */}
                    <div className="protocol-layer">
                      <details open>
                        <summary>
                          {selectedPacket.protocol === 'TCP' ? 'Transmission Control Protocol' : 
                           selectedPacket.protocol === 'UDP' ? 'User Datagram Protocol' : 
                           selectedPacket.protocol}
                          {selectedPacket.source_port && `, Src Port: ${selectedPacket.source_port}, Dst Port: ${selectedPacket.destination_port}`}
                        </summary>
                        <div className="layer-fields">
                          {selectedPacket.source_port && <div>Source Port: {selectedPacket.source_port}</div>}
                          {selectedPacket.destination_port && <div>Destination Port: {selectedPacket.destination_port}</div>}
                          {selectedPacket.tcp_flags && <div>Flags: [{selectedPacket.tcp_flags}]</div>}
                        </div>
                      </details>
                    </div>

                    {/* Fallback Application Layer / Info */}
                    {(selectedPacket.service || selectedPacket.info) && (
                      <div className="protocol-layer">
                        <details open>
                          <summary>{selectedPacket.service || 'Application Data'}</summary>
                          <div className="layer-fields">
                            <div>Info: {selectedPacket.info}</div>
                          </div>
                        </details>
                      </div>
                    )}
                  </>
                )}

                {/* Dynamic Hex Dump */}
                {selectedPacket.payload_preview ? (
                  <div className="hex-dump-preview mono">
                    <div className="hex-header">Payload Data ({selectedPacket.payload_preview.length} bytes)</div>
                    <div className="hex-content muted" style={{ display: 'flex', gap: '2rem', whiteSpace: 'pre' }}>
                      <div className="hex-bytes">
                        {selectedPacket.payload_preview.hex.match(/.{1,32}/g)?.map((line, i) => (
                           <div key={i}>{line.match(/.{1,2}/g)?.join(' ')}</div>
                        ))}
                      </div>
                      <div className="hex-ascii" style={{ color: 'var(--text-secondary)' }}>
                         {selectedPacket.payload_preview.ascii.match(/.{1,16}/g)?.map((line, i) => (
                           <div key={i}>{line}</div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="hex-dump-preview mono">
                    <div className="hex-header">0000 (No payload data available)</div>
                    <div className="hex-content muted">
                      45 00 00 3c 1c 46 40 00 40 06 b1 e6 c0 a8 01 0a<br/>
                      c0 a8 01 01 04 d2 00 50 00 00 00 00 00 00 00 00
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </Panel>
    </div>
  )
}