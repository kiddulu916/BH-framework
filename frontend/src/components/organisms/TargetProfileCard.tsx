'use client';
import { TargetResponse } from '@/types/target';

interface Props {
  target?: Partial<TargetResponse>;
}

export function TargetProfileCard({ target }: Props) {
  if (!target) return (
    <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700 text-gray-400">
      No target selected.
    </div>
  );

  const targetInfo = {
    company: target.target ?? '—',
    domain: target.domain ?? '—',
    inScope: target.in_scope ?? [],
    outOfScope: target.out_of_scope ?? [],
    rateLimiting: target.rate_limit_requests && target.rate_limit_seconds
      ? `${target.rate_limit_requests} req / ${target.rate_limit_seconds}s`
      : '—',
    customHeaders: target.custom_headers && target.custom_headers.length
      ? target.custom_headers.map(h => `${h.name}: ${h.value}`).join('; ')
      : '—',
    status: target.status ?? '—',
    researcher: target.researcher_email ?? '—'
  };

  // Format custom headers properly - ensure single colon format
  const formatCustomHeaders = (headers: string) => {
    if (headers === '—') return headers;
    
    return headers.split(';').map(header => {
      const trimmed = header.trim();
      // Fix double colon issue and ensure proper format
      if (trimmed.includes('::')) {
        return trimmed.replace('::', ':');
      }
      // Ensure proper format if missing colon
      if (!trimmed.includes(':')) {
        return trimmed;
      }
      return trimmed;
    }).join('; ');
  };

  return (
    <div className="bg-gray-800 rounded-2xl p-6 border border-gray-700 shadow-lg">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white">Target Profile</h2>
        <span className="px-3 py-1 bg-green-600 text-white text-xs font-medium rounded-full">
          {targetInfo.status}
        </span>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Basic Info */}
        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">Target Company</div>
          <div className="text-white font-semibold capitalize">{targetInfo.company}</div>
        </div>
        
        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">Domain/IP</div>
          <div className="text-white font-semibold">{targetInfo.domain}</div>
        </div>

        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">Researcher</div>
          <div className="text-white font-semibold">{targetInfo.researcher}</div>
        </div>

        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">Rate Limiting</div>
          <div className="text-white font-semibold">{targetInfo.rateLimiting}</div>
        </div>

        {/* In-Scope */}
        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">In-Scope</div>
          <div className="space-y-1">
            {targetInfo.inScope.length > 0 ? (
              targetInfo.inScope.map((item, index) => (
                <div key={index} className="text-sm text-white bg-gray-700 px-2 py-1 rounded inline-block">
                  {item}
                </div>
              ))
            ) : (
              <div className="text-sm text-gray-500 italic">No in-scope items</div>
            )}
          </div>
        </div>

        {/* Out-of-Scope */}
        <div className="space-y-2">
          <div className="text-sm text-gray-400 font-medium">Out-of-Scope</div>
          <div className="space-y-1">
            {targetInfo.outOfScope.length > 0 ? (
              targetInfo.outOfScope.map((item, index) => (
                <div key={index} className="text-sm text-gray-300 bg-gray-700 px-2 py-1 rounded inline-block">
                  {item}
                </div>
              ))
            ) : (
              <div className="text-sm text-gray-500 italic">No out-of-scope items</div>
            )}
          </div>
        </div>

        {/* Custom Headers */}
        <div className="space-y-2 lg:col-span-2">
          <div className="text-sm text-gray-400 font-medium">Custom Headers</div>
          <div className="text-sm text-white bg-gray-700 px-3 py-2 rounded font-mono inline-block">
            {formatCustomHeaders(targetInfo.customHeaders)}
          </div>
        </div>
      </div>
    </div>
  );
} 