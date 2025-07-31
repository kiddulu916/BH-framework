import { fetchTargetsServer } from '@/lib/api/targetsServer';
import Link from 'next/link';

export default async function TargetSelectPage() {
  const targets = await fetchTargetsServer();

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center text-white p-6">
      <div className="w-full max-w-md space-y-6">
        <h1 className="text-3xl font-bold text-center">Select Target Profile</h1>

        <ul className="space-y-3">
          {targets.map(t => (
            <li key={t.id}>
              <Link
                href={`/dashboard?target=${t.id}`}
                className="block w-full bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg p-4 transition"
              >
                <div className="font-semibold">{t.target}</div>
                <div className="text-sm text-gray-400">{t.domain}</div>
              </Link>
            </li>
          ))}
        </ul>

        <div className="text-center">
          <Link href="/target-profile" className="text-blue-500 hover:underline">
            + Create New Target Profile
          </Link>
        </div>
      </div>
    </div>
  );
} 