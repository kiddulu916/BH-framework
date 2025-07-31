import { redirect } from 'next/navigation';
import { fetchTargetsServer } from '@/lib/api/targetsServer';

export default async function HomePage() {
  const targets = await fetchTargetsServer();

  if (targets.length === 0) {
    // no targets – start creation wizard
    redirect('/target-profile');
  }

  const primary = targets.find(t => t.is_primary);
  if (primary) {
    redirect(`/dashboard?target=${primary.id}`);
  }

  // no primary but have targets – show selection
  redirect('/target-select');
}
