import { fetchTargetsServer } from '@/lib/api/targetsServer';
import { DashboardPage } from '@/components/pages/DashboardPage';

export default async function DashboardRoute({ searchParams }: { searchParams: { target?: string } }) {
  const id = searchParams?.target;
  const targets = await fetchTargetsServer();
  const current = id ? targets.find(t => t.id === id) : targets.find(t => t.is_primary) ?? targets[0];
  return <DashboardPage target={current} />;
} 