import { Suspense } from 'react';
import { PassiveReconPage } from '@/components/pages/PassiveReconPage';
import { fetchTargetsServer } from '@/lib/api/targetsServer';

export default async function PassiveReconRoute({ 
  searchParams 
}: { 
  searchParams: { target?: string } 
}) {
  const targetId = searchParams?.target;
  const targets = await fetchTargetsServer();
  const current = targetId ? targets.find(t => t.id === targetId) : targets.find(t => t.is_primary) ?? targets[0];
  
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <PassiveReconPage target={current} />
    </Suspense>
  );
} 