import { Suspense } from 'react';
import { ActiveReconPage } from '@/components/pages/ActiveReconPage';
import { fetchTargetsServer } from '@/lib/api/targetsServer';

export default async function ActiveReconRoute({ 
  searchParams 
}: { 
  searchParams: { target?: string } 
}) {
  const targetId = searchParams?.target;
  const targets = await fetchTargetsServer();
  const current = targetId ? targets.find(t => t.id === targetId) : targets.find(t => t.is_primary) ?? targets[0];
  
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ActiveReconPage target={current} />
    </Suspense>
  );
} 