import dynamic from 'next/dynamic';

// Lazy-load to reduce bundle size
const TargetProfileBuilder = dynamic(() => import('@/components/pages/TargetProfileBuilder'), {
  ssr: false,
});

export default function TargetCreatePage() {
  return <TargetProfileBuilder />;
} 