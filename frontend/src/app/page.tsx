import TargetProfileBuilder from '@/components/pages/TargetProfileBuilder';
import HydrationProvider from '@/components/providers/HydrationProvider';

export default function HomePage() {
  return (
    <main>
      <HydrationProvider>
        <TargetProfileBuilder />
      </HydrationProvider>
    </main>
  );
}
