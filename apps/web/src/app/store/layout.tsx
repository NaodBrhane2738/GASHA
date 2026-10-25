import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'GASHA Market — sandbox store',
  description: 'Demo storefront defended by GASHA. All traffic is simulated.',
};

export default function StoreLayout({ children }: { children: React.ReactNode }) {
  return children;
}
