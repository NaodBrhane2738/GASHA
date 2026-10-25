import { redirect } from 'next/navigation';

// The Vercel OAuth connection flow is not part of the demo build; send visitors to the SOC.
export default function ConnectPage() {
  redirect('/soc');
}
