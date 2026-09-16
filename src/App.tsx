import { useState } from 'react';
import { AuthProvider, useAuth } from '@/context/AuthContext';
import Layout, { type PageId } from '@/components/Layout';
import AuthPage from '@/pages/AuthPage';
import Dashboard from '@/pages/Dashboard';
import ScanLaunch from '@/pages/ScanLaunch';
import Vulnerabilities from '@/pages/Vulnerabilities';
import Chat from '@/pages/Chat';
import Lab from '@/pages/Lab';
import Guide from '@/pages/Guide';
import { Loader2 } from 'lucide-react';

function AppContent() {
  const { user, loading } = useAuth();
  const [page, setPage] = useState<PageId>('dashboard');

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <img src="/orvyn-logo.png" alt="Orvyn" className="w-24 h-auto" />
        <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
        <p className="text-sm text-gray-500">Loading Orvyn Cyber...</p>
      </div>
    );
  }

  if (!user) {
    return <AuthPage />;
  }

  return (
    <Layout currentPage={page} onNavigate={setPage}>
      {page === 'dashboard' && <Dashboard onNavigate={setPage} />}
      {page === 'scan' && <ScanLaunch onNavigate={setPage} />}
      {page === 'vulnerabilities' && <Vulnerabilities />}
      {page === 'chat' && <Chat />}
      {page === 'lab' && <Lab />}
      {page === 'guide' && <Guide />}
    </Layout>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
