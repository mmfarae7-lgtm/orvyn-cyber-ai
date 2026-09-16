import { useState, type ReactNode } from 'react';
import {
  LayoutDashboard,
  Rocket,
  FileWarning,
  MessageSquare,
  FlaskConical,
  BookOpen,
  LogOut,
  Menu,
  Crown,
  type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

export type PageId = 'dashboard' | 'scan' | 'vulnerabilities' | 'chat' | 'lab' | 'guide';

type NavItem = {
  id: PageId;
  label: string;
  icon: LucideIcon;
};

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scan', label: 'New Scan', icon: Rocket },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: FileWarning },
  { id: 'chat', label: 'AI Assistant', icon: MessageSquare },
  { id: 'lab', label: 'Lab', icon: FlaskConical },
  { id: 'guide', label: 'Guide', icon: BookOpen },
];

export default function Layout({
  currentPage,
  onNavigate,
  children,
}: {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  children: ReactNode;
}) {
  const { user, isAdmin, signOut } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleNav = (page: PageId) => {
    onNavigate(page);
    setMobileOpen(false);
  };

  const currentLabel = NAV_ITEMS.find((n) => n.id === currentPage)?.label ?? '';

  return (
    <div className="min-h-screen flex">
      {/* Sidebar - Desktop */}
      <aside className="hidden md:flex w-64 flex-col bg-[#0d0f1a] border-r border-white/[0.04] fixed inset-y-0 left-0 z-30">
        <SidebarContent currentPage={currentPage} onNavigate={handleNav} user={user} isAdmin={isAdmin} onSignOut={signOut} />
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 z-40">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 bg-[#0d0f1a] border-r border-white/[0.04] flex flex-col">
            <SidebarContent currentPage={currentPage} onNavigate={handleNav} user={user} isAdmin={isAdmin} onSignOut={signOut} />
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 md:ml-64 flex flex-col min-h-screen">
        {/* Top bar */}
        <header className="sticky top-0 z-20 bg-[#0a0b14]/95 border-b border-white/[0.04] px-4 md:px-8 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="md:hidden p-2 rounded-lg hover:bg-white/[0.06] transition-colors"
            >
              <Menu className="w-5 h-5" />
            </button>
            <h2 className="text-lg font-semibold">{currentLabel}</h2>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
              <span className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-xs text-green-400 font-medium">System Online</span>
            </div>
            <div className="flex items-center gap-2">
              {isAdmin && (
                <span className="flex items-center gap-1 text-xs px-2 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium">
                  <Crown className="w-3 h-3" /> Admin
                </span>
              )}
              <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-sm font-medium text-white">
                {user?.email?.[0]?.toUpperCase() ?? 'U'}
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 p-4 md:p-8">{children}</main>
      </div>
    </div>
  );
}

function SidebarContent({
  currentPage,
  onNavigate,
  user,
  isAdmin,
  onSignOut,
}: {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  user: { email?: string } | null;
  isAdmin: boolean;
  onSignOut: () => void;
}) {
  return (
    <>
      {/* Logo */}
      <div className="px-6 py-6 border-b border-white/[0.04]">
        <div className="flex items-center gap-3">
          <img src="/orvyn-logo.png" alt="Orvyn" className="w-10 h-10 object-cover rounded-lg" />
          <div>
            <div className="font-bold text-sm tracking-tight">
              Orvyn <span className="text-blue-400">Cyber</span>
            </div>
            <div className="text-[10px] text-gray-600">orvyn.is-great.org</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                active
                  ? 'bg-blue-600/15 text-blue-300'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
              }`}
            >
              <Icon className="w-4 h-4" />
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div className="px-3 py-4 border-t border-white/[0.04]">
        <div className="px-3 py-2 mb-2">
          <div className="text-xs text-gray-500 truncate flex items-center gap-1.5">
            {isAdmin && <Crown className="w-3 h-3 text-amber-400 flex-shrink-0" />}
            <span className="truncate">{user?.email ?? ''}</span>
          </div>
        </div>
        <button
          onClick={onSignOut}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/5 transition-all"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </>
  );
}
