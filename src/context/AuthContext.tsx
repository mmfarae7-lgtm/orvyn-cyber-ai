import { createContext, useContext, useEffect, useCallback, useState, type ReactNode } from 'react';
import type { Session, User } from '@supabase/supabase-js';
import { supabase } from '@/lib/supabase';

type AuthContextType = {
  session: Session | null;
  user: User | null;
  loading: boolean;
  isAdmin: boolean;
  awaitingNewPassword: boolean;
  signIn: (email: string, password: string) => Promise<{ error: string | null }>;
  signUp: (email: string, password: string, displayName: string) => Promise<{ error: string | null }>;
  adminSignIn: (email: string) => Promise<{ error: string | null }>;
  resetPassword: (email: string) => Promise<{ error: string | null }>;
  newPassword: (password: string) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const ADMIN_EMAILS = (import.meta.env.VITE_ADMIN_EMAILS ?? '')
  .split(',')
  .map((e: string) => e.trim().toLowerCase())
  .filter(Boolean);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [awaitingNewPassword, setAwaitingNewPassword] = useState(false);

  useEffect(() => {
    const timeout = setTimeout(() => setLoading(false), 5000);
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setUser(data.session?.user ?? null);
      setLoading(false);
      clearTimeout(timeout);
    }).catch(() => {
      setLoading(false);
      clearTimeout(timeout);
    });

    const { data: listener } = supabase.auth.onAuthStateChange((event, newSession) => {
      setSession(newSession);
      setUser(newSession?.user ?? null);
      if (event === 'PASSWORD_RECOVERY') {
        setAwaitingNewPassword(true);
      }
      setLoading(false);
    });

    return () => {
      listener.subscription.unsubscribe();
      clearTimeout(timeout);
    };
  }, []);

  const checkAdminStatus = useCallback(async (email: string) => {
    if (ADMIN_EMAILS.includes(email)) {
      setIsAdmin(true);
      return;
    }
    const { data } = await supabase
      .from('profiles')
      .select('is_admin')
      .eq('id', user?.id ?? '')
      .maybeSingle();
    setIsAdmin(data?.is_admin ?? false);
  }, [user]);

  useEffect(() => {
    if (user) {
      checkAdminStatus(user.email ?? '');
    } else {
      setIsAdmin(false);
    }
  }, [user, checkAdminStatus]);

  const signIn = async (email: string, password: string) => {
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) {
        if (error.message.includes('Failed to fetch') || error.message.includes('fetch')) {
          return { error: 'Cannot connect to the server. Please check your internet connection and try again.' };
        }
        return { error: error.message };
      }
      return { error: null };
    } catch {
      return { error: 'Connection error. Please check your internet connection and try again.' };
    }
  };

  const signUp = async (email: string, password: string, displayName: string) => {
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { display_name: displayName } },
    });
    return { error: error?.message ?? null };
  };

  const adminSignIn = async (email: string) => {
    if (!ADMIN_EMAILS.includes(email)) {
      return { error: 'This email is not authorized for admin access' };
    }
    try {
      const { error } = await supabase.auth.signInWithOtp({
        email,
        options: { shouldCreateUser: false },
      });
      if (error) {
        if (error.message.includes('Failed to fetch') || error.message.includes('fetch')) {
          return { error: 'Cannot connect to the server. Please use Sign In with your password instead.' };
        }
        return { error: error.message };
      }
      return { error: null };
    } catch {
      return { error: 'Connection error. Please use Sign In with email and password instead.' };
    }
  };

  const resetPassword = async (email: string) => {
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: window.location.origin,
      });
      if (error) {
        if (error.message.includes('Failed to fetch') || error.message.includes('fetch')) {
          return { error: 'Cannot connect to the server. Please check your internet connection and try again.' };
        }
        return { error: error.message };
      }
      return { error: null };
    } catch {
      return { error: 'Connection error. Please check your internet connection and try again.' };
    }
  };

  const newPassword = async (password: string) => {
    try {
      const { error } = await supabase.auth.updateUser({ password });
      if (error) {
        if (error.message.includes('Failed to fetch') || error.message.includes('fetch')) {
          return { error: 'Cannot connect to the server. Please check your internet connection and try again.' };
        }
        return { error: error.message };
      }
      setAwaitingNewPassword(false);
      return { error: null };
    } catch {
      return { error: 'Connection error. Please check your internet connection and try again.' };
    }
  };

  const signOut = async () => {
    await supabase.auth.signOut();
    setIsAdmin(false);
    setAwaitingNewPassword(false);
  };

  return (
    <AuthContext.Provider
      value={{ session, user, loading, isAdmin, awaitingNewPassword, signIn, signUp, adminSignIn, resetPassword, newPassword, signOut }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
