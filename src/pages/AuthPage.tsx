import { useState, type FormEvent } from 'react';
import { Mail, Lock, User, AlertCircle, Loader2, Crown, CheckCircle2, KeyRound, Shield, Zap, Globe } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

export default function AuthPage() {
  const { signIn, signUp, adminSignIn, resetPassword, newPassword, awaitingNewPassword } = useAuth();
  const [mode, setMode] = useState<'signin' | 'signup' | 'admin' | 'reset'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [adminSent, setAdminSent] = useState(false);
  const [resetSent, setResetSent] = useState(false);
  const [passwordUpdated, setPasswordUpdated] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    if (mode === 'signup') {
      const { error } = await signUp(email, password, displayName);
      if (error) setError(error);
    } else if (mode === 'admin') {
      const { error } = await adminSignIn(email);
      if (error) {
        setError(error);
      } else {
        setAdminSent(true);
      }
    } else if (mode === 'reset') {
      const { error } = await resetPassword(email);
      if (error) {
        setError(error);
      } else {
        setResetSent(true);
      }
    } else {
      const { error } = await signIn(email, password);
      if (error) setError(error);
    }
    setLoading(false);
  };

  const handleNewPasswordSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    const { error } = await newPassword(password);
    setLoading(false);
    if (error) {
      setError(error);
    } else {
      setPasswordUpdated(true);
    }
  };

  return (
    <div className="min-h-screen flex">
      {/* ── Left panel: branding ── */}
      <div className="hidden lg:flex lg:w-[44%] xl:w-[48%] relative flex-col items-center justify-center p-12 overflow-hidden">
        {/* Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-blue-900/30 via-[#0a0b14] to-cyan-900/10" />

        <div className="relative z-10 flex flex-col items-center text-center max-w-sm">
          <img src="/orvyn-logo.png" alt="Orvyn Cyber" className="w-28 h-auto mb-6 rounded-2xl" />
          <h1 className="text-4xl font-bold tracking-tight mb-2">
            <span className="gradient-text">Orvyn</span> <span className="text-white">Cyber</span>
          </h1>
          <p className="text-gray-400 text-sm mb-10 leading-relaxed">
            Advanced Security Scanning Platform
          </p>

          {/* Feature highlights */}
          <div className="space-y-4 w-full text-left">
            {[
              { icon: Shield, label: 'Real-time Vulnerability Scanning', desc: 'Detect threats across your entire infrastructure' },
              { icon: Zap, label: 'Intelligent Threat Analysis', desc: 'AI-powered assessment with actionable insights' },
              { icon: Globe, label: 'Full Attack Surface Coverage', desc: 'Web, API, network, and cloud security testing' },
            ].map(({ icon: Icon, label, desc }) => (
              <div key={label} className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/[0.04]">
                <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                  <Icon className="w-4 h-4 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-200">{label}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Right panel: form ── */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-10 relative">
        <div className="relative z-10 w-full max-w-md fade-in">
          {/* Mobile logo */}
          <div className="lg:hidden text-center mb-8">
            <img src="/orvyn-logo.png" alt="Orvyn Cyber" className="w-20 h-auto mx-auto mb-3 rounded-xl" />
            <h1 className="text-2xl font-bold">
              <span className="gradient-text">Orvyn</span> Cyber
            </h1>
          </div>

          {/* Tabs — hidden in special modes */}
          {mode !== 'reset' && !awaitingNewPassword && !passwordUpdated && (
            <div className="flex gap-1 mb-8 p-1 bg-white/[0.03] rounded-xl border border-white/[0.04]">
              <button
                onClick={() => { setMode('signin'); setError(null); setAdminSent(false); setResetSent(false); }}
                className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200 ${
                  mode === 'signin'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                }`}
              >
                Sign In
              </button>
              <button
                onClick={() => { setMode('signup'); setError(null); setAdminSent(false); setResetSent(false); }}
                className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200 ${
                  mode === 'signup'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                }`}
              >
                Sign Up
              </button>
              <button
                onClick={() => { setMode('admin'); setError(null); setAdminSent(false); setResetSent(false); }}
                className={`flex-1 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200 flex items-center justify-center gap-1.5 ${
                  mode === 'admin'
                    ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                }`}
              >
                <Crown className="w-3.5 h-3.5" /> Admin
              </button>
            </div>
          )}

          {/* ── Password updated success ── */}
          {passwordUpdated ? (
            <div className="text-center py-12 fade-in">
              <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-5">
                <CheckCircle2 className="w-8 h-8 text-green-400" />
              </div>
              <h3 className="text-xl font-bold mb-2">Password updated</h3>
              <p className="text-sm text-gray-400 mb-8 max-w-xs mx-auto">
                Your password has been successfully updated. Sign in with your new credentials.
              </p>
              <button
                onClick={() => { setPasswordUpdated(false); setPassword(''); setConfirmPassword(''); setMode('signin'); setError(null); }}
                className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-semibold py-3 px-8 rounded-xl transition-colors duration-200"
              >
                Go to Sign In
              </button>
            </div>

          /* ── New password form (from email link) ── */
          ) : awaitingNewPassword ? (
            <div className="fade-in">
              <div className="mb-6">
                <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mb-4">
                  <KeyRound className="w-5 h-5 text-blue-400" />
                </div>
                <h2 className="text-xl font-bold">Create new password</h2>
                <p className="text-sm text-gray-400 mt-1">Choose a strong password for your account.</p>
              </div>
              <form onSubmit={handleNewPasswordSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      minLength={6}
                      className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                      placeholder="••••••••"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      minLength={6}
                      className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                      placeholder="••••••••"
                    />
                  </div>
                </div>

                {error && (
                  <div className="flex items-start gap-3 p-3.5 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
                    <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3.5 rounded-xl transition-colors duration-200 flex items-center justify-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Set New Password'}
                </button>
              </form>
            </div>

          /* ── Reset password (forgot) ── */
          ) : mode === 'reset' ? (
            resetSent ? (
              <div className="text-center py-12 fade-in">
                <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-5">
                  <CheckCircle2 className="w-8 h-8 text-green-400" />
                </div>
                <h3 className="text-xl font-bold mb-2">Check your email</h3>
                <p className="text-sm text-gray-400 mb-8 max-w-xs mx-auto">
                  We sent a password reset link to <span className="text-blue-400 font-medium">{email}</span>. The link expires in 30 minutes.
                </p>
                <button
                  onClick={() => { setMode('signin'); setResetSent(false); setError(null); }}
                  className="text-sm text-gray-400 hover:text-gray-200 transition-colors"
                >
                  ← Back to Sign In
                </button>
              </div>
            ) : (
              <div className="fade-in">
                <div className="mb-6">
                  <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mb-4">
                    <KeyRound className="w-5 h-5 text-blue-400" />
                  </div>
                  <h2 className="text-xl font-bold">Forgot your password?</h2>
                  <p className="text-sm text-gray-400 mt-1">Enter your email and we'll send you a reset link.</p>
                </div>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                    <div className="relative">
                      <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                        placeholder="you@example.com"
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="flex items-start gap-3 p-3.5 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
                      <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                      <span>{error}</span>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={loading}
className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3.5 rounded-xl transition-colors duration-200 flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Send Reset Link'}
                  </button>

                  <button
                    type="button"
                    onClick={() => { setMode('signin'); setError(null); }}
                    className="w-full text-sm text-gray-400 hover:text-gray-200 transition-colors text-center"
                  >
                    ← Back to Sign In
                  </button>
                </form>
              </div>
            )

          /* ── Admin magic link sent ── */
          ) : mode === 'admin' && adminSent ? (
            <div className="text-center py-12 fade-in">
              <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-5">
                <CheckCircle2 className="w-8 h-8 text-cyan-400" />
              </div>
              <h3 className="text-xl font-bold mb-2">Magic link sent!</h3>
              <p className="text-sm text-gray-400 max-w-xs mx-auto">
                Check your email at <span className="text-cyan-400 font-medium">{email}</span> and click the link to sign in as admin.
              </p>
            </div>

          /* ── Main form (sign in / sign up / admin) ── */
          ) : (
            <div className="fade-in">
              <div className="mb-6">
                <h2 className="text-2xl font-bold">
                  {mode === 'signin' && 'Welcome back'}
                  {mode === 'signup' && 'Create your account'}
                  {mode === 'admin' && 'Admin Access'}
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {mode === 'signin' && 'Sign in to access your security dashboard'}
                  {mode === 'signup' && 'Get started with Orvyn Cyber today'}
                  {mode === 'admin' && 'Sign in using a magic link sent to your email'}
                </p>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                {mode === 'admin' && (
                  <div className="flex items-start gap-3 p-3.5 bg-cyan-500/10 border border-cyan-500/20 rounded-xl">
                    <Crown className="w-4 h-4 text-cyan-500 flex-shrink-0 mt-0.5" />
                    <p className="text-xs text-cyan-400/80">
                      Admin access via magic link. If it fails, use the Sign In tab with your email and password instead.
                    </p>
                  </div>
                )}

                {mode === 'signup' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Display Name</label>
                    <div className="relative">
                      <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type="text"
                        value={displayName}
                        onChange={(e) => setDisplayName(e.target.value)}
                        required
                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                        placeholder="Your name"
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                      placeholder="you@example.com"
                    />
                  </div>
                </div>

                {(mode === 'signin' || mode === 'signup') && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-gray-300">Password</label>
                      {mode === 'signin' && (
                        <button
                          type="button"
                          onClick={() => { setMode('reset'); setError(null); setAdminSent(false); }}
                          className="text-xs text-blue-400 hover:text-blue-300 transition-colors font-medium"
                        >
                          Forgot password?
                        </button>
                      )}
                    </div>
                    <div className="relative">
                      <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        minLength={6}
                        className="w-full bg-white/[0.04] border border-white/10 rounded-xl pl-11 pr-4 py-3.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>
                )}

                {error && (
                  <div className="flex items-start gap-3 p-3.5 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
                    <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className={`w-full disabled:opacity-50 disabled:cursor-not-allowed font-semibold py-3.5 rounded-xl transition-colors duration-200 flex items-center justify-center gap-2 ${
                    mode === 'admin'
                      ? 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white'
                      : 'bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white'
                  }`}
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : mode === 'signin' ? (
                    'Sign In'
                  ) : mode === 'signup' ? (
                    'Create Account'
                  ) : (
                    <>
                      <Crown className="w-4 h-4" /> Send Magic Link
                    </>
                  )}
                </button>

                {mode === 'signin' && (
                  <div className="pt-1">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="flex-1 h-px bg-white/[0.06]" />
                      <span className="text-xs text-gray-500">or</span>
                      <div className="flex-1 h-px bg-white/[0.06]" />
                    </div>
                    <button
                      type="button"
                      onClick={() => { setMode('reset'); setError(null); setAdminSent(false); }}
                      className="w-full flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] hover:bg-white/[0.06] text-gray-300 hover:text-white font-medium py-3.5 transition-all duration-200"
                    >
                      <KeyRound className="w-4 h-4 text-blue-400" />
                      Forgot password?
                    </button>
                  </div>
                )}
              </form>
            </div>
          )}

          <p className="text-center text-xs text-gray-600 mt-8">
            By continuing, you agree to use Orvyn Cyber for authorized security testing only.
          </p>
        </div>
      </div>
    </div>
  );
}
