import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  MessageSquare,
  Send,
  Loader2,
  Trash2,
  Bot,
  User,
} from 'lucide-react';
import { supabase, type ChatMessage } from '@/lib/supabase';
import { useAuth } from '@/context/AuthContext';

const SUGGESTIONS = [
  'What is SQL injection and how do I prevent it?',
  'Explain the OWASP Top 10 vulnerabilities',
  'How does TLS 1.3 improve security over TLS 1.2?',
  'What are common misconfigurations in web servers?',
];

export default function Chat() {
  const { session } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadMessages();
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const loadMessages = async () => {
    const { data } = await supabase
      .from('chat_messages')
      .select('*')
      .order('created_at', { ascending: true });
    setMessages((data ?? []) as ChatMessage[]);
    setLoadingHistory(false);
  };

  const handleSend = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    setLoading(true);

    const tempUser: ChatMessage = {
      id: 'temp-' + Date.now(),
      user_id: '',
      role: 'user',
      content: userMessage,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, tempUser]);

    await supabase.from('chat_messages').insert({ role: 'user', content: userMessage });

    try {
      const apiUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-chat`;
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.access_token ?? ''}`,
        },
        body: JSON.stringify({ message: userMessage, history: messages.slice(-10) }),
      });

      if (!response.ok) throw new Error('Chat request failed');
      const data = await response.json();
      const aiReply = data.reply ?? 'I could not process your request.';

      const tempAssistant: ChatMessage = {
        id: 'temp-ai-' + Date.now(),
        user_id: '',
        role: 'assistant',
        content: aiReply,
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, tempAssistant]);

      await supabase.from('chat_messages').insert({ role: 'assistant', content: aiReply });
    } catch {
      const errorMsg: ChatMessage = {
        id: 'err-' + Date.now(),
        user_id: '',
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = async () => {
    await supabase.from('chat_messages').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    setMessages([]);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <MessageSquare className="w-5 h-5 text-blue-400" />
            AI Security Assistant
          </h1>
          <p className="text-sm text-gray-500 mt-1">Ask about vulnerabilities, tools, or security best practices</p>
        </div>
        {messages.length > 0 && (
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-all"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear
          </button>
        )}
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-4 pb-4">
        {loadingHistory ? (
          <div className="flex items-center justify-center h-full">
            <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
          </div>
        ) : messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full">
            <div className="w-16 h-16 rounded-xl bg-[#12141f] border border-white/[0.06] flex items-center justify-center mb-4">
              <Bot className="w-8 h-8 text-blue-400" />
            </div>
            <h3 className="font-semibold mb-1">Orvyn Cyber AI Assistant</h3>
            <p className="text-sm text-gray-500 mb-6 text-center max-w-sm">
              I can answer questions about security tools, vulnerabilities, and best practices. Ask me anything!
            </p>
            <div className="grid sm:grid-cols-2 gap-2 max-w-lg w-full">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => setInput(s)}
                  className="glass-card-hover p-3 text-left text-sm text-gray-400 hover:text-gray-200"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
            >
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                  msg.role === 'user'
                    ? 'bg-blue-600/20'
                    : 'bg-[#12141f] border border-white/[0.06]'
                }`}
              >
                {msg.role === 'user' ? (
                  <User className="w-4 h-4 text-blue-400" />
                ) : (
                  <Bot className="w-4 h-4 text-cyan-400" />
                )}
              </div>
              <div
                className={`max-w-[80%] rounded-xl p-3.5 ${
                  msg.role === 'user'
                    ? 'bg-blue-600/15 border border-blue-500/20'
                    : 'glass-card'
                }`}
              >
                <p className="text-sm text-gray-200 whitespace-pre-wrap">{msg.content}</p>
              </div>
            </div>
          ))
        )}
        {loading && (
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#12141f] border border-white/[0.06] flex items-center justify-center flex-shrink-0">
              <Bot className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="glass-card rounded-xl p-3.5">
              <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <form onSubmit={handleSend} className="flex gap-2 pt-3 border-t border-white/[0.04]">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about security, vulnerabilities, tools..."
          disabled={loading}
          className="flex-1 bg-[#0a0b14] border border-white/[0.06] rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-blue-500/50 transition-colors disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="px-4 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors flex items-center justify-center"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
}
